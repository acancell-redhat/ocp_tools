#!/usr/bin/env python3
"""Find OpenShift upgrade paths between two versions in an update channel.

Reads the public OpenShift Update Service graph and reports two routes, each
found with breadth-first search (fewest hops):

  1. the shortest route that uses only unconditional edges, and
  2. the shortest route when conditional edges are allowed as well. Every
     conditional hop is labelled with the risks the graph declares for it.

A path in the graph is NOT an upgrade recommendation for a particular cluster.
Each cluster evaluates conditional risks for itself. This tool only reads the
public graph. It never contacts or changes a cluster.

Standard library only; Python 3.8+.
"""

import argparse
import collections
import http.client
import json
import math
import re
import socket
import ssl
import sys
import urllib.error
import urllib.parse
import urllib.request

GRAPH_URL = "https://api.openshift.com/api/upgrades_info/v1/graph"
DEFAULT_ARCH = "amd64"
DEFAULT_TIMEOUT = 30.0
MAX_RESPONSE_BYTES = 64 * 1024 * 1024
VERIFY_CMD = "oc adm upgrade --include-not-recommended"

EXIT_OK, EXIT_ERROR, EXIT_NO_PATH = 0, 1, 3  # argparse exits 2 on usage errors

NOTE = (
    "Note: a path in the update graph is not an upgrade recommendation for your\n"
    "cluster. Each cluster evaluates conditional-edge risks for itself, and graph data\n"
    "can change at any time. To see the next hops your cluster is offered, including\n"
    "not-recommended conditional updates and the reasons, run this read-only command\n"
    "(it does not start an upgrade):\n"
    "  " + VERIFY_CMD
)

# versions: node versions in graph order
# adjacency: {version: [(next_version, is_conditional), ...]} in version order
# risks: {(from_version, to_version): [risk dict, ...]} for conditional edges
Graph = collections.namedtuple("Graph", "versions adjacency risks")


class GraphError(Exception):
    """A user-facing failure (network, HTTP, JSON, schema or input problem)."""


def version_key(version):
    """Sort key that orders 4.20.9 before 4.20.10."""
    return [(0, int(p), "") if p.isascii() and p.isdigit() else (1, 0, p)
            for p in re.split(r"[.+-]", version)]


def build_url(channel, arch):
    query = urllib.parse.urlencode({"channel": channel, "arch": arch})
    return GRAPH_URL + "?" + query


def fetch_graph(channel, arch, timeout=DEFAULT_TIMEOUT):
    """Download and decode the graph JSON over HTTPS with TLS verification on."""
    url = build_url(channel, arch)
    request = urllib.request.Request(url, headers={"Accept": "application/json"})
    try:
        # Explicit verifying context, so environment settings cannot disable TLS checks.
        context = ssl.create_default_context()
        with urllib.request.urlopen(request, timeout=timeout, context=context) as response:
            body = response.read(MAX_RESPONSE_BYTES + 1)
    except urllib.error.HTTPError as e:
        raise GraphError("HTTP %s %s from %s" % (e.code, e.reason, url))
    except urllib.error.URLError as e:
        if isinstance(e.reason, ssl.SSLCertVerificationError):
            raise GraphError("TLS certificate verification failed for %s: %s "
                             "(check system CA certificates or proxy settings)"
                             % (url, e.reason))
        if isinstance(e.reason, (socket.timeout, TimeoutError)):
            raise GraphError("timed out after %gs connecting to %s" % (timeout, url))
        raise GraphError("network error contacting %s: %s" % (url, e.reason))
    except (socket.timeout, TimeoutError):
        raise GraphError("timed out after %gs waiting for %s" % (timeout, url))
    except (OSError, http.client.HTTPException) as e:
        raise GraphError("network error reading %s: %s" % (url, e))
    if len(body) > MAX_RESPONSE_BYTES:
        raise GraphError("response from %s is larger than %d bytes"
                         % (url, MAX_RESPONSE_BYTES))
    try:
        return json.loads(body.decode("utf-8"))
    except ValueError as e:  # JSONDecodeError and UnicodeDecodeError
        raise GraphError("invalid JSON from %s: %s" % (url, e))


def _schema(message):
    return GraphError("schema error: " + message)


def parse_graph(data):
    """Validate the graph document and return a Graph."""
    if not isinstance(data, dict):
        raise _schema("top-level JSON value must be an object")
    nodes, edges = data.get("nodes"), data.get("edges")
    if not isinstance(nodes, list):
        raise _schema("'nodes' must be a list")
    if not isinstance(edges, list):
        raise _schema("'edges' must be a list")

    versions = []
    for i, node in enumerate(nodes):
        version = node.get("version") if isinstance(node, dict) else None
        if not isinstance(version, str) or not version:
            raise _schema("nodes[%d] has no string 'version'" % i)
        versions.append(version)
    known = set(versions)

    adj = {}  # version -> {next_version: is_conditional}
    for i, edge in enumerate(edges):
        if not (isinstance(edge, list) and len(edge) == 2 and all(
                type(x) is int and 0 <= x < len(versions) for x in edge)):
            raise _schema("edges[%d] must be [source_index, target_index] "
                          "within 'nodes'" % i)
        adj.setdefault(versions[edge[0]], {})[versions[edge[1]]] = False

    groups = data.get("conditionalEdges", [])
    if not isinstance(groups, list):
        raise _schema("'conditionalEdges' must be a list")
    risks = {}
    for g, group in enumerate(groups):
        if not (isinstance(group, dict) and isinstance(group.get("edges"), list)
                and isinstance(group.get("risks"), list)):
            raise _schema("conditionalEdges[%d] needs 'edges' and 'risks' lists" % g)
        for r, risk in enumerate(group["risks"]):
            if not (isinstance(risk, dict) and isinstance(risk.get("name"), str)):
                raise _schema("conditionalEdges[%d].risks[%d] has no string 'name'"
                              % (g, r))
        for e, edge in enumerate(group["edges"]):
            src = edge.get("from") if isinstance(edge, dict) else None
            dst = edge.get("to") if isinstance(edge, dict) else None
            if not (isinstance(src, str) and isinstance(dst, str)):
                raise _schema("conditionalEdges[%d].edges[%d] needs string "
                              "'from' and 'to'" % (g, e))
            if src not in known or dst not in known:
                continue  # endpoint outside this channel: cannot be on a path
            adj.setdefault(src, {}).setdefault(dst, True)  # unconditional wins
            bucket = risks.setdefault((src, dst), [])
            for risk in group["risks"]:
                if all(risk["name"] != seen["name"] for seen in bucket):
                    bucket.append(risk)

    adjacency = {u: sorted(nbrs.items(), key=lambda kv: version_key(kv[0]))
                 for u, nbrs in adj.items()}
    return Graph(versions, adjacency, risks)


def shortest_path(adjacency, start, end, allow_conditional):
    """Breadth-first search for the fewest-hop path from start to end.

    Among equally short paths it prefers fewer conditional hops; remaining
    ties are broken deterministically by version order. Returns the list of
    versions on the path, or None when end is unreachable.
    """
    if start == end:
        return [start]
    parent, cost = {start: None}, {start: 0}  # cost = conditional hops so far
    seen, layer = {start}, [start]
    while layer and end not in cost:
        next_layer = []
        for u in layer:
            for v, conditional in adjacency.get(u, ()):
                if v in seen or (conditional and not allow_conditional):
                    continue
                c = cost[u] + conditional
                if v not in cost:
                    next_layer.append(v)
                elif c >= cost[v]:
                    continue
                parent[v], cost[v] = u, c
        seen.update(next_layer)
        layer = next_layer
    if end not in cost:
        return None
    path = [end]
    while parent[path[-1]] is not None:
        path.append(parent[path[-1]])
    return path[::-1]


def _one_line(value):
    return " ".join(value.split()) if isinstance(value, str) else ""


def _plural(n, word):
    return "%d %s%s" % (n, word, "" if n == 1 else "s")


def format_route(title, path, graph):
    if path is None:
        return ["%s: none found." % title]
    hops = list(zip(path, path[1:]))
    kinds = [dict(graph.adjacency[u])[v] for u, v in hops]
    head = "%s: %s" % (title, _plural(len(hops), "hop"))
    if any(kinds):
        head += ", %s (see risks)" % _plural(sum(kinds), "conditional hop")
    lines = [head]
    for i, ((u, v), conditional) in enumerate(zip(hops, kinds), 1):
        lines.append("  %d. %s -> %s%s" % (i, u, v, "  [CONDITIONAL]" if conditional else ""))
        for risk in graph.risks.get((u, v), ()):
            message = _one_line(risk.get("message"))
            lines.append("       risk %s%s" % (risk["name"], ": " + message if message else ""))
            if _one_line(risk.get("url")):
                lines.append("         more info: %s" % _one_line(risk["url"]))
            rules = risk.get("matchingRules")
            types = sorted({m["type"] for m in rules if isinstance(m, dict)
                            and isinstance(m.get("type"), str)}) if isinstance(rules, list) else []
            if types:
                lines.append("         evaluated per cluster by: %s" % ", ".join(types))
    return lines


def report(graph, start, end, channel, arch):
    """Return (text, exit_code) for one query. Raises GraphError on bad input."""
    if not graph.versions:
        raise GraphError("channel %r returned no versions for arch %r; check the "
                         "channel name and --arch" % (channel, arch))
    known = set(graph.versions)
    missing = [v for v in dict.fromkeys((start, end)) if v not in known]
    if missing:
        ordered = sorted(known, key=version_key)
        raise GraphError("%s %s %s not in channel %s (arch %s); the channel lists %s "
                         "from %s to %s" % (
                             "version" if len(missing) == 1 else "versions",
                             " and ".join(missing),
                             "is" if len(missing) == 1 else "are",
                             channel, arch, _plural(len(ordered), "version"),
                             ordered[0], ordered[-1]))
    if start == end:
        return ("Start and end are both %s; no upgrade hops are needed." % start,
                EXIT_OK)

    n_cond = sum(c for nbrs in graph.adjacency.values() for _, c in nbrs)
    n_edges = sum(len(nbrs) for nbrs in graph.adjacency.values())
    lines = ["Update graph: %s" % build_url(channel, arch),
             "%s, %s, %s" % (_plural(len(graph.versions), "version"),
                             _plural(n_edges - n_cond, "unconditional edge"),
                             _plural(n_cond, "conditional edge")),
             ""]
    plain = shortest_path(graph.adjacency, start, end, allow_conditional=False)
    best = shortest_path(graph.adjacency, start, end, allow_conditional=True)
    lines += format_route("Shortest unconditional route", plain, graph)
    lines.append("")
    title = "Shortest route including conditional edges"
    if best is not None and not any(dict(graph.adjacency[u])[v]
                                    for u, v in zip(best, best[1:])):
        lines.append("%s: same length as the unconditional route; conditional "
                     "edges give no shorter path." % title)
    else:
        lines += format_route(title, best, graph)
    code = EXIT_OK
    if best is None:
        lines += ["", "No route from %s to %s exists in channel %s (arch %s)."
                  % (start, end, channel, arch)]
        code = EXIT_NO_PATH
    lines += ["", NOTE]
    return "\n".join(lines), code


def _nonempty(text):
    text = text.strip()
    if not text:
        raise argparse.ArgumentTypeError("must not be empty")
    return text


def _positive_seconds(text):
    try:
        value = float(text)
    except ValueError:
        raise argparse.ArgumentTypeError("not a number: %r" % text)
    if not (value > 0 and math.isfinite(value)):
        raise argparse.ArgumentTypeError("must be a positive number of seconds")
    return value


def build_parser():
    parser = argparse.ArgumentParser(
        prog="upgrade_path.py",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description="Find the shortest OpenShift upgrade routes between two versions "
                    "in an\nupdate channel, using the public OpenShift Update Service "
                    "graph (read-only).",
        epilog="examples:\n"
               "  python3 upgrade_path.py 4.20.32 4.20.46 stable-4.20\n"
               "  python3 upgrade_path.py 4.20.32 4.20.46 stable-4.20 --arch arm64\n"
               "\n"
               "exit status: 0 route found, 1 error (network, HTTP, JSON, schema or\n"
               "unknown version), 2 usage error, 3 no route between the versions.\n"
               "\n"
               "A path in the graph is not an upgrade recommendation for a specific\n"
               "cluster. Check your cluster's next hop with the read-only command:\n"
               "  " + VERIFY_CMD)
    parser.add_argument("start", type=_nonempty, help="starting (current) version, e.g. 4.20.32")
    parser.add_argument("end", type=_nonempty, help="ending (target) version, e.g. 4.20.46")
    parser.add_argument("channel", type=_nonempty, help="update channel, e.g. stable-4.20")
    parser.add_argument("--arch", type=_nonempty, default=DEFAULT_ARCH,
                        help="release architecture, e.g. amd64, arm64, ppc64le, s390x "
                             "or multi (default: %(default)s)")
    parser.add_argument("--timeout", type=_positive_seconds, default=DEFAULT_TIMEOUT,
                        help="HTTP timeout in seconds (default: %(default)g)")
    return parser


def main(argv=None):
    args = build_parser().parse_args(argv)
    try:
        graph = parse_graph(fetch_graph(args.channel, args.arch, args.timeout))
        text, code = report(graph, args.start, args.end, args.channel, args.arch)
    except GraphError as e:
        print("error: %s" % e, file=sys.stderr)
        return EXIT_ERROR
    except KeyboardInterrupt:
        print("interrupted", file=sys.stderr)
        return 130
    print(text)
    return code


if __name__ == "__main__":
    sys.exit(main())
