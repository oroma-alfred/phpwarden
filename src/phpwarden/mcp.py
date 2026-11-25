"""`phpwarden mcp`: a local MCP server for agencies.

It lets an AI assistant (Claude Desktop, Claude Code, Cursor, ChatGPT desktop
and other MCP clients) answer questions about an agency's client sites from
phpwarden's own data: which sites have exploited vulnerabilities, what to fix
first and to which version, which sites a CVE or plugin hits, what became
exploited this week, and the facts for a client's monthly report.

Read-only. It talks to the partner API with the agency's partner key (Team
plan, Settings > Agency > Partner API key), read from PHPWARDEN_PARTNER_KEY.
The key never goes to the assistant: it stays in this process.

Transport: MCP over stdio, newline-delimited JSON-RPC 2.0. Standard library only.
"""
from __future__ import annotations

import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request

from . import __version__

DEFAULT_API = "https://app.phpwarden.io"
PROTOCOLS = ("2025-06-18", "2025-03-26", "2024-11-05")

INSTRUCTIONS = (
    "phpwarden data for this agency's client sites. Findings are ranked exploitation first: "
    "'exploited' means on CISA's Known Exploited Vulnerabilities list (attacks seen in the wild), "
    "then EPSS (probability of exploitation in the next 30 days, 0-1), then CVSS severity. "
    "Fix exploited items first. 'fixed_in' is the version that removes the issue. "
    "Each finding has a 'proof' label: 'proven' (affected version installed and the vulnerable entry point is "
    "live on the site, or attacks on it were seen in the site's logs), 'not reachable' (evidence the vulnerable "
    "code is not in use; still patch it), or 'needs proof' ('proof_summary' names the missing fact). 'evidence' "
    "lists the steps. Proven exploited items are the most urgent. "
    "Only state facts these tools return; if a tool returns nothing, say so.")

TOOLS = [
    {"name": "list_sites",
     "title": "List client sites",
     "description": "All client sites (projects) with open finding counts and how many are actively exploited. "
                    "Use first to get site names, or to answer 'which sites need attention?'.",
     "inputSchema": {"type": "object", "properties": {
         "only_exploited": {"type": "boolean", "description": "Only sites with at least one exploited vulnerability."}},
         "additionalProperties": False}},
    {"name": "site_findings",
     "title": "Site findings, fix-first order",
     "description": "Open vulnerabilities on one site in fix-first order (exploited, then likely, then severity), "
                    "each with the version that fixes it for the installed version. Returns totals plus the top findings.",
     "inputSchema": {"type": "object", "properties": {
         "site": {"type": "string", "description": "Site name (or part of it) or project id."},
         "limit": {"type": "integer", "minimum": 1, "maximum": 200,
                   "description": "How many findings to return, default 25. Exploited ones are always all included."}},
         "required": ["site"], "additionalProperties": False}},
    {"name": "find_affected_sites",
     "title": "Which sites are affected",
     "description": "Which client sites have a given CVE, WordPress plugin or theme slug, or Composer package.",
     "inputSchema": {"type": "object", "properties": {
         "query": {"type": "string", "description": "A CVE id (CVE-2026-1234), plugin slug (contact-form-7) or package (drupal/core)."}},
         "required": ["query"], "additionalProperties": False}},
    {"name": "new_exploited",
     "title": "Newly exploited across all sites",
     "description": "Exploited vulnerabilities that appeared on any client site in the last N days and are still open "
                    "(new installs, new findings, or newly added to the exploited list), one entry per issue with the "
                    "sites it affects.",
     "inputSchema": {"type": "object", "properties": {
         "days": {"type": "integer", "minimum": 1, "maximum": 90, "description": "Look-back window, default 7."}},
         "additionalProperties": False}},
    {"name": "client_report_facts",
     "title": "Facts for a client report",
     "description": "The numbers and items for one client's report over a period: open and exploited counts, "
                    "what was fixed (each verified by a later scan or live check), updates applied, attack attempts "
                    "logged, software versions. Use these facts to write a plain-English client update.",
     "inputSchema": {"type": "object", "properties": {
         "site": {"type": "string", "description": "Site name (or part of it) or project id."},
         "days": {"type": "integer", "minimum": 1, "maximum": 92, "description": "Report period in days, default 30."}},
         "required": ["site"], "additionalProperties": False}},
]

for _t in TOOLS:
    _t["annotations"] = {"readOnlyHint": True, "destructiveHint": False, "openWorldHint": False}


class ApiError(Exception):
    pass


class Client:
    def __init__(self, key: str, base: str = DEFAULT_API, timeout: float = 20):
        self.key, self.base, self.timeout = key, base.rstrip("/"), timeout

    def get(self, path: str, **params) -> dict:
        q = {k: v for k, v in params.items() if v not in (None, "")}
        url = self.base + path + ("?" + urllib.parse.urlencode(q) if q else "")
        r = urllib.request.Request(url, headers={"Authorization": "Bearer " + self.key, "Accept": "application/json",
                                                 "User-Agent": f"phpwarden-mcp/{__version__}"})
        try:
            with urllib.request.urlopen(r, timeout=self.timeout) as resp:
                return json.loads(resp.read() or b"{}")
        except urllib.error.HTTPError as e:
            code = {401: "The partner key was not accepted. Create one in Settings > Agency on phpwarden.",
                    402: "The partner API needs the Team or Agency plan.",
                    404: "Not found.", 429: "Rate limited; try again shortly."}.get(e.code, f"HTTP {e.code}")
            raise ApiError(code) from None
        except (urllib.error.URLError, OSError, ValueError) as e:
            raise ApiError(f"Could not reach {self.base}: {e.__class__.__name__}") from None

    def resolve(self, site: str) -> dict:
        site = (site or "").strip()
        projects = self.get("/v1/partner/projects").get("projects", [])
        for p in projects:
            if site == p["id"]:
                return p
        low = site.lower()
        exact = [p for p in projects if p["name"].lower() == low]
        if len(exact) == 1:
            return exact[0]
        part = [p for p in projects if low and low in p["name"].lower()]
        if len(part) == 1:
            return part[0]
        if not part:
            raise ApiError(f"No site matches '{site}'. Use list_sites to see the names.")
        raise ApiError(f"'{site}' matches {len(part)} sites: " + ", ".join(p["name"] for p in part[:10])
                       + ". Use a fuller name.")


def call_tool(cli: Client, name: str, args: dict) -> dict:
    args = args or {}
    if name == "list_sites":
        ps = cli.get("/v1/partner/projects").get("projects", [])
        if args.get("only_exploited"):
            ps = [p for p in ps if p.get("kev")]
        ps.sort(key=lambda p: (-(p.get("kev") or 0), -(p.get("findings") or 0), p.get("name", "")))
        return {"sites": [{"id": p["id"], "name": p["name"], "open_findings": p.get("findings", 0),
                           "exploited": p.get("kev", 0), "scanned": p.get("scanned", False),
                           "last_scan": p.get("last_ts", 0), "suspended": p.get("suspended", False)} for p in ps]}
    if name == "site_findings":
        p = cli.resolve(args.get("site", ""))
        return cli.get(f"/v1/partner/projects/{urllib.parse.quote(p['id'])}/findings", limit=int(args.get("limit") or 25))
    if name == "find_affected_sites":
        return cli.get("/v1/partner/findings", q=str(args.get("query", ""))[:120])
    if name == "new_exploited":
        return cli.get("/v1/partner/exploited", days=int(args.get("days") or 7))
    if name == "client_report_facts":
        p = cli.resolve(args.get("site", ""))
        return cli.get(f"/v1/partner/projects/{urllib.parse.quote(p['id'])}/report", days=int(args.get("days") or 30))
    raise KeyError(name)


def handle(cli: Client, msg: dict):
    """One JSON-RPC message in, a response dict (or None for notifications) out."""
    mid, method = msg.get("id"), msg.get("method", "")
    if mid is None:                       # notification (initialized, cancelled, ...)
        return None

    def ok(result):
        return {"jsonrpc": "2.0", "id": mid, "result": result}

    def err(code, text):
        return {"jsonrpc": "2.0", "id": mid, "error": {"code": code, "message": text}}

    if method == "initialize":
        want = (msg.get("params") or {}).get("protocolVersion")
        return ok({"protocolVersion": want if want in PROTOCOLS else PROTOCOLS[0],
                   "capabilities": {"tools": {"listChanged": False}},
                   "serverInfo": {"name": "phpwarden", "title": "phpwarden", "version": __version__},
                   "instructions": INSTRUCTIONS})
    if method == "ping":
        return ok({})
    if method == "tools/list":
        return ok({"tools": TOOLS})
    if method == "tools/call":
        p = msg.get("params") or {}
        name = p.get("name", "")
        if name not in {t["name"] for t in TOOLS}:
            return err(-32602, f"Unknown tool: {name}")
        try:
            data = call_tool(cli, name, p.get("arguments") or {})
        except (ApiError, ValueError, TypeError) as e:
            return ok({"content": [{"type": "text", "text": str(e) or "Bad arguments."}], "isError": True})
        return ok({"content": [{"type": "text", "text": json.dumps(data, indent=1)}], "structuredContent": data,
                   "isError": False})
    if method in ("resources/list", "prompts/list"):
        return ok({method.split("/")[0]: []})
    return err(-32601, f"Method not found: {method}")


def serve(cli: Client, stdin=None, stdout=None) -> int:
    stdin, stdout = stdin or sys.stdin, stdout or sys.stdout
    for line in stdin:
        line = line.strip()
        if not line:
            continue
        try:
            msg = json.loads(line)
        except ValueError:
            out = {"jsonrpc": "2.0", "id": None, "error": {"code": -32700, "message": "Parse error"}}
        else:
            if isinstance(msg, list):     # batch (older protocol versions)
                out = [r for r in (handle(cli, m) for m in msg if isinstance(m, dict)) if r] or None
            elif isinstance(msg, dict):
                out = handle(cli, msg)
            else:
                out = {"jsonrpc": "2.0", "id": None, "error": {"code": -32600, "message": "Invalid request"}}
        if out:
            stdout.write(json.dumps(out) + "\n")
            stdout.flush()
    return 0


def main(args) -> int:
    key = os.environ.get("PHPWARDEN_PARTNER_KEY", "").strip()
    base = getattr(args, "api", None) or os.environ.get("PHPWARDEN_API") or DEFAULT_API
    if not key:
        print("phpwarden mcp: set PHPWARDEN_PARTNER_KEY to your partner API key "
              "(Team plan: Settings > Agency > Partner API key).", file=sys.stderr)
        return 2
    cli = Client(key, base)
    if getattr(args, "check", False):
        try:
            n = len(cli.get("/v1/partner/projects").get("projects", []))
        except ApiError as e:
            print(f"phpwarden mcp: {e}", file=sys.stderr)
            return 1
        print(f"phpwarden mcp: connected to {base}, {n} sites visible. Ready for your MCP client.")
        return 0
    return serve(cli)
