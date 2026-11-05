# Writing a SecurityWarden connector

A connector gives an AI agent (Hermes, Claude, any MCP client) tools for one application: a mail service, a
CRM, a broker, a home-automation API. `sw-mcp` runs it as an MCP server. What makes it a SecurityWarden
connector: **every tool call is an action that the user's SecurityWarden rules allow, refuse, or hold for a
person to approve**, and the application's credentials come from SecurityWarden, never from files or the AI.

This guide is the contract. It is written so that an AI can build a correct connector from it alone.

---

## 1. Quick start

```bash
sw-mcp new-connector notes --title "Notes"     # creates notes-connector/ with code, tests and packaging
cd notes-connector
pip install -e ".[dev]"
sw-mcp check --connector notes                 # finds mistakes in names, parameters and rules
pytest                                         # the generated tests pass before you change anything
```

Then replace the example tools in `src/sw_connector_notes/connector.py`, update the tests, and repeat
`sw-mcp check` and `pytest` until both pass.

## 2. How a call works (read this before writing a tool)

1. The agent calls a tool, e.g. `notes_delete(item_id="a1")`.
2. `sw-mcp` checks the arguments against the tool's schema, then calls your method. Your method **prepares**:
   it validates, looks up whatever it needs, and returns a `Plan(args, summary, run)`. It changes nothing.
3. `sw-mcp` asks SecurityWarden whether this token may do the action `notes.delete` with exactly `args`
   (a SHA-256 digest of them). The rules answer:
   - allowed: `run(args)` is called now and its result goes to the agent;
   - a person must decide: the agent is told `waiting_for_approval` immediately; the person sees your
     `summary` (website, phone); once approved, `run` is called with the stored `args`, once;
   - refused or denied: nothing runs, and the agent is told why. The person may **deny with a comment**
     ("send it to Ann instead"): the agent gets the comment and may call your tool again with changed
     arguments, which is a new request. Your connector needs nothing for this.
4. Text your `run` returns that came from outside (messages, documents, names) is wrapped as untrusted data.

So: **`args` is the contract with the person approving.** Whatever `run` does must be fully determined by
`args` (plus the credentials). If `run` could do something the person didn't see, the approval is worthless.

## 3. The connector class

```python
from securitywarden.mcp import Connector, Plan, Summary, ToolError, tool, untrusted

class Notes(Connector):
    name = "notes"                         # lowercase; prefixes every action (notes.*) and tool (notes_*)
    title = "Notes"                        # the name people see
    description = "Read and manage notes in Notes."
    secrets = ("NOTES_API_KEY",)           # every SecurityWarden secret this connector reads
    suggested_rules = ("notes.read.*=allow", "notes.update=window:30m", "notes.delete=each")
    transport = None                       # tests swap the real service for httpx.MockTransport

    def __init__(self, ctx):
        super().__init__(ctx)
        self.http = httpx.Client(timeout=30, transport=self.transport)

    def close(self):
        self.http.close()
```

- `name` never changes once people use it: their SecurityWarden rules refer to `notes.*`.
- `secrets`: UPPER_CASE names, prefixed with the connector name. The user stores them in the token's
  SecurityWarden project. Read them only with `self.secret("NOTES_API_KEY")`.
- One connector per application. Several connectors can run in one `sw-mcp` (`--connector a --connector b`).

## 4. Tools

```python
    @tool("Delete one note for good. Returns the deleted id.",
          action="notes.delete", risk="high",
          params={"note_id": {"type": "string", "description": "From notes_search."}},
          required=["note_id"])
    def delete(self, note_id: str) -> Plan:
        note = self._get(f"/notes/{note_id}")                     # look up now, so the person sees what goes
        return Plan({"id": note_id}, Summary("Delete a note", [("Note", note["title"])]), self._delete)

    def _delete(self, args):
        self._call("DELETE", f"/notes/{args['id']}")
        return {"deleted": args["id"]}
```

### Description
Written for the AI choosing tools: what it does, what it returns, and any limits. One or two sentences.
`sw-mcp` adds the approval note itself.

### Action names
`<connector>.<verb>[.<object>]`: lowercase words and `_`, joined by dots, two to six parts.

| Kind of tool | Action | Typical risk |
|---|---|---|
| Reading, searching, listing | `<name>.read.<object>` (e.g. `notes.read.search`) | low |
| Reversible tidying (labels, archive, mark read, move) | `<name>.<verb>` (e.g. `notes.archive`) | low |
| Creating something the user reviews before it matters (a draft) | `<name>.draft` | medium |
| Changing shared or important data (update a record, post internally) | `<name>.update` | medium |
| Sending, publishing, paying, trading, deleting, sharing, inviting, changing permissions | `<name>.send`, `.delete`, `.order.place`, ... | high |

Put all reads under `.read.` so one rule (`notes.read.*=allow`) covers them. Give each different kind of
change its own action, so people can allow one and keep asking for another.

### Risk
`low`, `medium` or `high`. Risk only tightens the user's rules: a **high-risk action always asks a person**,
whatever the rules say, and "allow for 30 minutes" windows never cover it. When unsure, choose the higher risk.
Anything that sends data outside, costs money, can't be undone, or acts in the user's name is `high`.

### Parameters
A JSON Schema subset, checked before your method runs:

| `type` | Notes |
|---|---|
| `string` | optional `enum` |
| `integer` | optional `minimum`, `maximum` |
| `boolean` | |
| `array` | give `items`, e.g. `{"type": "string"}` |
| `object` | free-form; validate it yourself |

- No `number` (floats): money, prices and quantities with decimals go in as strings ("189.50").
- Give every parameter a `description`.
- The method's arguments must match `params` exactly: required ones without defaults, optional ones with.
  `sw-mcp check` verifies this.

## 5. The Plan

`Plan(args, summary, run)`:

**`args`**: a dict of JSON values (strings, integers, booleans, null, lists, dicts; no floats, no bytes). It
must contain **everything that decides what happens**:
- resolved ids, not names the AI typed ("Bob" → the user id you looked up);
- full content that will be sent or written (a message body, the new value), or a SHA-256 of large content
  you keep verbatim in args anyway;
- for batches, the full sorted list of ids.

**`run(args)`**: performs the action using only `args` and `self.secret(...)`. No new lookups that could
change the target (no "find the newest message and delete it" inside run: find it in the tool method and put
its id in args). Return a JSON-able value (dict, list, str) or `untrusted(...)`.

**The tool method** may read from the service (to validate, resolve names, build the summary) but must not
change anything. What it reads goes only into `args` and the summary, never back to the AI.

## 6. The Summary (what a person sees before approving)

`Summary(title, fields=[(label, value), ...], preview=None, count=1)`

- `title`: fixed wording, e.g. "Send an email", "Delete 3 notes". Don't put outside text in the title.
- `fields`: what the person needs to decide, at most 10: recipients, amounts, accounts, the item's name, what
  changes from what to what. Labels up to 40 characters, values up to 300 (longer ones are shortened).
- `preview`: the message or content itself, up to 500 characters.
- `count`: how many items a batch covers.

Values may contain text from the service (a subject line): the person sees it; the AI never gets the summary
back. Never put secrets in a summary.

## 7. Results and untrusted content

Anything written by someone other than the user (emails, documents, comments, names, web pages) is returned with
`untrusted(value, "Notes")`. `sw-mcp` fences it and tells the AI it's data, not instructions. That's the
defence against prompt injection; the approval on risky actions is the backstop.

Return the fields the AI needs, not raw API responses: smaller, clearer, and no internal tokens or links with
credentials in them.

## 8. Errors

Raise `ToolError("message for the AI")` for anything the AI or user should know: not found, invalid input,
the service refused. Keep messages short and free of secrets and raw response bodies. Unexpected exceptions are
caught by `sw-mcp` and reported only by type.

If the service rejects the credentials, raise a `ToolError` that tells the user which secret to check, and
call `self.ctx.forget_secrets()` so a corrected secret is fetched next time.

## 9. Secrets and the network

- Never log, print, return or put secrets in `args` or a summary.
- Use `httpx` with a timeout. Create the client in `__init__` with `transport=self.transport` and close it in
  `close()`.
- Validate ids before putting them in URLs (no `/`, `..`, spaces).
- For OAuth services, store the refresh token as a secret and refresh access tokens in memory (see the Gmail
  connector, `sw-mcp login gmail` for a sign-in helper).

## 10. Suggested rules

`suggested_rules` is the starting policy the user applies to the token (`sw-mcp tools --connector NAME` prints
it ready for `swctl`; the website has the same rule syntax). One rule per line, first match wins, anything not
listed asks every time:

```
notes.read.*=allow          reads run without asking
notes.update=window:30m     ask once, then allowed for 30 minutes
notes.delete=each           ask every time
notes.export=deny           never
```

Suggest `allow` only for reads, `window` only for low-risk reversible actions, `each` for everything else.

## 11. Tests

Use `securitywarden.mcp.testing` (no server needed) and `httpx.MockTransport` (no real service):

```python
from securitywarden.mcp.testing import FakeSecurityWarden, make_hub

sw = FakeSecurityWarden({"notes.read.*": "allow"}, secrets={"NOTES_API_KEY": "test-key"})
cls = type("TestNotes", (Notes,), {"transport": httpx.MockTransport(fake_service)})
hub = make_hub(cls, sw)

r = hub.call("notes_delete", {"note_id": "a1"})
assert r.data["status"] == "waiting_for_approval"
assert sw.last()["summary"]["fields"] == [["Note", "Shopping"]]
sw.approve(r.data["request_id"])          # or sw.deny(...)
done = hub.call("check_approval", {"request_id": r.data["request_id"]})
```

Test, for every tool: what runs at once; what waits and what the person sees (`sw.last()["summary"]`, `["args"]`);
that approval runs exactly the approved `args`; that a denial changes nothing; bad input; the service's errors.
Include `check_connector(YourClass)` having no errors.

## 12. Packaging and how sw-mcp finds the connector

The project's `pyproject.toml` declares an entry point (the template already has it):

```toml
[project.entry-points."securitywarden.connectors"]
notes = "sw_connector_notes.connector:Notes"
```

Install the package into the same Python environment as `sw-mcp` (`pip install .`, or from a wheel). Then
`--connector notes` works, `sw-mcp tools` lists it, and `sw-mcp check` checks it. Without packaging, a
connector can also be named directly: `--connector mymodule:Notes` (the module must be importable).

Or, with no installing on each machine: upload it to SecurityWarden (next section).

## 13. Distributing it through SecurityWarden (no pip on the agents' machines)

```bash
sw-mcp pack notes                  # writes notes.swconnector (refuses a connector that fails sw-mcp check)
```

On the SecurityWarden website: **Connectors > Upload...**, check the tools and risks shown, make it available to
the projects that need it, then tick it for each token whose agent should have it. Every `sw-mcp` using such a
token loads it, with no `--connector` needed. Tools whose actions the token's rules `deny` are left out of the
list the agent sees. Uploading a newer `notes.swconnector` stores the next version (the one it replaces is kept
as a backup to download or restore) and asks when running agents switch: **Go live now** (at their next tool
call) or **On next restart**.

For a connector to be packable:
- everything it needs is in its own package: the standard library, `httpx` and `cryptography` are available;
  nothing else is (no other pip packages, no compiled files);
- only `.py`, `.json`, `.txt` and `.md` files are packed; don't name packages after standard modules;
- set `title = "Notes"` on the class for the name people see.

The code is encrypted in the browser before upload; the server can't read it. Machines refuse a version older
than one they have already run.

## 14. Using it

1. SecurityWarden website: a project with the connector's secrets; make the connector available to the project
   (Connectors); a token for the agent with the connector ticked and the suggested rules (token → Manage). Or
   install the package where the agent runs and name it in the MCP settings (`--connector notes`).
2. The agent's MCP settings: command `sw-mcp`, arguments `serve`, environment `SW_SERVER_URL` and
   `SW_TOKEN_NAME` (the token's name; it's kept in SW_Tokens.json once set up).
3. Give the agent the token's setup code: "Set up SecurityWarden with code SWS1-...".
4. Try a tool by hand: `sw-mcp call notes_search query=shopping`.

## 15. Checklist (before calling it done)

- [ ] `sw-mcp check --connector NAME` reports no errors (and you've read the warnings).
- [ ] `pytest` passes, with the tests listed in section 11.
- [ ] Every action that sends, deletes, pays, shares or can't be undone is `high`.
- [ ] `run` uses only `args` and secrets; `args` holds resolved ids and full content.
- [ ] Every summary tells a person, in a few fields, exactly what will happen.
- [ ] Outside text is returned with `untrusted(...)`.
- [ ] No secret appears in args, summaries, results, errors or logs.
- [ ] Tell the user which secrets to add and the suggested rules.
- [ ] To share it through SecurityWarden: `sw-mcp pack NAME` works (only the standard library, httpx and
      cryptography are used).

## 16. A complete example

The Gmail connector is a full reference (OAuth, search and read, batches with summaries, sending with exact
recipients and body, untrusted email content):

```bash
python -c "import securitywarden.mcp.gmail as g; print(g.__file__)"
```
