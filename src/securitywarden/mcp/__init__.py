"""aiSecurityWarden MCP connectors: give an AI agent tools for an application (Gmail, ...) where every action
goes through the token's rules in aiSecurityWarden and, when they say so, a person's approval.

Writing a connector::

    from securitywarden.mcp import Connector, Plan, Summary, tool, untrusted

    class Notes(Connector):
        name = "notes"
        secrets = ("NOTES_API_KEY",)

        @tool("Delete a note.", action="notes.delete", risk="high",
              params={"id": {"type": "string"}}, required=["id"])
        def delete(self, id):
            return Plan({"id": id}, Summary("Delete a note", [("Note", id)]), self._delete)

        def _delete(self, args):
            ...  # uses self.secret("NOTES_API_KEY"); runs only once allowed or approved

Run it: ``sw-mcp serve --connector mypackage.notes:Notes``.
"""

from .framework import Connector, Context, Hub, Plan, Result, Summary, ToolError, Untrusted, tool, untrusted

__all__ = ["Connector", "Context", "Hub", "Plan", "Result", "Summary", "ToolError", "Untrusted", "tool", "untrusted"]
