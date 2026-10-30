# Writing a connector

The guide lives inside the package, so it's on every machine that has the client:

```bash
sw-mcp guide              # print it (give it to your AI)
sw-mcp new-connector NAME # a ready-to-fill project: code, tests, packaging, AGENTS.md for an AI
sw-mcp check              # find mistakes in installed connectors
sw-mcp pack NAME          # one file to upload on the SecurityWarden website (Connectors > Upload)
```

Uploaded connectors reach every agent whose token's project uses them, without installing anything there; see
section 13 of the guide and [DESIGN.md](DESIGN.md#connector-distribution).

Source: [src/securitywarden/mcp/CONNECTORS.md](../src/securitywarden/mcp/CONNECTORS.md).
