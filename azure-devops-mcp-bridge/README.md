# Azure DevOps MCP Bridge

A Docker-based HTTP(S) bridge for the Azure DevOps MCP server.

This is an optional component of the `azure-devops-mcp` repository. Contributing,
security, and license information are inherited from the repo root
(`CONTRIBUTING.md`, `SECURITY.md`, `LICENSE.md`).

## Features
- HTTPS via Caddy
- API key auth (Authorization: Bearer <MCP_API_KEY> or x-api-key)
- Rate limiting on /sse
- Pinned upstream version (ADO_MCP_REF)

## Quick Start
1) From the repo root, `cd azure-devops-mcp-bridge`
2) Copy `.env.example` to `.env` and set values
3) Run:
   docker compose up -d --build

## Test
curl -k https://localhost/healthz
curl -k https://localhost/sse

Expected:
- /healthz => {"ok":true}
- /sse without API key => 401 Unauthorized

## OpenAI Agent Builder
- URL: https://<your-domain>/sse
- Auth: API Key
- Key: MCP_API_KEY

## Notes
- "search" domain is not supported in bridge mode.
- Use least-privilege ADO PAT.
