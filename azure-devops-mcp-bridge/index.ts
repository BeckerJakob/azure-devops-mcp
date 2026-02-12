import { timingSafeEqual } from "node:crypto";

import express from "express";
import { getBearerHandler, WebApi } from "azure-devops-node-api";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";

import { createAuthenticator } from "../src/auth.js";
import { logger } from "../src/logger.js";
import { getOrgTenant } from "../src/org-tenants.js";
import { configureAdvSecTools } from "../src/tools/advanced-security.js";
import { configureCoreTools } from "../src/tools/core.js";
import { configurePipelineTools } from "../src/tools/pipelines.js";
import { configureRepoTools } from "../src/tools/repositories.js";
import { configureTestPlanTools } from "../src/tools/test-plans.js";
import { configureWikiTools } from "../src/tools/wiki.js";
import { configureWorkTools } from "../src/tools/work.js";
import { configureWorkItemTools } from "../src/tools/work-items.js";
import { UserAgentComposer } from "../src/useragent.js";
import { packageVersion } from "../src/version.js";
import { Domain, DomainsManager } from "../src/shared/domains.js";

const ALLOWED_AUTH_TYPES = new Set(["interactive", "azcli", "env", "envvar"]);
const DEFAULT_RATE_LIMIT_WINDOW_MS = 60_000;
const DEFAULT_RATE_LIMIT_MAX = 60;

const rateLimitWindowMs = parsePositiveInt(process.env.RATE_LIMIT_WINDOW_MS, DEFAULT_RATE_LIMIT_WINDOW_MS);
const rateLimitMax = parsePositiveInt(process.env.RATE_LIMIT_MAX, DEFAULT_RATE_LIMIT_MAX);
const rateLimitByIp = new Map<string, { count: number; resetAt: number }>();

function requireEnv(name: string): string {
  const value = process.env[name];
  if (!value) {
    throw new Error(`Missing required environment variable: ${name}`);
  }
  return value;
}

function parsePositiveInt(value: string | undefined, fallback: number): number {
  if (!value) {
    return fallback;
  }
  const parsed = Number.parseInt(value, 10);
  return Number.isFinite(parsed) && parsed > 0 ? parsed : fallback;
}

function parseDomains(domainsEnv?: string): string[] {
  if (!domainsEnv) {
    return ["all"];
  }
  const domains = domainsEnv
    .split(/[,\s]+/)
    .map((domain) => domain.trim())
    .filter(Boolean);
  return domains.length > 0 ? domains : ["all"];
}

function extractApiKeyFromHeaders(headers: Record<string, string | string[] | undefined>): string | undefined {
  const directKey = headers["x-api-key"];
  if (typeof directKey === "string") {
    return directKey;
  }
  if (Array.isArray(directKey) && directKey.length > 0) {
    return directKey[0];
  }

  const authHeader = headers["authorization"];
  if (typeof authHeader === "string" && authHeader.toLowerCase().startsWith("bearer ")) {
    return authHeader.slice("bearer ".length).trim();
  }
  if (Array.isArray(authHeader) && authHeader.length > 0) {
    const first = authHeader[0];
    if (first && first.toLowerCase().startsWith("bearer ")) {
      return first.slice("bearer ".length).trim();
    }
  }

  return undefined;
}

function apiKeyMatches(candidate: string | undefined, expected: string): boolean {
  if (!candidate) {
    return false;
  }
  const expectedBuffer = Buffer.from(expected);
  const candidateBuffer = Buffer.from(candidate);
  if (expectedBuffer.length !== candidateBuffer.length) {
    return false;
  }
  return timingSafeEqual(expectedBuffer, candidateBuffer);
}

function checkRateLimit(ip: string): { allowed: boolean; retryAfterSeconds: number } {
  const now = Date.now();
  let entry = rateLimitByIp.get(ip);
  if (!entry || now >= entry.resetAt) {
    entry = { count: 0, resetAt: now + rateLimitWindowMs };
    rateLimitByIp.set(ip, entry);
  }

  entry.count += 1;
  if (entry.count > rateLimitMax) {
    const retryAfterSeconds = Math.max(1, Math.ceil((entry.resetAt - now) / 1000));
    return { allowed: false, retryAfterSeconds };
  }

  if (rateLimitByIp.size > 10_000) {
    for (const [key, value] of rateLimitByIp.entries()) {
      if (now >= value.resetAt) {
        rateLimitByIp.delete(key);
      }
    }
  }

  return { allowed: true, retryAfterSeconds: 0 };
}

function getAzureDevOpsClient(
  getAzureDevOpsToken: () => Promise<string>,
  userAgentComposer: UserAgentComposer,
  orgUrl: string
): () => Promise<WebApi> {
  return async () => {
    const accessToken = await getAzureDevOpsToken();
    const authHandler = getBearerHandler(accessToken);
    return new WebApi(orgUrl, authHandler, undefined, {
      productName: "AzureDevOps.MCP",
      productVersion: packageVersion,
      userAgent: userAgentComposer.userAgent,
    });
  };
}

function configureEnabledTools(
  server: McpServer,
  authenticator: () => Promise<string>,
  connectionProvider: () => Promise<WebApi>,
  userAgentProvider: () => string,
  enabledDomains: Set<string>
): void {
  const configureIfDomainEnabled = (domain: string, configureFn: () => void) => {
    if (enabledDomains.has(domain)) {
      configureFn();
    }
  };

  configureIfDomainEnabled(Domain.CORE, () => configureCoreTools(server, authenticator, connectionProvider, userAgentProvider));
  configureIfDomainEnabled(Domain.WORK, () => configureWorkTools(server, authenticator, connectionProvider));
  configureIfDomainEnabled(Domain.PIPELINES, () => configurePipelineTools(server, authenticator, connectionProvider, userAgentProvider));
  configureIfDomainEnabled(Domain.REPOSITORIES, () => configureRepoTools(server, authenticator, connectionProvider, userAgentProvider));
  configureIfDomainEnabled(Domain.WORK_ITEMS, () => configureWorkItemTools(server, authenticator, connectionProvider, userAgentProvider));
  configureIfDomainEnabled(Domain.WIKI, () => configureWikiTools(server, authenticator, connectionProvider, userAgentProvider));
  configureIfDomainEnabled(Domain.TEST_PLANS, () => configureTestPlanTools(server, authenticator, connectionProvider));
  configureIfDomainEnabled(Domain.ADVANCED_SECURITY, () => configureAdvSecTools(server, authenticator, connectionProvider));

  if (enabledDomains.has(Domain.SEARCH)) {
    throw new Error("Domain 'search' is not supported in bridge mode due to CLI-coupled import in upstream module.");
  }
}

async function main() {
  const orgName = requireEnv("ADO_ORG");
  const apiKey = requireEnv("MCP_API_KEY");
  const authType = (process.env.ADO_AUTH_TYPE ?? "envvar").toLowerCase();
  const tenantOverride = process.env.ADO_TENANT_ID;

  if (!ALLOWED_AUTH_TYPES.has(authType)) {
    throw new Error(`Unsupported ADO_AUTH_TYPE '${authType}'. Allowed values: ${Array.from(ALLOWED_AUTH_TYPES).join(", ")}`);
  }

  if (authType === "envvar") {
    requireEnv("ADO_MCP_AUTH_TOKEN");
  }

  const domains = parseDomains(process.env.ADO_DOMAINS);
  const orgUrl = `https://dev.azure.com/${orgName}`;

  logger.info("Starting Azure DevOps MCP Web Bridge", {
    organization: orgName,
    organizationUrl: orgUrl,
    authentication: authType,
    domains,
    version: packageVersion,
  });

  const server = new McpServer({
    name: "Azure DevOps MCP Server",
    version: packageVersion,
    icons: [{ src: "https://cdn.vsassets.io/content/icons/favicon.ico" }],
  });

  const userAgentComposer = new UserAgentComposer(packageVersion);
  server.server.oninitialized = () => {
    userAgentComposer.appendMcpClientInfo(server.server.getClientVersion());
  };

  const tenantId = (await getOrgTenant(orgName)) ?? tenantOverride;
  const authenticator = createAuthenticator(authType, tenantId);
  const domainsManager = new DomainsManager(domains);
  const enabledDomains = domainsManager.getEnabledDomains();

  configureEnabledTools(
    server,
    authenticator,
    getAzureDevOpsClient(authenticator, userAgentComposer, orgUrl),
    () => userAgentComposer.userAgent,
    enabledDomains
  );

  const transport = new StreamableHTTPServerTransport({ sessionIdGenerator: undefined });
  await server.connect(transport);

  const app = express();
  app.disable("x-powered-by");
  app.set("trust proxy", 1);
  app.use(express.json({ limit: "1mb" }));

  app.get("/healthz", (_req, res) => {
    res.status(200).json({ ok: true });
  });

  app.all("/sse", async (req, res) => {
    const clientIp = req.ip || req.socket.remoteAddress || "unknown";
    const rateLimit = checkRateLimit(clientIp);
    if (!rateLimit.allowed) {
      res.set("Retry-After", rateLimit.retryAfterSeconds.toString());
      res.status(429).json({ error: "Too Many Requests" });
      return;
    }

    const candidateKey = extractApiKeyFromHeaders(req.headers);
    if (!apiKeyMatches(candidateKey, apiKey)) {
      res.status(401).json({ error: "Unauthorized" });
      return;
    }

    try {
      await transport.handleRequest(req, res, req.body);
    } catch (error) {
      logger.error("Failed to handle MCP request:", error);
      if (!res.headersSent) {
        res.status(500).json({ error: "Internal server error" });
      }
    }
  });

  const port = Number(process.env.PORT ?? "3000");
  app.listen(port, () => {
    logger.info("Azure DevOps MCP bridge listening", { port });
  });

  const shutdown = async () => {
    logger.info("Shutting down Azure DevOps MCP bridge");
    await server.close();
    await transport.close();
    process.exit(0);
  };

  process.on("SIGINT", shutdown);
  process.on("SIGTERM", shutdown);
}

main().catch((error) => {
  logger.error("Fatal error in MCP bridge:", error);
  process.exit(1);
});
