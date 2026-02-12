FROM node:20-slim

ARG ADO_MCP_REF=v2.4.0

RUN apt-get update \
  && apt-get install -y --no-install-recommends git ca-certificates \
  && rm -rf /var/lib/apt/lists/*

WORKDIR /opt
RUN git clone --depth 1 --branch ${ADO_MCP_REF} https://github.com/microsoft/azure-devops-mcp.git

WORKDIR /opt/azure-devops-mcp
RUN npm install --omit=dev --ignore-scripts
RUN npm install --omit=dev --ignore-scripts --no-save express tsx

RUN mkdir -p /opt/azure-devops-mcp/bridge
COPY index.ts /opt/azure-devops-mcp/bridge/index.ts

ENV NODE_ENV=production
RUN chown -R node:node /opt/azure-devops-mcp
USER node
EXPOSE 3000

CMD ["npx", "tsx", "bridge/index.ts"]
