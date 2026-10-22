# syntax=docker/dockerfile:1.7@sha256:a57df69d0ea827fb7266491f2813635de6f17269be881f696fbfdf2d83dda33e
ARG AGENT_IMAGE
ARG GIT_COMMIT
ARG GIT_TREE
FROM node:22-slim AS build
WORKDIR /opt/nanoclaw
RUN corepack enable && corepack prepare pnpm@10.34.5 --activate
# The helm-release tests drive a real git repo.
RUN apt-get update && apt-get install -y --no-install-recommends git && rm -rf /var/lib/apt/lists/*
COPY package.json pnpm-lock.yaml pnpm-workspace.yaml .npmrc ./
COPY patches ./patches
RUN HUSKY=0 pnpm install --frozen-lockfile
RUN node -e "const Database=require('better-sqlite3'); const db=new Database(':memory:'); db.close()"
COPY tsconfig.json vitest.config.ts ./
COPY src ./src
RUN pnpm run build && pnpm exec vitest run src/modules/kubernetes-remediation

FROM ${AGENT_IMAGE}
ARG GIT_COMMIT
ARG GIT_TREE
ENV NANOCLAW_GIT_COMMIT="${GIT_COMMIT}"
ENV NANOCLAW_GIT_TREE="${GIT_TREE}"
LABEL org.opencontainers.image.revision="${GIT_COMMIT}"
LABEL dev.nanoclaw.source-tree="${GIT_TREE}"
USER root
# The remediation module shells out to `onecli run` for gateway-credentialed Kubernetes calls.
RUN curl -fsSL -o /tmp/onecli.tar.gz https://github.com/onecli/onecli-cli/releases/download/v2.2.5/onecli_2.2.5_linux_amd64.tar.gz \
    && echo 'bd51bfbaed90d03081370d50b3733aa6b20790860a478191c216ac68b54d6495  /tmp/onecli.tar.gz' | sha256sum -c - \
    && tar -xzf /tmp/onecli.tar.gz -C /usr/local/bin onecli \
    && rm /tmp/onecli.tar.gz
# helm-values plans push to k8s.jegor.nl over SSH and run helm upgrade.
RUN apt-get update && apt-get install -y --no-install-recommends git openssh-client && rm -rf /var/lib/apt/lists/* \
    && curl -fsSL -o /tmp/helm.tar.gz https://get.helm.sh/helm-v4.3.1-linux-amd64.tar.gz \
    && echo '0403a88ae20913d11b10a2467b50087721fea7581736da6b9d3992f5357fe54b  /tmp/helm.tar.gz' | sha256sum -c - \
    && tar -xzf /tmp/helm.tar.gz -C /usr/local/bin --strip-components=1 linux-amd64/helm \
    && rm /tmp/helm.tar.gz
WORKDIR /opt/nanoclaw
COPY --from=build /opt/nanoclaw/node_modules ./node_modules
COPY --from=build /opt/nanoclaw/dist ./dist
COPY package.json pnpm-lock.yaml pnpm-workspace.yaml .npmrc tsconfig.json ./
COPY src ./src
COPY setup ./setup
COPY scripts ./scripts
COPY bin ./bin
COPY .claude/skills/add-codex ./.claude/skills/add-codex
COPY .claude/skills/add-onecli ./.claude/skills/add-onecli
COPY container/AGENTS.md container/CLAUDE.md container/cli-tools.json ./container/
COPY container/agent-runner/src ./container/agent-runner/src
RUN chown -R node:node /opt/nanoclaw
USER node
