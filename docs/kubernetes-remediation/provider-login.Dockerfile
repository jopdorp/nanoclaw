FROM registry.prophet.jopdorp.nl/nanoclaw/remediation-host@sha256:bf19fbf5b353451d44dab74c38ea01b6c658b10049d1a07b73efabbf5657df2d

USER root
RUN npm install --global --force pnpm@10.34.5 \
    && curl -fsSL -o /tmp/onecli.tar.gz https://github.com/onecli/onecli-cli/releases/download/v2.2.5/onecli_2.2.5_linux_amd64.tar.gz \
    && echo 'bd51bfbaed90d03081370d50b3733aa6b20790860a478191c216ac68b54d6495  /tmp/onecli.tar.gz' | sha256sum -c - \
    && tar -xzf /tmp/onecli.tar.gz -C /usr/local/bin onecli \
    && rm /tmp/onecli.tar.gz \
    && npm cache clean --force
USER node
