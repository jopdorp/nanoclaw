# Orfie's shared memory image: the qmem CLI, its MCP server and the LoRA encoder, built over a qmem checkout (jopdorp/qmem 302f028).
# The base EmbeddingGemma weights are mounted at /data/embeddinggemma; the server checks them against its signature.
FROM docker.io/library/python:3.12-slim@sha256:cb33f7f771ecec2ef1225cf39b159591a040391bd73e4c01f00fdfc4c47611d2
RUN pip install --no-cache-dir --index-url https://download.pytorch.org/whl/cpu torch==2.14.0+cpu \
 && pip install --no-cache-dir numpy==2.5.3 sentence-transformers==6.1.0 transformers==5.17.0 peft==0.21.2
COPY --chmod=755 qmem mcp-mem.py qmem_sparse.py /home/qmem/.local/bin/
COPY embed-server.py /opt/qmem/
COPY experiments/adapters/qmem-embeddinggemma-lora /opt/qmem/qmem-embeddinggemma-lora
USER 1000:1000
WORKDIR /opt/qmem
