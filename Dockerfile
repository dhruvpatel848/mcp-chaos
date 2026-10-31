FROM python:3.12-slim
WORKDIR /opt/mcp-chaos
COPY pyproject.toml README.md LICENSE ./
COPY src ./src
RUN pip install --no-cache-dir . && useradd -m chaos
USER chaos
WORKDIR /home/chaos
ENTRYPOINT []
CMD ["mcp-chaos", "--help"]
