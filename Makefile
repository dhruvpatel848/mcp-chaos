.PHONY: install test lint demo docker
install:
	pip install -e ".[dev,dashboard,langgraph]"
test:
	pytest -q
lint:
	ruff check src tests
demo:
	mcp-chaos attack --target demo:vulnerable; mcp-chaos attack --target demo:secure
docker:
	docker build -t mcp-chaos:local .
