WIKI_REPO_PATH ?= .
WIKI_DATA_PATH ?= $(WIKI_REPO_PATH)/.wiki

docker-build:
	docker build -t gwiki .

build:
	docker build -t docker.senomas.com/gwiki .

docker-run:
	docker run --rm -p 8080:8080 -v $(WIKI_REPO_PATH):/notes -v $(WIKI_DATA_PATH):/data -e WIKI_REPO_PATH=/notes -e WIKI_DATA_PATH=/data gwiki

dev:
	@if command -v air >/dev/null 2>&1; then \
		WIKI_REPO_PATH=$(WIKI_REPO_PATH) WIKI_DATA_PATH=$(WIKI_DATA_PATH) air -c .air.toml; \
	else \
		echo "air is not installed. Install with:"; \
		echo "  go install github.com/air-verse/air@latest"; \
		exit 1; \
	fi
