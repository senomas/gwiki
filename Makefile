WIKI_REPO_PATH ?= .

docker-build:
	docker build -t gwiki .

docker-run:
	docker run --rm -p 8080:8080 -v $(WIKI_REPO_PATH):/data gwiki

run:
	WIKI_REPO_PATH=$(WIKI_REPO_PATH) go run ./cmd/wiki
