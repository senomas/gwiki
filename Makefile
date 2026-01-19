WIKI_REPO_PATH ?= ../seno-wiki/
WIKI_DATA_PATH ?= ./.wiki

docker-build:
	docker build -t gwiki .

BUILD_TAG := $(shell git show -s --format=%cd --date=format:%Y%m%d%H%M%S)
IMAGE := docker.senomas.com/gwiki
SYNC_IMAGE := docker.senomas.com/gwiki-sync

build:
	docker build -t $(IMAGE):$(BUILD_TAG) .
	docker tag $(IMAGE):$(BUILD_TAG) $(IMAGE):latest
	docker push $(IMAGE):$(BUILD_TAG)
	docker push $(IMAGE):latest
	docker build -f Dockerfile.git-sync -t $(SYNC_IMAGE):$(BUILD_TAG) .
	docker tag $(SYNC_IMAGE):$(BUILD_TAG) $(SYNC_IMAGE):latest
	docker push $(SYNC_IMAGE):$(BUILD_TAG)
	docker push $(SYNC_IMAGE):latest

docker-run:
	docker run --rm -p 8080:8080 -v $(WIKI_REPO_PATH):/notes -v $(WIKI_DATA_PATH):/data -e WIKI_REPO_PATH=/notes -e WIKI_DATA_PATH=/data gwiki

dev:
	@if command -v air >/dev/null 2>&1; then \
		WIKI_REPO_PATH=$(WIKI_REPO_PATH) WIKI_DATA_PATH=$(WIKI_DATA_PATH) WIKI_LOG_LEVEL=debug WIKI_LOG_PRETTY=1 air -c .air.toml; \
	else \
		echo "air is not installed. Install with:"; \
		echo "  go install github.com/air-verse/air@latest"; \
		exit 1; \
	fi
