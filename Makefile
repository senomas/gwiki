-include .env.build
-include .env
export

WIKI_REPO_PATH ?= ../seno-wiki/
WIKI_DATA_PATH ?= ./.wiki

docker-build:
	docker build --build-arg BUILD_TAG=$(BUILD_VERSION) --build-arg HTMX_VERSION=$(HTMX_VERSION) --build-arg NODE_VERSION=$(NODE_VERSION) --build-arg TAILWIND_VERSION=$(TAILWIND_VERSION) --build-arg GO_VERSION=$(GO_VERSION) --build-arg ALPINE_VERSION=$(ALPINE_VERSION) -t gwiki .

BUILD_VERSION := $(shell git show -s --format=%cd --date=format:%Y.%m.%d.%H.%M.%S)
IMAGE_TAG := $(shell git show -s --format=%cd --date=format:%Y%m%d%H%M%S)
IMAGE := docker.senomas.com/gwiki
NODE_VERSION ?= 20-alpine
GO_VERSION ?= 1.25.6-alpine
ALPINE_VERSION ?= 3.22
TAILWIND_VERSION ?= 3.4.17

build:
	@for f in .env*; do \
		if [ -f "$$f" ] && rg -q '^GWIKI_IMAGE=' "$$f"; then \
			sed -i 's|^GWIKI_IMAGE=.*|GWIKI_IMAGE=$(IMAGE):$(IMAGE_TAG)|' "$$f"; \
		fi; \
	done
	docker build --build-arg BUILD_TAG=$(BUILD_VERSION) --build-arg HTMX_VERSION=$(HTMX_VERSION) --build-arg NODE_VERSION=$(NODE_VERSION) --build-arg TAILWIND_VERSION=$(TAILWIND_VERSION) --build-arg GO_VERSION=$(GO_VERSION) --build-arg ALPINE_VERSION=$(ALPINE_VERSION) -t $(IMAGE):$(IMAGE_TAG) .
	docker tag $(IMAGE):$(IMAGE_TAG) $(IMAGE):latest
	docker push $(IMAGE):$(IMAGE_TAG)
	docker push $(IMAGE):latest

docker-run:
	docker run --rm -p 8080:8080 -v $(WIKI_REPO_PATH):/notes -v $(WIKI_DATA_PATH):/data -e WIKI_REPO_PATH=/notes -e WIKI_DATA_PATH=/data gwiki

dev:
	@if command -v reflex >/dev/null 2>&1; then \
		if [ ! -f ./tmp/main ]; then \
			$(MAKE) dev-build; \
		fi; \
		DEV=1 WIKI_REPO_PATH=$(WIKI_REPO_PATH) WIKI_DATA_PATH=$(WIKI_DATA_PATH) WIKI_DEBUG_LEVEL=info WIKI_LOG_PRETTY=1 WIKI_AUTH_SECRET=dev-secret-key reflex -s -r 'tmp/main$$' -- sh -lc './tmp/main'; \
	else \
		echo "reflex is not installed. Install with:"; \
		echo "  go install github.com/cespare/reflex@latest"; \
		exit 1; \
	fi

dev-build: static
	mkdir -p ./tmp
	WIKI_REPO_PATH=$(WIKI_REPO_PATH) WIKI_DATA_PATH=$(WIKI_DATA_PATH) go build -tags "sqlite_fts5" -ldflags "-X gwiki/internal/web.BuildVersion=$$(date +%Y.%m.%d.%H.%M.%S)" -o ./tmp/main ./cmd/wiki

NODE_IMAGE ?= node:20-alpine
TAILWIND_CONFIG ?= tailwind.config.js
TAILWIND_INPUT ?= assets/tailwind.css
TAILWIND_OUTPUT ?= static/css/app.css
TAILWIND_IMAGE ?= gwiki-tailwind:local
TAILWIND_DOCKER_USER ?= $(shell id -u):$(shell id -g)
TAILWIND_SOURCES := $(shell find templates internal -type f \( -name '*.html' -o -name '*.go' \))

.PHONY: tailwind-image

tailwind-image:
	docker build -f Dockerfile.tailwind --build-arg NODE_VERSION=$(NODE_VERSION) --build-arg TAILWIND_VERSION=$(TAILWIND_VERSION) -t $(TAILWIND_IMAGE) .

css: tailwind-image $(TAILWIND_OUTPUT)

$(TAILWIND_OUTPUT): $(TAILWIND_INPUT) $(TAILWIND_CONFIG) $(TAILWIND_SOURCES)
	mkdir -p $$(dirname $(TAILWIND_OUTPUT))
	docker run --rm --user $(TAILWIND_DOCKER_USER) -v "$$(pwd)":/work -w /work $(TAILWIND_IMAGE) \
		-c $(TAILWIND_CONFIG) -i $(TAILWIND_INPUT) -o $(TAILWIND_OUTPUT)

css-watch:
	mkdir -p $$(dirname $(TAILWIND_OUTPUT))
	docker run --rm -it --user $(TAILWIND_DOCKER_USER) -v "$$(pwd)":/work -w /work $(TAILWIND_IMAGE) \
		-c $(TAILWIND_CONFIG) -i $(TAILWIND_INPUT) -o $(TAILWIND_OUTPUT) --watch

HTMX_VERSION ?= 1.9.12
HTMX_URL ?= https://unpkg.com/htmx.org@$(HTMX_VERSION)/dist/htmx.min.js
HTMX_OUTPUT ?= static/js/htmx.min.js

htmx: $(HTMX_OUTPUT)

$(HTMX_OUTPUT):
	mkdir -p $$(dirname $(HTMX_OUTPUT))
	curl -fsSL -o $(HTMX_OUTPUT) $(HTMX_URL)

static: css htmx

e2e:
	docker compose up -d gwiki-e2e
	docker compose run --rm e2e
