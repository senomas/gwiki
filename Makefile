WIKI_REPO_PATH ?= ../seno-wiki/
WIKI_DATA_PATH ?= ./.wiki

docker-build:
	docker build --build-arg BUILD_TAG=$(BUILD_VERSION) --build-arg HTMX_VERSION=$(HTMX_VERSION) --build-arg NODE_VERSION=$(NODE_VERSION) --build-arg GO_VERSION=$(GO_VERSION) --build-arg ALPINE_VERSION=$(ALPINE_VERSION) -t gwiki .

BUILD_VERSION := $(shell git show -s --format=%cd --date=format:%Y.%m.%d.%H.%M.%S)
IMAGE_TAG := $(shell git show -s --format=%cd --date=format:%Y%m%d%H%M%S)
IMAGE := docker.senomas.com/gwiki
NODE_VERSION ?= 20-alpine
GO_VERSION ?= 1.25.5-alpine
ALPINE_VERSION ?= 3.19

build:
	@for f in .env*; do \
		if [ -f "$$f" ] && rg -q '^GWIKI_IMAGE=' "$$f"; then \
			sed -i 's|^GWIKI_IMAGE=.*|GWIKI_IMAGE=$(IMAGE):$(IMAGE_TAG)|' "$$f"; \
		fi; \
	done
	docker build --build-arg BUILD_TAG=$(BUILD_VERSION) --build-arg HTMX_VERSION=$(HTMX_VERSION) --build-arg NODE_VERSION=$(NODE_VERSION) --build-arg GO_VERSION=$(GO_VERSION) --build-arg ALPINE_VERSION=$(ALPINE_VERSION) -t $(IMAGE):$(IMAGE_TAG) .
	docker tag $(IMAGE):$(IMAGE_TAG) $(IMAGE):latest
	docker push $(IMAGE):$(IMAGE_TAG)
	docker push $(IMAGE):latest

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

NODE_IMAGE ?= node:20-alpine
TAILWIND_CONFIG ?= tailwind.config.js
TAILWIND_INPUT ?= assets/tailwind.css
TAILWIND_OUTPUT ?= static/css/app.css
TAILWIND_SOURCES := $(shell find templates internal -type f -name '*.html' -o -name '*.go')

css: $(TAILWIND_OUTPUT)

$(TAILWIND_OUTPUT): $(TAILWIND_INPUT) $(TAILWIND_CONFIG) $(TAILWIND_SOURCES)
	docker run --rm -v "$$(pwd)":/work -w /work $(NODE_IMAGE) \
		sh -lc "mkdir -p $$(dirname $(TAILWIND_OUTPUT)) && BROWSERSLIST_IGNORE_OLD_DATA=1 npx --yes --package tailwindcss@3.4.17 tailwindcss -c $(TAILWIND_CONFIG) -i $(TAILWIND_INPUT) -o $(TAILWIND_OUTPUT)"

css-watch:
	docker run --rm -it -v "$$(pwd)":/work -w /work $(NODE_IMAGE) \
		sh -lc "mkdir -p $$(dirname $(TAILWIND_OUTPUT)) && BROWSERSLIST_IGNORE_OLD_DATA=1 npx --yes --package tailwindcss@3.4.17 tailwindcss -c $(TAILWIND_CONFIG) -i $(TAILWIND_INPUT) -o $(TAILWIND_OUTPUT) --watch"

HTMX_VERSION ?= 1.9.12
HTMX_URL ?= https://unpkg.com/htmx.org@$(HTMX_VERSION)/dist/htmx.min.js
HTMX_OUTPUT ?= static/js/htmx.min.js

htmx: $(HTMX_OUTPUT)

$(HTMX_OUTPUT):
	mkdir -p $$(dirname $(HTMX_OUTPUT))
	curl -fsSL -o $(HTMX_OUTPUT) $(HTMX_URL)

e2e:
	docker compose up -d gwiki-e2e
	docker compose run --rm e2e
