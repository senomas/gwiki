-include .env.build
-include .env
-include .env.local
export

.PHONY: docker-build build deploy docker-run dev dev-local tailwind-image css css-watch htmx static e2e ensure-clean update-env-image compose-restart docker-prune-old-gwiki-images

WIKI_REPO_PATH ?= ../seno-wiki/
WIKI_DATA_PATH ?= ./.wiki
COMPOSE_ENV_FILES := --env-file .env
ifneq ($(wildcard .env.local),)
COMPOSE_ENV_FILES += --env-file .env.local
endif
COMPOSE := docker compose $(COMPOSE_ENV_FILES)

docker-build:
	docker build --build-arg BUILD_TAG=$(BUILD_VERSION) --build-arg HTMX_VERSION=$(HTMX_VERSION) --build-arg NODE_VERSION=$(NODE_VERSION) --build-arg TAILWIND_VERSION=$(TAILWIND_VERSION) --build-arg GO_VERSION=$(GO_VERSION) --build-arg ALPINE_VERSION=$(ALPINE_VERSION) -t gwiki .

GIT_SHA_SHORT := $(shell git rev-parse --short HEAD)
BUILD_TS := $(shell date +%Y%m%d%H%M%S)
BUILD_VERSION_TS := $(shell date +%Y-%m-%d.%H:%M)
BUILD_VERSION := $(BUILD_VERSION_TS)-$(GIT_SHA_SHORT)
IMAGE_TAG := $(GIT_SHA_SHORT)-$(BUILD_TS)
DOCKER_IMAGE_NAME ?= gwiki
DOCKER_REGISTRY_TRIMMED := $(patsubst %/,%,$(strip $(DOCKER_REGISTRY)))
ifeq ($(DOCKER_REGISTRY_TRIMMED),)
IMAGE := $(DOCKER_IMAGE_NAME)
else
IMAGE := $(DOCKER_REGISTRY_TRIMMED)/$(DOCKER_IMAGE_NAME)
endif
NODE_VERSION ?= 20-alpine
GO_VERSION ?= 1.25.6-alpine
ALPINE_VERSION ?= 3.22
TAILWIND_VERSION ?= 3.4.17

ensure-clean:
	@if [ -n "$$(git status --porcelain)" ]; then \
		echo "ERROR: git working tree is not clean."; \
		git status -sb; \
		exit 1; \
	fi

update-env-image:
	@touch .env.local
	@if rg -q '^GWIKI_IMAGE=' .env.local; then \
		sed -i 's|^GWIKI_IMAGE=.*|GWIKI_IMAGE=$(IMAGE):$(IMAGE_TAG)|' .env.local; \
	else \
		printf '\nGWIKI_IMAGE=%s:%s\n' "$(IMAGE)" "$(IMAGE_TAG)" >> .env.local; \
	fi
	@echo "Updated .env.local with GWIKI_IMAGE=$(IMAGE):$(IMAGE_TAG)"

compose-restart:
	$(COMPOSE) up -d --force-recreate gwiki
	$(COMPOSE) ps gwiki

docker-prune-old-gwiki-images:
	@now=$$(date -u +%s); \
	for image in $$(docker image ls "$(IMAGE)" --format '{{.Repository}}:{{.Tag}}' | sort -u); do \
		case "$$image" in \
			"$(IMAGE):latest"|*":<none>") continue ;; \
		esac; \
		created=$$(docker image inspect -f '{{.Created}}' "$$image" 2>/dev/null || true); \
		if [ -z "$$created" ]; then \
			continue; \
		fi; \
		created_ts=$$(date -u -d "$$created" +%s 2>/dev/null || true); \
		if [ -z "$$created_ts" ]; then \
			continue; \
		fi; \
		age=$$((now-created_ts)); \
		if [ $$age -gt 86400 ]; then \
			echo "Removing old image $$image"; \
			docker image rm "$$image" >/dev/null 2>&1 || echo "WARN: failed to remove $$image"; \
		fi; \
	done

deploy:
	@if [ -n "$(strip $(TRUENAS_SERVER))" ] && [ -n "$(strip $(TRUENAS_PATH))" ] && [ -n "$(strip $(TRUENAS_APP))" ]; then \
		if [ ! -f .env.truenas ]; then \
			echo "ERROR: .env.truenas not found"; \
			exit 1; \
		fi; \
		echo "Deploying TrueNAS app $(TRUENAS_APP) on $(TRUENAS_SERVER)"; \
		ssh truenas_admin@$(TRUENAS_SERVER) "midclt call app.stop $(TRUENAS_APP)"; \
		scp .env.truenas truenas_admin@$(TRUENAS_SERVER):$(TRUENAS_PATH)/.env; \
		ssh truenas_admin@$(TRUENAS_SERVER) "midclt call app.start $(TRUENAS_APP)"; \
	else \
		echo "Skipping TrueNAS deploy (set TRUENAS_SERVER, TRUENAS_PATH, TRUENAS_APP in .env.local)"; \
	fi

build: ensure-clean
	@echo "Building image $(IMAGE):$(IMAGE_TAG)"
	docker build --build-arg BUILD_TAG=$(BUILD_VERSION) --build-arg HTMX_VERSION=$(HTMX_VERSION) --build-arg NODE_VERSION=$(NODE_VERSION) --build-arg TAILWIND_VERSION=$(TAILWIND_VERSION) --build-arg GO_VERSION=$(GO_VERSION) --build-arg ALPINE_VERSION=$(ALPINE_VERSION) -t $(IMAGE):$(IMAGE_TAG) .
	docker tag $(IMAGE):$(IMAGE_TAG) $(IMAGE):latest
	docker push $(IMAGE):$(IMAGE_TAG)
	docker push $(IMAGE):latest
	$(MAKE) update-env-image IMAGE_TAG=$(IMAGE_TAG)
	$(MAKE) compose-restart
	$(MAKE) docker-prune-old-gwiki-images

docker-run:
	docker run --rm -p 8080:8080 -v $(WIKI_REPO_PATH):/notes -v $(WIKI_DATA_PATH):/data -e WIKI_REPO_PATH=/notes -e WIKI_DATA_PATH=/data gwiki

dev:
	$(COMPOSE) up -d gwiki
	$(COMPOSE) ps gwiki

dev-local:
	@if command -v reflex >/dev/null 2>&1; then \
		if [ ! -f ./tmp/main ]; then \
			$(MAKE) static; \
			mkdir -p ./tmp; \
			WIKI_REPO_PATH=$(WIKI_REPO_PATH) WIKI_DATA_PATH=$(WIKI_DATA_PATH) go build -tags "sqlite_fts5" -ldflags "-X gwiki/internal/web.BuildVersion=$(BUILD_VERSION)" -o ./tmp/main ./cmd/wiki; \
		fi; \
		DEV=1 WIKI_REPO_PATH=$(WIKI_REPO_PATH) WIKI_DATA_PATH=$(WIKI_DATA_PATH) WIKI_DEBUG_LEVEL=info WIKI_LOG_PRETTY=1 WIKI_AUTH_SECRET=dev-secret-key reflex -s -r 'tmp/main$$' -- sh -lc './tmp/main'; \
	else \
		echo "reflex is not installed. Install with:"; \
		echo "  go install github.com/cespare/reflex@latest"; \
		exit 1; \
	fi

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
	$(COMPOSE) up -d gwiki
	$(COMPOSE) run --rm e2e
