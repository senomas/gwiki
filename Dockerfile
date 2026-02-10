ARG NODE_VERSION=20-alpine
ARG GO_VERSION=1.25.5-alpine
ARG ALPINE_VERSION=3.19
ARG TAILWIND_VERSION=3.4.17

FROM node:${NODE_VERSION} AS assets

WORKDIR /app
ARG HTMX_VERSION=1.9.12
ARG TAILWIND_VERSION=3.4.17
RUN apk add --no-cache curl
RUN mkdir -p /app/static/css /app/static/js
RUN curl -fsSL -o /app/static/js/htmx.min.js https://unpkg.com/htmx.org@${HTMX_VERSION}/dist/htmx.min.js
RUN npm init -y >/dev/null 2>&1
RUN npm install --silent tailwindcss@${TAILWIND_VERSION}
COPY assets/tailwind.css /app/assets/tailwind.css
COPY tailwind.config.js /app/tailwind.config.js
COPY templates /app/templates
COPY internal /app/internal
RUN BROWSERSLIST_IGNORE_OLD_DATA=1 npx --yes --verbose --package tailwindcss@${TAILWIND_VERSION} tailwindcss \
  -c /app/tailwind.config.js \
  -i /app/assets/tailwind.css \
  -o /app/static/css/app.css

FROM golang:${GO_VERSION} AS build-base

WORKDIR /src
RUN apk add --no-cache gcc musl-dev
COPY go.mod go.sum ./
RUN go mod download
ARG BUILD_TAG=dev
ARG BUILD_VERSION=dev
COPY cmd ./cmd
COPY internal ./internal
COPY templates ./templates

FROM build-base AS test
RUN CGO_ENABLED=1 go test -tags "sqlite_fts5" ./...

FROM test AS build
RUN CGO_ENABLED=1 go build -tags "sqlite_fts5" -ldflags="-X gwiki/internal/web.BuildVersion=${BUILD_VERSION}" -o /out/wiki ./cmd/wiki
RUN CGO_ENABLED=1 go build -tags "sqlite_fts5" -o /out/user ./cmd/user

FROM alpine:${ALPINE_VERSION}

WORKDIR /app
RUN apk add --no-cache ffmpeg git tzdata
COPY templates /app/templates
COPY static /app/static
COPY --from=assets /app/static /app/static
COPY --from=build /out/wiki /usr/local/bin/wiki
COPY --from=build /out/user /usr/local/bin/gwiki-user
ENV WIKI_LISTEN_ADDR=0.0.0.0:8080
ENV WIKI_REPO_PATH=/data
ENV TZ=UTC
EXPOSE 8080
CMD ["wiki"]
