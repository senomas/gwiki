ARG NODE_VERSION=20-alpine
ARG GO_VERSION=1.25.5-alpine
ARG ALPINE_VERSION=3.19

FROM node:${NODE_VERSION} AS assets

WORKDIR /app
ARG HTMX_VERSION=1.9.12
RUN apk add --no-cache curl
COPY assets/tailwind.css /app/assets/tailwind.css
COPY tailwind.config.js /app/tailwind.config.js
COPY templates /app/templates
COPY internal /app/internal
RUN mkdir -p /app/static/css /app/static/js
RUN BROWSERSLIST_IGNORE_OLD_DATA=1 npx --yes --package tailwindcss@3.4.17 tailwindcss \
  -c /app/tailwind.config.js \
  -i /app/assets/tailwind.css \
  -o /app/static/css/app.css
RUN curl -fsSL -o /app/static/js/htmx.min.js https://unpkg.com/htmx.org@${HTMX_VERSION}/dist/htmx.min.js

FROM golang:${GO_VERSION} AS build

WORKDIR /src
ARG BUILD_TAG=dev
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -ldflags="-X gwiki/internal/web.BuildVersion=${BUILD_TAG}" -o /out/wiki ./cmd/wiki
RUN CGO_ENABLED=0 go build -o /out/sync ./cmd/sync

FROM alpine:${ALPINE_VERSION}

WORKDIR /app
RUN apk add --no-cache ffmpeg git tzdata
COPY templates /app/templates
COPY static /app/static
COPY --from=assets /app/static /app/static
COPY --from=build /out/wiki /usr/local/bin/wiki
COPY --from=build /out/sync /usr/local/bin/sync
ENV WIKI_LISTEN_ADDR=0.0.0.0:8080
ENV WIKI_REPO_PATH=/data
ENV TZ=UTC
EXPOSE 8080
CMD ["wiki"]
