FROM golang:1.25.5-alpine AS build

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -o /out/wiki ./cmd/wiki
RUN CGO_ENABLED=0 go build -o /out/sync ./cmd/sync

FROM alpine:3.19

WORKDIR /app
RUN apk add --no-cache ffmpeg git tzdata
COPY templates /app/templates
COPY static /app/static
COPY --from=build /out/wiki /usr/local/bin/wiki
COPY --from=build /out/sync /usr/local/bin/sync
ENV WIKI_LISTEN_ADDR=0.0.0.0:8080
ENV WIKI_REPO_PATH=/data
ENV TZ=UTC
EXPOSE 8080
CMD ["wiki"]
