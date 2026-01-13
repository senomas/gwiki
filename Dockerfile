FROM golang:1.25.5-alpine AS build

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -o /out/wiki ./cmd/wiki

FROM alpine:3.19

WORKDIR /app
COPY templates /app/templates
COPY --from=build /out/wiki /usr/local/bin/wiki
ENV WIKI_LISTEN_ADDR=0.0.0.0:8080
ENV WIKI_REPO_PATH=/data
EXPOSE 8080
CMD ["wiki"]
