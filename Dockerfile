# syntax=docker/dockerfile:1

# Base images are pinned by digest. Bump them deliberately, not implicitly.

# Frontend build: npm dependencies are cached until package-lock.json changes.
FROM node:24-alpine@sha256:ebfe2f90462722a7a4de65e91990e97fe0d401c70e0e762c5b53302f905ec1c1 AS web
WORKDIR /src
COPY web/package.json web/package-lock.json web/
RUN cd web && npm ci --no-audit --no-fund
COPY web web/
RUN cd web && npm run build

FROM golang:1.26.5-alpine@sha256:0178a641fbb4858c5f1b48e34bdaabe0350a330a1b1149aabd498d0699ff5fb2 AS builder
WORKDIR /src
# Module downloads are cached until go.mod or go.sum changes.
COPY go.mod go.sum ./
RUN go mod download
COPY . .
COPY --from=web /src/internal/web/static internal/web/static
ARG VERSION=devel
RUN CGO_ENABLED=0 go build \
    -trimpath \
    -ldflags="-s -w -X main.version=$VERSION" \
    -o /kfadapter \
    ./cmd/kfadapter

FROM alpine:3.23@sha256:85fe1e81d6758c208f3e1eed4338a1997e19d4be002d4dd32d3100c9a8c010a0
RUN apk add --no-cache ca-certificates tzdata \
    && mkdir -p /kfadapter/data \
    && chown -R 65532:65532 /kfadapter \
    && chmod 0700 /kfadapter/data
WORKDIR /kfadapter
ARG VERSION=devel
LABEL org.opencontainers.image.version="$VERSION"
COPY --from=builder --chown=65532:65532 /kfadapter ./kfadapter
USER 65532:65532
ENTRYPOINT ["./kfadapter"]
