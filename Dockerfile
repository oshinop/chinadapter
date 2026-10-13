# syntax=docker/dockerfile:1

# Base images are pinned by digest. Bump them deliberately, not implicitly.

# Frontend build: npm dependencies are cached until package-lock.json changes.
FROM node:24-alpine@sha256:ebfe2f90462722a7a4de65e91990e97fe0d401c70e0e762c5b53302f905ec1c1 AS web
WORKDIR /src
COPY web/package.json web/package-lock.json web/
RUN cd web && npm ci --no-audit --no-fund
COPY web web/
RUN cd web && npm run build

FROM golang:1.26.9-alpine@sha256:3082400e369fa24d5fc60bca20edab3f6d604e0c5a690ec66b295eff4dd87ade AS builder
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
    -o /chinadapter \
    ./cmd/chinadapter

FROM alpine:3.23@sha256:85fe1e81d6758c208f3e1eed4338a1997e19d4be002d4dd32d3100c9a8c010a0
RUN apk add --no-cache ca-certificates tzdata \
    && mkdir -p /chinadapter/data \
    && chown -R 65532:65532 /chinadapter \
    && chmod 0700 /chinadapter/data
WORKDIR /chinadapter
ARG VERSION=devel
LABEL org.opencontainers.image.version="$VERSION"
COPY --from=builder --chown=65532:65532 /chinadapter ./chinadapter
USER 65532:65532
ENTRYPOINT ["./chinadapter"]
