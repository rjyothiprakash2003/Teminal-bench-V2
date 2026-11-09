# syntax=docker/dockerfile:1
FROM public.ecr.aws/docker/library/golang:1.24-bookworm@sha256:1a6d4452c65dea36aac2e2d606b01b4a029ec90cc1ae53890540ce6173ea77ac

LABEL org.opencontainers.image.title="dart-pub-dependency-conflict-analyzer" \
    org.opencontainers.image.description="Offline deterministic Dart pub monorepository dependency analyzer" \
    org.opencontainers.image.source="https://github.com/laude-institute/terminal-bench" \
    org.opencontainers.image.revision="2.2.0" \
    org.opencontainers.image.created="2026-07-19T00:00:00Z" \
    org.opencontainers.image.version="2.2.0" \
    org.opencontainers.image.licenses="MIT"

ENV DEBIAN_FRONTEND=noninteractive \
    PATH="/usr/local/go/bin:/go/bin:/usr/local/bin:/usr/bin:/bin" \
    GOTOOLCHAIN=local \
    GOPROXY=off \
    GO111MODULE=on \
    CGO_ENABLED=0 \
    LANG=C.UTF-8 \
    LC_ALL=C.UTF-8 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1 \
    SOURCE_DATE_EPOCH=0

COPY requirements.lock /tmp/requirements.lock

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        asciinema \
        ca-certificates \
        make \
        python3 \
        python3-pip \
        tmux \
    && ln -sf /usr/bin/python3 /usr/local/bin/python \
    && ln -sf /usr/local/go/bin/go /usr/local/bin/go \
    && ln -sf /usr/local/go/bin/gofmt /usr/local/bin/gofmt \
    && pip3 install --break-system-packages --no-cache-dir --require-hashes \
        -r /tmp/requirements.lock \
    && rm -f /tmp/requirements.lock \
    && rm -rf /var/lib/apt/lists/* /root/.cache

WORKDIR /app

COPY pubforge_seed/go.mod /app/go.mod
COPY pubforge_seed/Makefile /app/Makefile
COPY pubforge_seed/cmd/ /app/cmd/
COPY pubforge_seed/internal/ /app/internal/
COPY pubforge_report_contract.json /app/pubforge_report_contract.json
COPY pubforge_workspace/ /app/pubforge_workspace/

RUN mkdir -p /app/bin
