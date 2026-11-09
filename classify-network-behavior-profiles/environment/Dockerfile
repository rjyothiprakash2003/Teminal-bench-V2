FROM public.ecr.aws/docker/library/golang:1.24-bookworm@sha256:1a6d4452c65dea36aac2e2d606b01b4a029ec90cc1ae53890540ce6173ea77ac

# Agent must rebuild /app/build/huntctl after editing Go packages, and the
# verifier re-runs that build. Keep the Go toolchain plus make in the final
# image (documented single-stage carve-out for compile-at-runtime repair tasks).
LABEL org.opencontainers.image.title="classify-network-behavior-profiles" \
    org.opencontainers.image.description="Offline SOC network threat hunt admission and investigation ranker" \
    org.opencontainers.image.source="https://github.com/laude-institute/terminal-bench" \
    org.opencontainers.image.revision="1.0.2" \
    org.opencontainers.image.created="2026-07-24T00:00:00Z" \
    org.opencontainers.image.version="1.0.2" \
    org.opencontainers.image.licenses="MIT"

ENV DEBIAN_FRONTEND=noninteractive \
    PATH="/usr/local/go/bin:/go/bin:/usr/local/bin:/usr/bin:/bin" \
    GOTOOLCHAIN=local \
    GO111MODULE=on \
    GOPROXY=off \
    CGO_ENABLED=0 \
    GOROOT=/usr/local/go \
    LANG=C.UTF-8 \
    LC_ALL=C.UTF-8 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1 \
    SOURCE_DATE_EPOCH=0

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        asciinema \
        ca-certificates \
        make \
        python3 \
        python3-pip \
        tmux \
    && ln -sf /usr/bin/python3 /usr/bin/python \
    && ln -sf /usr/local/go/bin/go /usr/local/bin/go \
    && ln -sf /usr/local/go/bin/gofmt /usr/local/bin/gofmt \
    && printf '%s\n' 'export PATH="/usr/local/go/bin:/go/bin:/usr/local/bin:/usr/bin:/bin"' > /etc/profile.d/go-path.sh \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.lock /tmp/requirements.lock
COPY verifier-wheels/ /opt/verifier-wheels/

RUN pip3 install --break-system-packages --no-cache-dir --no-index \
        --find-links=/opt/verifier-wheels \
        --require-hashes \
        -r /tmp/requirements.lock \
    && rm -rf /root/.cache /tmp/requirements.lock

WORKDIR /app

COPY go.mod Makefile /app/
COPY hunt_captures/ /app/hunt_captures/
COPY detect_policy/ /app/detect_policy/
COPY huntgate/ /app/huntgate/
COPY sigscore/ /app/sigscore/
COPY peerhunt/ /app/peerhunt/
COPY triageprio/ /app/triageprio/

RUN mkdir -p /app/build
