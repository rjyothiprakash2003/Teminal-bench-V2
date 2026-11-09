FROM public.ecr.aws/docker/library/golang:1.24-bookworm@sha256:1a6d4452c65dea36aac2e2d606b01b4a029ec90cc1ae53890540ce6173ea77ac

# Agent must rebuild /app/build/alsctl after editing Go packages, so the
# Go toolchain remains in the final runtime image (not a multi-stage strip).
LABEL org.opencontainers.image.title="optimize-active-learning-sampling" \
    org.opencontainers.image.description="Offline active learning sampling efficiency replay validator" \
    org.opencontainers.image.source="https://github.com/laude-institute/terminal-bench" \
    org.opencontainers.image.revision="1.0.0" \
    org.opencontainers.image.created="2026-07-26T00:00:00Z" \
    org.opencontainers.image.version="1.0.0" \
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

COPY requirements.lock /tmp/requirements.lock
COPY verifier-wheels/ /opt/verifier-wheels/

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
    && pip3 install --break-system-packages --no-cache-dir --no-index \
        --find-links=/opt/verifier-wheels \
        --require-hashes \
        -r /tmp/requirements.lock \
    && rm -rf /var/lib/apt/lists/* /root/.cache /tmp/requirements.lock

WORKDIR /app

COPY go.mod Makefile /app/
COPY label_suites/ /app/label_suites/
COPY sampling_policy/ /app/sampling_policy/
COPY samplegate/ /app/samplegate/
COPY pickcore/ /app/pickcore/
COPY stratops/ /app/stratops/
COPY effimath/ /app/effimath/

RUN mkdir -p /app/build
