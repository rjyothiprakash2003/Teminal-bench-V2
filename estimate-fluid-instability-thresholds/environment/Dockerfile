FROM public.ecr.aws/docker/library/golang:1.24-bookworm@sha256:1a6d4452c65dea36aac2e2d606b01b4a029ec90cc1ae53890540ce6173ea77ac

# The Go toolchain remains in the runtime image because agents must rebuild
# /app/build/instabctl after editing Go packages, and the verifier re-runs
# make build. That makes the single-stage layout the documented carve-out for
# the multi-stage build warning.
LABEL org.opencontainers.image.title="estimate-fluid-instability-thresholds" \
    org.opencontainers.image.description="Scientific computing Kelvin-Helmholtz stratified shear instability threshold estimator" \
    org.opencontainers.image.source="https://github.com/laude-institute/terminal-bench" \
    org.opencontainers.image.revision="1.0.0" \
    org.opencontainers.image.created="2026-07-25T00:00:00Z" \
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

WORKDIR /app

COPY go.mod Makefile /app/
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
    && ln -sf /usr/bin/python3 /usr/local/bin/python \
    && ln -sf /usr/local/go/bin/go /usr/local/bin/go \
    && ln -sf /usr/local/go/bin/gofmt /usr/local/bin/gofmt \
    && printf '%s\n' 'export PATH="/usr/local/go/bin:/go/bin:/usr/local/bin:/usr/bin:/bin"' > /etc/profile.d/go-path.sh \
    && pip3 install --break-system-packages --no-cache-dir --no-index \
        --find-links=/opt/verifier-wheels \
        --require-hashes \
        -r /tmp/requirements.lock \
    && rm -rf /var/lib/apt/lists/* /root/.cache /tmp/requirements.lock

COPY flow_suites/ /app/flow_suites/
COPY thresh_contract/ /app/thresh_contract/
COPY flowgate/ /app/flowgate/
COPY shearfv/ /app/shearfv/
COPY growscan/ /app/growscan/
COPY massguard/ /app/massguard/

RUN mkdir -p /app/build
