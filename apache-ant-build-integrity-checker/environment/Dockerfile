FROM public.ecr.aws/docker/library/golang:1.24-bookworm@sha256:1a6d4452c65dea36aac2e2d606b01b4a029ec90cc1ae53890540ce6173ea77ac

# The Go compiler remains available because repairing and rebuilding the verifier
# is the task. Apache Ant and a JDK are required for local validation.
LABEL org.opencontainers.image.title="apache-ant-build-integrity-checker" \
    org.opencontainers.image.description="Offline Apache Ant release gate for build evidence" \
    org.opencontainers.image.source="https://github.com/laude-institute/terminal-bench" \
    org.opencontainers.image.revision="2.2.0" \
    org.opencontainers.image.created="2026-07-19T00:00:00Z" \
    org.opencontainers.image.version="2.2.0" \
    org.opencontainers.image.licenses="MIT"

ENV DEBIAN_FRONTEND=noninteractive \
    PATH="/usr/local/go/bin:/go/bin:/usr/local/bin:/usr/bin:/bin" \
    GOTOOLCHAIN=local \
    GOPROXY=off \
    CGO_ENABLED=0 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1 \
    SOURCE_DATE_EPOCH=946684800 \
    LANG=C.UTF-8 \
    LC_ALL=C.UTF-8 \
    HOME=/home/model \
    GOPATH=/home/model/go \
    GOCACHE=/home/model/go/cache \
    GOTMPDIR=/home/model/tmp

COPY requirements.lock /tmp/requirements.lock
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        ant \
        asciinema \
        ca-certificates \
        default-jdk-headless \
        make \
        passwd \
        python3 \
        python3-pip \
        tmux \
        util-linux \
    && ln -sf /usr/bin/python3 /usr/local/bin/python \
    && ln -sf /usr/local/go/bin/go /usr/local/bin/go \
    && ln -sf /usr/local/go/bin/gofmt /usr/local/bin/gofmt \
    && pip3 install --break-system-packages --no-cache-dir --require-hashes \
        -r /tmp/requirements.lock \
    && rm -rf /var/lib/apt/lists/* /root/.cache /tmp/requirements.lock

# Default USER stays root so Harbor/Daytona can boot (non-root default hangs ensure_dirs).
# Oracle/agent work drops to the unprivileged "model" identity via runuser. Verifier
# python is a separate root-owned binary under /opt/verifier that model cannot replace.
# Agents must rebuild antlock at runtime, so the Go toolchain remains in this single stage.
RUN /usr/sbin/useradd --create-home --uid 10001 --shell /bin/bash model \
    && mkdir -p /app/build /home/model/go/cache /home/model/tmp /opt/verifier/bin /logs/verifier \
    && cp -a "$(readlink -f /usr/bin/python3)" /opt/verifier/bin/python3 \
    && ln -sf /usr/sbin/runuser /opt/verifier/bin/runuser \
    && chown root:root /opt/verifier/bin/python3 \
    && chown -h root:root /opt/verifier/bin/runuser \
    && chmod 0755 /opt/verifier /opt/verifier/bin \
    && chmod 0555 /opt/verifier/bin/python3 \
    && chmod 1777 /logs /logs/verifier \
    && chown model:model /app /app/build /home/model /home/model/go /home/model/go/cache /home/model/tmp

WORKDIR /app

COPY --chown=model:model go.mod Makefile /app/
COPY --chown=model:model antlock/ /app/antlock/
COPY --chown=model:model auditmodel/ /app/auditmodel/
COPY --chown=model:model evidenceledger/ /app/evidenceledger/
COPY --chown=model:model forgegraph/ /app/forgegraph/
COPY --chown=model:model propseal/ /app/propseal/
COPY --chown=model:model reportwire/ /app/reportwire/
COPY --chown=model:model ember_workcell/ /app/ember_workcell/
