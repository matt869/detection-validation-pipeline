# Runtime image for the validation pipeline.
#
# Two stages so the final image carries no build toolchain. The result is small
# because the pipeline has one required dependency - see ADR 0003.

FROM python:3.11-slim-bookworm AS build

WORKDIR /build

# Dependency metadata first, so editing a rule does not invalidate the layer.
COPY pyproject.toml README.md LICENSE ./
COPY harness/ ./harness/
COPY rulekit/ ./rulekit/
COPY dashboard/ ./dashboard/

RUN python -m venv /opt/venv \
    && /opt/venv/bin/pip install --no-cache-dir --upgrade pip \
    && /opt/venv/bin/pip install --no-cache-dir '.[live]'


FROM python:3.11-slim-bookworm

LABEL org.opencontainers.image.title="detection-validation-pipeline" \
      org.opencontainers.image.description="Validate SIEM/EDR detections with a three-state outcome model" \
      org.opencontainers.image.licenses="Apache-2.0"

# curl is here for the compose healthcheck against a sidecar SIEM, nothing else.
RUN apt-get update \
    && apt-get install -y --no-install-recommends curl ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --system --create-home --home-dir /opt/dvp --shell /usr/sbin/nologin dvp

COPY --from=build /opt/venv /opt/venv

WORKDIR /opt/dvp

# Content. Bind-mounted over in development; baked in for a standalone image so
# `docker run dvp:local run` works with no host directory at all.
COPY --chown=dvp:dvp detections/ ./detections/
COPY --chown=dvp:dvp mapping/ ./mapping/
COPY --chown=dvp:dvp fixtures/ ./fixtures/
COPY --chown=dvp:dvp config/ ./config/
COPY --chown=dvp:dvp baseline/ ./baseline/
COPY --chown=dvp:dvp storage/ ./storage/

RUN mkdir -p /opt/dvp/.dvp /opt/dvp/docs/results \
    && chown -R dvp:dvp /opt/dvp

ENV PATH="/opt/venv/bin:$PATH" \
    DVP_ROOT=/opt/dvp \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    NO_COLOR=1

USER dvp

# Nothing here executes emulation: the container is not the host whose telemetry
# is being validated, so running commands inside it would prove nothing. The
# safety policy would refuse anyway.
ENTRYPOINT ["dvp"]
CMD ["run", "--profile", "quick-smoke"]
