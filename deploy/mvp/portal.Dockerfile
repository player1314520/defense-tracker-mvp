ARG PYTHON_BASE_IMAGE
FROM ${PYTHON_BASE_IMAGE}

ARG GIT_SHA
ARG BACKEND_SOURCE_MANIFEST
ARG BACKEND_WIRE_COMPATIBILITY
ARG BACKEND_MIGRATION_POLICY
LABEL org.opencontainers.image.title="DefenseTracker V9 Portal" \
      org.opencontainers.image.revision="${GIT_SHA}" \
      org.opencontainers.image.source="local-git-release" \
      io.defensetracker.mvp.backend-source-manifest="${BACKEND_SOURCE_MANIFEST}" \
      io.defensetracker.mvp.backend-wire-compatibility="${BACKEND_WIRE_COMPATIBILITY}" \
      io.defensetracker.mvp.backend-migration-policy="${BACKEND_MIGRATION_POLICY}"

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PORT=8080

WORKDIR /app

COPY deploy/requirements.cloud.txt /tmp/requirements.txt
RUN python -m pip install --no-cache-dir --requirement /tmp/requirements.txt \
    && rm -f /tmp/requirements.txt \
    && groupadd --gid 10001 defense \
    && useradd --uid 10001 --gid defense --no-create-home --shell /usr/sbin/nologin defense \
    && install -d -o defense -g defense -m 0700 /data

COPY --chown=defense:defense v9_cloud.py /app/v9_cloud.py
COPY --chown=defense:defense v9 /app/v9
COPY --chown=defense:defense web/v9-portal /app/web/v9-portal
COPY --chown=root:root deploy/mvp/portal-entrypoint.sh /usr/local/bin/portal-entrypoint
COPY --chown=root:root build-metadata.json /app/build-metadata.json

RUN chmod 0555 /usr/local/bin/portal-entrypoint \
    && find /app -type d -exec chmod 0555 {} + \
    && find /app -type f -exec chmod 0444 {} +

USER 10001:10001
EXPOSE 8080
VOLUME ["/data"]

ENTRYPOINT ["/usr/local/bin/portal-entrypoint"]
