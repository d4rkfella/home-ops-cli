FROM python:3.13-slim@sha256:51e1a0a317fdb6e170dc791bbeae63fac5272c82f43958ef74a34e170c6f8b18

ARG CLI_VERSION

RUN groupadd -g 65532 nonroot \
    && useradd -r -u 65532 -g 65532 -m nonroot

RUN pip install --no-cache-dir home-ops-cli==${CLI_VERSION}

USER nonroot

ENTRYPOINT ["home-ops-cli"]
