FROM python:3.14-slim@sha256:9b81fe9acff79e61affb44aaf3b6ff234392e8ca477cb86c9f7fd11732ce9b6a

ARG CLI_VERSION

RUN groupadd -g 65532 nonroot \
    && useradd -r -u 65532 -g 65532 -m nonroot

RUN pip install --no-cache-dir home-ops-cli==${CLI_VERSION}

COPY dist/*.whl /tmp/
RUN pip install --no-cache-dir /tmp/*.whl \
    && rm -f /tmp/*.whl

USER nonroot

ENTRYPOINT ["home-ops-cli"]
