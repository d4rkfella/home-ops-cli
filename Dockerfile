FROM python:3.14-slim@sha256:486b8092bfb12997e10d4920897213a06563449c951c5506c2a2cfaf591c599f

RUN groupadd -g 65532 nonroot \
    && useradd -r -u 65532 -g 65532 -m nonroot

COPY dist/*.whl /tmp/
RUN pip install --no-cache-dir /tmp/*.whl \
    && rm -f /tmp/*.whl

USER nonroot

ENTRYPOINT ["home-ops-cli"]
