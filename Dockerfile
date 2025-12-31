FROM python:3.13-slim@sha256:56ab277ddf459858f94052252565945c34617c841818faf8f34f6896de06cffe

RUN groupadd -g 65532 nonroot \
    && useradd -r -u 65532 -g 65532 -m nonroot

RUN pip install --no-cache-dir home-ops-cli==0.3.5

USER nonroot

ENTRYPOINT ["home-ops-cli"]
