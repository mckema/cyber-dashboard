# Runtime image for rebuild.py and bootstrap_wiki.py.
#
# The code is NOT copied in: docker-compose.yml bind-mounts the repo at /app, so
# edits apply on the next run without a rebuild. Rebuild only when
# requirements.txt changes.
#
# Proxy: HTTP_PROXY / HTTPS_PROXY / NO_PROXY are Docker's predefined build args.
# docker-compose.yml passes them from the host so `pip install` can reach PyPI
# behind the corporate proxy. They are deliberately not declared with ARG, which
# keeps them out of `docker history` and out of the final image.
FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app

COPY requirements.txt /tmp/requirements.txt
RUN pip install -r /tmp/requirements.txt \
 && useradd --uid 1000 --create-home --shell /usr/sbin/nologin app

USER app

CMD ["python", "rebuild.py"]
