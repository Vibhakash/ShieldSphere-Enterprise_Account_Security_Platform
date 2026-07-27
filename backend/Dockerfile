FROM python:3.12-slim-bookworm

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1

RUN apt-get update \
    && apt-get install --no-install-recommends -y nmap libpcap0.8 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt ./
RUN python -m pip install --upgrade pip \
    && sed '/^# Development and release verification/,$d' requirements.txt > /tmp/requirements-runtime.txt \
    && python -m pip install -r /tmp/requirements-runtime.txt \
    && rm -f /tmp/requirements-runtime.txt

COPY alembic.ini main.py docker-entrypoint.sh ./
COPY alembic ./alembic
COPY app ./app
COPY data ./data
COPY sandbox ./sandbox

RUN addgroup --system --gid 10001 shieldsphere \
    && adduser --system --uid 10001 --ingroup shieldsphere --home /app shieldsphere \
    && chown -R shieldsphere:shieldsphere /app \
    && chmod +x /app/docker-entrypoint.sh

USER shieldsphere

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=30s --retries=3 \
    CMD python -c "import os, urllib.request; urllib.request.urlopen('http://127.0.0.1:' + os.environ.get('PORT', '8000') + '/health', timeout=4)"

ENTRYPOINT ["/app/docker-entrypoint.sh"]
