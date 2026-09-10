FROM python:3.12-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential libpq-dev curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /srv/app

# Copy the full source BEFORE installing, since `pip install -e .` needs
# the actual `app` package on disk to resolve the editable install --
# installing from only pyproject.toml (before COPY . .) fails with
# "package directory 'app' does not exist".
COPY . .
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -e .

# Run as a non-root user (Celery/uvicorn otherwise emit a
# "running with superuser privileges" warning and it's an unnecessary
# privilege escalation risk in production).
RUN groupadd --gid 1000 sentinel && \
    useradd --uid 1000 --gid sentinel --shell /bin/bash --create-home sentinel && \
    mkdir -p /data/evidence && \
    chown -R sentinel:sentinel /srv/app /data/evidence

USER sentinel

EXPOSE 8000

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]