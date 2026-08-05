FROM python:3.12-slim
RUN apt-get update && apt-get install -y --no-install-recommends curl jq \
    && rm -rf /var/lib/apt/lists/* \
    && pip install --no-cache-dir requests
WORKDIR /work
COPY attack.py .
CMD ["sleep", "infinity"]