# Pure Python: no compiled components, no Open Bamboo Networking binary.
FROM python:3.12-slim
RUN apt-get update && apt-get install -y --no-install-recommends iproute2 ca-certificates \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY proxy/ proxy/
COPY tools/ tools/
ENV PROXY_CONFIG=/data/config.yaml PROXY_ADD_ADDRESSES=1 PYTHONUNBUFFERED=1
CMD ["python", "-m", "proxy.main"]
