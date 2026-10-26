FROM python:3.12-slim

LABEL maintainer="AegisDNS Team <security@aegisdns.io>"
LABEL description="Next-Gen Recursive DNS Resolver, RFC 8484 DoH, and Threat Sinkhole"

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Install python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application files
COPY . .

# Expose standard DNS (UDP & TCP) and Web Dashboard / DoH
EXPOSE 53/udp
EXPOSE 53/tcp
EXPOSE 5380/tcp

ENV PYTHONPATH=/app
ENV AEGIS_DNS_HOST=0.0.0.0
ENV AEGIS_DNS_PORT=53
ENV AEGIS_HTTP_HOST=0.0.0.0
ENV AEGIS_HTTP_PORT=5380

CMD ["python", "-m", "aegisdns.main"]
