FROM python:3.9-slim

WORKDIR /app

# Create unprivileged application user
RUN groupadd -g 10001 appgroup && \
    useradd -u 10001 -g appgroup -s /sbin/nologin -d /app appuser

RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app.py .

ENV LOG_DIR=/var/log/soc
RUN mkdir -p /var/log/soc && chown -R appuser:appgroup /var/log/soc /app

USER appuser:appgroup

EXPOSE 9200

HEALTHCHECK --interval=20s --timeout=5s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:9200/health || exit 1

CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "9200"]
