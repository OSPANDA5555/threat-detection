FROM python:3.9-slim

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app.py .

ENV LOG_DIR=/var/log/soc

EXPOSE 9200

HEALTHCHECK --interval=20s --timeout=5s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:9200/health || exit 1

CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "9200"]
