FROM python:3.11-slim

RUN groupadd -g 10000 bayora && \
    useradd -u 10000 -g bayora -m -s /usr/sbin/nologin bayora

WORKDIR /app
COPY backend/requirements.txt /app/backend/requirements.txt
RUN pip install --no-cache-dir -r /app/backend/requirements.txt

COPY backend /app/backend
RUN mkdir -p /app/data && chown -R 10000:10000 /app

USER 10000:10000
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    BAYORA_DB_PATH=/app/data/bayora.db \
    BAYORA_BACKEND_HOST=0.0.0.0 \
    BAYORA_BACKEND_PORT=8000

EXPOSE 8000
CMD ["python3", "-m", "backend.app.main"]
