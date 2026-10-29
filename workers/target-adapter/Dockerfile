FROM python:3.11-slim
RUN groupadd -g 10003 bayoraadapter && useradd -u 10003 -g bayoraadapter -m -s /usr/sbin/nologin bayoraadapter
WORKDIR /app
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
ENV PYTHONPATH=/app
COPY backend /app/backend
COPY workers/target-adapter /app/workers/target-adapter
USER 10003:10003
CMD ["python3", "/app/workers/target-adapter/adapter_service.py"]
EXPOSE 8100
HEALTHCHECK CMD python3 -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8100/health', timeout=3)"
