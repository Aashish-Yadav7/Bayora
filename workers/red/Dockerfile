FROM python:3.11-slim
RUN groupadd -g 10001 bayorared && useradd -u 10001 -g bayorared -m -s /usr/sbin/nologin bayorared
WORKDIR /app
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
COPY workers/red/worker.py /app/worker.py
USER 10001:10001
CMD ["python3", "/app/worker.py"]
