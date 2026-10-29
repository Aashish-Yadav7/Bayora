FROM python:3.11-slim
RUN groupadd -g 10002 bayorablue && useradd -u 10002 -g bayorablue -m -s /usr/sbin/nologin bayorablue
WORKDIR /app
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
COPY workers/blue/worker.py /app/worker.py
USER 10002:10002
CMD ["python3", "/app/worker.py"]
