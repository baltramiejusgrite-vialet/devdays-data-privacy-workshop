FROM python:3.13-slim-bookworm
ENV PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1
RUN pip install --no-cache-dir 'psycopg[binary]==3.2.10'
RUN apt-get update \
    && apt-get install -y --no-install-recommends nodejs npm ca-certificates \
    && npm install -g @openai/codex \
    && npm cache clean --force \
    && rm -rf /var/lib/apt/lists/*
RUN groupadd --gid 10001 agent \
    && useradd --uid 10001 --gid 10001 --create-home --home-dir /home/agent --shell /usr/sbin/nologin agent
ENV HOME=/home/agent
WORKDIR /workspace
COPY starter.py ./
USER 10001:10001
CMD ["python", "-c", "import time; time.sleep(2147483647)"]
