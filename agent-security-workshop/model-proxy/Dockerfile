FROM python:3.13-slim-bookworm
ENV PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1
WORKDIR /app
COPY proxy.py issue_client_token.py ./
# Volume mount points owned by the proxy user so new named volumes inherit that ownership.
RUN install -d -o 10003 -g 10003 -m 0700 /var/lib/model-proxy \
    && install -d -o 10003 -g 10003 -m 0755 /run/model-proxy-client
USER 10003:10003
CMD ["python", "/app/proxy.py"]
