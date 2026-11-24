FROM python:3.13-slim-bookworm
ENV PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1
WORKDIR /app
COPY proxy.py ./
USER 10003:10003
CMD ["python", "/app/proxy.py"]
