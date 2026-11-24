FROM python:3.13-slim-bookworm
ENV PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1
RUN pip install --no-cache-dir 'psycopg[binary]==3.2.10'
WORKDIR /app
COPY app.py ./
USER 10002:10002
CMD ["python", "/app/app.py"]
