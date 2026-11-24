FROM python:3.13-slim-bookworm
ENV PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1 PIP_DISABLE_PIP_VERSION_CHECK=1 \
    TLDEXTRACT_CACHE=/opt/presidio/tld-cache
RUN pip install --no-cache-dir presidio-analyzer==2.2.364 spacy==3.8.11 \
    https://github.com/explosion/spacy-models/releases/download/en_core_web_sm-3.8.0/en_core_web_sm-3.8.0-py3-none-any.whl \
    && python -c "import tldextract; tldextract.extract('example.com')"
WORKDIR /pipeline
COPY recognizers.py server.py ./
COPY tests ./tests
RUN useradd --uid 10010 --no-create-home presidio
USER 10010
EXPOSE 8000
CMD ["python", "server.py"]
