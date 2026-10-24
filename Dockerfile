FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1
RUN useradd --system --uid 10001 --no-create-home bayora
WORKDIR /app
COPY requirements.txt .
RUN pip install -r requirements.txt
COPY bayora_gateway bayora_gateway
COPY attacks attacks
USER 10001
EXPOSE 8000
HEALTHCHECK --interval=10s --timeout=3s --retries=5 CMD python -c "import urllib.request as u; u.urlopen('http://127.0.0.1:8000/health', timeout=2)"
CMD ["uvicorn", "--factory", "bayora_gateway.main:create_app", "--host", "0.0.0.0", "--port", "8000", "--no-server-header"]
