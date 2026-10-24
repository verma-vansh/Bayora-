FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1
RUN useradd --system --uid 10003 --no-create-home worker && pip install httpx==0.28.1
WORKDIR /app
COPY agent.py .
USER 10003
ENTRYPOINT ["python", "agent.py"]
