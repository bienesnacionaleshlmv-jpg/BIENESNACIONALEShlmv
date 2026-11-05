FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 HLMV_CLOUD_MODE=1 HLMV_DATOS=/data
WORKDIR /srv/nexus
RUN pip install --no-cache-dir "pymupdf>=1.24,<2"
COPY index.html ./index.html
COPY app/ ./app/
COPY vendor/ ./vendor/
EXPOSE 8895
CMD ["python", "app/server.py", "--lan", "--no-browser", "--port", "8895"]
