FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY tplink_scraper.py .

# Default: run as Prometheus exporter
ENTRYPOINT ["python3", "tplink_scraper.py", "--serve"]
