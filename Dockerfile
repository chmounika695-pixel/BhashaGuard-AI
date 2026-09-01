FROM python:3.12-slim

WORKDIR /app

# ZBar is required by pyzbar for QR decoding on Linux.
RUN apt-get update \
    && apt-get install -y --no-install-recommends libzbar0 \
    && rm -rf /var/lib/apt/lists/*

COPY backend/requirements.txt ./backend/requirements.txt
RUN pip install --no-cache-dir -r backend/requirements.txt

COPY backend/ ./backend/
COPY frontend/ ./frontend/
COPY extension/ ./extension/

WORKDIR /app/backend

ENV PYTHONUNBUFFERED=1

# Works on Render (PORT=10000) and Cloud Run (PORT=8080).
CMD ["sh", "-c", "uvicorn app:app --host 0.0.0.0 --port ${PORT:-8080}"]
