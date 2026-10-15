FROM python:3.13-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PHISHTRACE_HOST=0.0.0.0 \
    PHISHTRACE_PORT=5055 \
    PHISHTRACE_DEBUG=false \
    PHISHTRACE_STORE_SCAN_HISTORY=false

WORKDIR /app
COPY requirements.txt ./requirements.txt
RUN pip install --no-cache-dir -r requirements.txt
COPY backend ./backend
RUN mkdir -p /app/instance
EXPOSE 5055
CMD ["python", "-m", "backend.app"]
