FROM --platform=linux/arm/v7 python:3.13.17-alpine3.23
COPY app /app
ENV DATA_DIR=/data LISTEN_HOST=0.0.0.0 LISTEN_PORT=8443
CMD ["python3", "/app/app.py"]
