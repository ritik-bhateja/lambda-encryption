# Sandbox image for the Empower Care payload encryption example.
# It runs the real Lambda handlers behind a local API Gateway emulator,
# with Secrets Manager, DynamoDB, ANZ and Hasura all mocked in process.
FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    AWS_DEFAULT_REGION=ap-south-1 \
    AWS_ACCESS_KEY_ID=test \
    AWS_SECRET_ACCESS_KEY=test \
    PORT=8080

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY layer/ layer/
COPY lambdas/ lambdas/
COPY client/ client/
COPY local_gateway.py .

EXPOSE 8080

HEALTHCHECK --interval=10s --timeout=3s --start-period=5s --retries=5 \
  CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://localhost:8080/health').status==200 else 1)"

CMD ["python", "local_gateway.py"]
