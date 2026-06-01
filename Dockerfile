FROM python:3.12-slim
WORKDIR /app
RUN pip install --no-cache-dir starlette "uvicorn[standard]"
COPY server.py .
USER 1001
EXPOSE 8080
CMD ["python", "server.py"]
