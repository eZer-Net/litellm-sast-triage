FROM python:3.12-slim
WORKDIR /app
COPY agent.py prompt.txt .env.example README.md LICENSE ./
COPY src/ ./src/
RUN mkdir -p /app/output
ENV PYTHONDONTWRITEBYTECODE=1
ENTRYPOINT ["python3", "agent.py"]
