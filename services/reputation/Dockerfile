FROM python:3.13-slim
WORKDIR /app
COPY . .
ENV PYTHONPATH=/app
EXPOSE 8081
USER 65532:65532
ENTRYPOINT ["python", "-m", "berry_reputation"]
