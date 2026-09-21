FROM python:3.11-slim
WORKDIR /app
COPY scanner.py .
ENV PORT=8080
EXPOSE 8080
CMD ["python", "-u", "scanner.py"]
