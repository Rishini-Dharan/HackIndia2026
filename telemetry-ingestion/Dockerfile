FROM eclipse-temurin:17-jdk-alpine

WORKDIR /app

COPY TelemetryIngestion.java .

RUN javac TelemetryIngestion.java

# Default: stream to a local backend
CMD ["java", "TelemetryIngestion", "--emit", "http://backend:8000/ingest"]
