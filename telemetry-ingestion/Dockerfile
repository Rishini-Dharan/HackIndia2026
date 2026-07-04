FROM eclipse-temurin:17-jdk-alpine

WORKDIR /app

COPY TelemetryIngestion.java .

RUN javac TelemetryIngestion.java

# Default: simulate 1000 packets for demo
CMD ["java", "TelemetryIngestion", "--simulate", "1000"]
