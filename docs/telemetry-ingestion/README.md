# Telemetry Ingestion Documentation

This folder documents the `telemetry-ingestion/` service.

The ingestion service is a Java prototype that simulates high-frequency telemetry input. It is packaged with a Dockerfile so it can run as a standalone container and feed the backend during demos.

## Files

- `TelemetryIngestion.java` — Java source for the ingestion simulator
- `Dockerfile` — container build definition for the ingestion service

## Purpose

- Generate realistic telemetry event streams for the Q-Guardian backend.
- Emulate high-throughput packet and log ingestion.
- Drive proactive threat events when the backend simulator mode is enabled.

## Notes

- The ingestion service is optional for local frontend/backend development.
- It is included in `docker-compose.yml` to demonstrate a full pipeline with an external ingestion source.
