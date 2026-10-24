FROM python:3.11-slim AS base

LABEL org.opencontainers.image.source="https://github.com/LazarusProtocol/services"
LABEL org.opencontainers.image.licenses="MIT"

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY common ./common


# Stage 1: Attestation Enclave & 2-of-3 FROST Threshold Signer
FROM base AS attestation-enclave

LABEL org.opencontainers.image.title="Lazarus Attestation Enclave"
LABEL org.opencontainers.image.description="Lazarus Protocol Isolated Ed25519 Enclave & 2-of-3 FROST Threshold Signer"

COPY attestation ./attestation

EXPOSE 8085

CMD ["python", "-m", "attestation.server"]

# Stage 2: Autonomous Keeper Node Daemon (default target)
FROM base AS keeper-daemon

LABEL org.opencontainers.image.title="Lazarus Keeper Daemon"
LABEL org.opencontainers.image.description="Lazarus Protocol Autonomous Keeper Node Daemon"

COPY keeper ./keeper

CMD ["python", "-m", "keeper.cli"]
