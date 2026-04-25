# ─────────────────────────────────────────────────────────────
#  Demon-Pot SSH Honeypot — Production Dockerfile
#  Stage 1: Build dependencies
#  Stage 2: Minimal Alpine runtime image
# ─────────────────────────────────────────────────────────────

# ── Stage 1: Builder ─────────────────────────────────────────
FROM python:3.11-alpine AS builder

WORKDIR /build

# Install build tools needed for cryptography (paramiko dep)
RUN apk add --no-cache \
    gcc \
    musl-dev \
    libffi-dev \
    openssl-dev \
    cargo \
    make

# Copy and install dependencies into a prefix directory
COPY requirements.txt .
RUN pip install --prefix=/install --no-cache-dir -r requirements.txt


# ── Stage 2: Minimal Runtime ─────────────────────────────────
FROM python:3.11-alpine AS runtime

LABEL maintainer="your@email.com"
LABEL description="Demon-Pot — Advanced SSH Honeypot"
LABEL version="2.0.0"

# Install only runtime libraries (no build tools)
RUN apk add --no-cache libffi openssl

# Create non-root user inside the container
RUN addgroup -S honeypot && adduser -S -G honeypot -h /opt/ssh-honeypot honeypot

# Copy installed Python packages from builder
COPY --from=builder /install /usr/local

# Set up directory structure
RUN mkdir -p /opt/ssh-honeypot/logs && \
    chown -R honeypot:honeypot /opt/ssh-honeypot

WORKDIR /opt/ssh-honeypot

# Copy honeypot source
COPY --chown=honeypot:honeypot honeypot.py .

USER honeypot

# Expose honeypot port (override via env if needed)
EXPOSE 2222

# Health check — verify the port is open
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD nc -z localhost 2222 || exit 1

# Runtime environment defaults (override in docker-compose or -e flags)
ENV HONEYPOT_PORT=2222 \
    HONEYPOT_BIND=0.0.0.0 \
    HONEYPOT_BASE_DIR=/opt/ssh-honeypot \
    HONEYPOT_RATE=10 \
    HONEYPOT_WINDOW=60 \
    HONEYPOT_IDLE=120

ENTRYPOINT ["python3", "honeypot.py"]
