# Argus - WordPress Security Scanner
# Multi-stage build for minimal image size

# Build stage
FROM python:3.11-slim as builder

WORKDIR /build

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    g++ \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements and install Python dependencies
COPY requirements.txt .
RUN pip install --user --no-cache-dir -r requirements.txt

# Runtime stage
FROM python:3.11-slim

# Add metadata
LABEL maintainer="Rodney Dhavid Jimenez Chacin (rodhnin)"
LABEL description="Argus - WordPress Security Scanner & Evidence Collector"
LABEL version="0.1.0"

# Create non-root user
RUN useradd -m -u 1000 argus

# Install runtime dependencies only
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Copy Python packages from builder
COPY --from=builder /root/.local /home/argus/.local

# Set up working directory
WORKDIR /app

# Copy application code
COPY argus/ ./argus/
COPY config/ ./config/
COPY schema/ ./schema/
COPY templates/ ./templates/
COPY db/ ./db/
COPY assets/ ./assets/

# Create necessary directories
RUN mkdir -p /reports /data && \
    chown -R argus:argus /reports /data /app

# Switch to non-root user
USER argus

# Update PATH to include local pip installations
ENV PATH="/home/argus/.local/bin:${PATH}"
ENV PYTHONPATH="/app:${PYTHONPATH}"

# Create volumes for persistent data
VOLUME ["/reports", "/data"]

# Default command: show help
ENTRYPOINT ["python", "-m", "argus"]
CMD ["--help"]

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python -c "import argus; print(argus.__version__)" || exit 1

# Usage examples:
# Build: docker build -t argus:latest -f docker/Dockerfile .
# Run: docker run --rm -v $(pwd)/reports:/reports argus --target https://example.com
# Interactive: docker run --rm -it -v $(pwd)/reports:/reports argus bash