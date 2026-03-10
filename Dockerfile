# ===========================================================================
# CMMC Cloud Compliance Scanner — Multi-stage Docker Build
#
# Stage 1: Install Python dependencies
# Stage 2: Production image with backend + frontend
#
# Build:  docker build -t cmmc-scanner:latest .
# Run:    docker run -p 8000:8000 --env-file .env cmmc-scanner:latest
# ===========================================================================

# ---------------------------------------------------------------------------
# Stage 1: Builder — install Python dependencies into a virtual environment
# ---------------------------------------------------------------------------
FROM python:3.12-slim AS builder

WORKDIR /build

# Install build dependencies needed for some Python packages (e.g., bcrypt)
RUN apt-get update && \
    apt-get install -y --no-install-recommends gcc libpq-dev && \
    rm -rf /var/lib/apt/lists/*

# Copy only requirements first for Docker layer caching
COPY backend/requirements.txt ./requirements.txt

# Create virtual environment and install dependencies
RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# ---------------------------------------------------------------------------
# Stage 2: Production — lean runtime image
# ---------------------------------------------------------------------------
FROM python:3.12-slim AS production

# Install only runtime dependencies
RUN apt-get update && \
    apt-get install -y --no-install-recommends libpq5 curl && \
    rm -rf /var/lib/apt/lists/*

# Create non-root user for security
RUN groupadd --gid 1000 appuser && \
    useradd --uid 1000 --gid appuser --shell /bin/bash --create-home appuser

# Copy virtual environment from builder stage
COPY --from=builder /opt/venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Set working directory
WORKDIR /app

# Copy backend application code
COPY backend/ ./backend/

# Copy check definitions and config files
COPY config/ ./config/

# Copy frontend static files
COPY frontend/ ./frontend/

# Set PYTHONPATH so imports work correctly
ENV PYTHONPATH="/app/backend"

# Prevent Python from writing .pyc files and enable unbuffered output
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# Change ownership to non-root user
RUN chown -R appuser:appuser /app

# Switch to non-root user
USER appuser

# Expose the application port
EXPOSE 8000

# Health check — verify the API responds
HEALTHCHECK --interval=30s --timeout=5s --start-period=30s --retries=3 \
    CMD curl --fail http://localhost:8000/health || exit 1

# Start the FastAPI application with uvicorn
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "2", "--proxy-headers", "--forwarded-allow-ips", "*"]
