# Build stage
FROM python:3.10-slim AS builder

WORKDIR /app

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Install python dependencies
COPY pyproject.toml .
# We install dependencies into a local directory to copy later
RUN pip install --user --upgrade pip
# We need to install the project in editable mode or just the deps. 
# For a production image, we usually install the package itself.
# But here we want the deps available for the runner.
COPY . .
RUN pip install --user .[dev]


# Runtime stage
FROM python:3.10-slim AS runtime

WORKDIR /app

# Create a non-root user
RUN useradd -m aegis_user
USER aegis_user

# Copy installed packages from builder
COPY --from=builder /root/.local /home/aegis_user/.local
COPY . .

# Update PATH
ENV PATH=/home/aegis_user/.local/bin:$PATH

# Expose port for the dashboard
EXPOSE 8501

# Default command (can be overridden to run dashboard)
ENTRYPOINT ["aegis"]
CMD ["--help"]
