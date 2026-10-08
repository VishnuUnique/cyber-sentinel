FROM python:3.11-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements first for layer caching
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy project files
COPY . .

# Install package in editable mode
RUN pip install --no-cache-dir -e .

# Create required directories
RUN mkdir -p database logs data/samples data/training models/anomaly models/classifier

# Expose API and dashboard ports
EXPOSE 8000 8501

# Default: run the CLI (override with docker run command)
CMD ["python", "-m", "cyber_sentinel.cli.main"]
