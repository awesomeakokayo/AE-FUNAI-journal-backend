FROM python:3.11-slim-bookworm

# Completely block mise from installing Python
ENV MISE_PYTHON_VERSION="system"
ENV MISE_PYTHON_PREFER_SYSTEM=1
ENV MISE_PYTHON_COMPILE=0

WORKDIR /app

RUN apt-get update && apt-get install -y \
    gcc \
    libpq-dev \
    && rm -rf /var/lib/apt/lists/*

# Remove version pin files if present
RUN rm -f .mise.toml .tool-versions

COPY . .

# Delete python plugin so mise cannot attempt python install
RUN mise plugins uninstall python || true

RUN pip install --no-cache-dir -r requirements.txt

EXPOSE 8080

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8080"]
