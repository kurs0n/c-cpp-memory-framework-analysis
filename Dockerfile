# Ubuntu ARM64 environment for Memory Safety Benchmarking (with Valgrind & Clang)
FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive

# In Ubuntu, the 'clang' package provides both clang and clang++
RUN apt-get update && apt-get install -y \
    build-essential \
    clang \
    valgrind \
    python3 \
    python3-pip \
    python3-venv \
    git \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /workspace

# Set up Python virtual environment
COPY requirements.txt .
RUN python3 -m venv /opt/venv && \
    /opt/venv/bin/pip install --no-cache-dir -r requirements.txt

ENV PATH="/opt/venv/bin:$PATH"

ENTRYPOINT ["python3", "runner/main.py"]
CMD ["--help"]
