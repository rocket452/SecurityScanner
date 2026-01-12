FROM python:3.12-slim

# Install system deps
RUN apt-get update && apt-get install -y \
    golang-go \
    wget \
    unzip \
    && rm -rf /var/lib/apt/lists/*

# Subfinder via Go
RUN go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest \
    && mv /root/go/bin/subfinder /usr/local/bin/

# Amass via Go (latest v4+)
RUN go install -v github.com/owasp-amass/amass/v4/...@master \
    && mv /root/go/bin/amass /usr/local/bin/

WORKDIR /app
COPY . /app

RUN pip install --no-cache-dir httpx pyyaml

# Health check
RUN subfinder --version && amass --version

ENTRYPOINT ["python", "subfinder_amass_scanner.py"]