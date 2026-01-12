FROM python:3.12-slim

# Install Go for tools
RUN apt-get update && apt-get install -y golang-go wget unzip && rm -rf /var/lib/apt/lists/*

# Install Subfinder
RUN go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest && \
    mv /root/go/bin/subfinder /usr/local/bin/

# Install Amass
RUN wget https://github.com/owasp-amass/amass/releases/download/v4.2.0/amass_linux.zip && \
    unzip amass_linux.zip && mv amass_linux_amd64/amass /usr/local/bin/ && \
    rm -rf amass_linux.zip amass_linux_amd64

# Copy code
WORKDIR /app
COPY . /app

# Python deps
RUN pip install --no-cache-dir httpx pyyaml

ENTRYPOINT ["python", "subfinder_amass_scanner.py"]
