FROM python:3.12-slim

# Install system deps
RUN apt-get update && apt-get install -y \
    golang-go \
    wget \
    unzip \
    git \
    && rm -rf /var/lib/apt/lists/*

# Subfinder via Go
RUN go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest \
    && mv /root/go/bin/subfinder /usr/local/bin/

# Amass via Go (latest v4+)
RUN go install -v github.com/owasp-amass/amass/v4/...@master \
    && mv /root/go/bin/amass /usr/local/bin/

# Nuclei via Go
RUN go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest \
    && mv /root/go/bin/nuclei /usr/local/bin/ \
    && nuclei -update-templates -silent

# ffuf for directory fuzzing
RUN go install -v github.com/ffuf/ffuf/v2@latest \
    && mv /root/go/bin/ffuf /usr/local/bin/

# Create app directory and download raft-medium wordlist (~30k paths)
WORKDIR /app
RUN wget -q https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/raft-medium-directories.txt -O /app/wordlist.txt

COPY . /app

RUN pip install --no-cache-dir -r requirements.txt

# Health check
RUN subfinder --version && amass --version && nuclei -version && ffuf -V

ENTRYPOINT ["python", "scanner.py"]
