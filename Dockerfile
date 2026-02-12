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

# Install Arjun for parameter discovery
RUN pip install arjun

# Playwright browser deps (Debian) + Chromium install for DOM XSS verification.
# We avoid `--with-deps` because it may try Ubuntu package names depending on base image.
RUN apt-get update && apt-get install -y \
    ca-certificates \
    fonts-liberation \
    fonts-unifont \
    libasound2 \
    libatk-bridge2.0-0 \
    libatk1.0-0 \
    libcairo2 \
    libcups2 \
    libdbus-1-3 \
    libdrm2 \
    libexpat1 \
    libfontconfig1 \
    libgbm1 \
    libglib2.0-0 \
    libgtk-3-0 \
    libnspr4 \
    libnss3 \
    libpango-1.0-0 \
    libpangocairo-1.0-0 \
    libstdc++6 \
    libx11-6 \
    libx11-xcb1 \
    libxcb1 \
    libxcomposite1 \
    libxdamage1 \
    libxext6 \
    libxfixes3 \
    libxrandr2 \
    libxrender1 \
    libxshmfence1 \
    libxss1 \
    libxtst6 \
    xdg-utils \
    && rm -rf /var/lib/apt/lists/*

RUN python -m playwright install chromium

# Create /reports directory for output files
RUN mkdir -p /reports

# Declare volume for reports
VOLUME ["/reports"]

# Health check (arjun doesn't support --version flag)
RUN subfinder --version && amass --version && nuclei -version && ffuf -V && arjun -h > /dev/null

ENTRYPOINT ["python", "scanner.py"]
