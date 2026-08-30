FROM kalilinux/kali-rolling

ENV DEBIAN_FRONTEND=noninteractive
WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 python3-pip python3-venv git curl wget jq \
    dnsutils whois nmap ca-certificates \
    theharvester sherlock maigret whatweb amass \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip3 install --break-system-packages --no-cache-dir -r requirements.txt

COPY . .
RUN pip3 install --break-system-packages -e . || true

ENTRYPOINT ["python3", "-m", "argus.cli"]
CMD ["--help"]
