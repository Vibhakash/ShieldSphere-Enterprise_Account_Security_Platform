FROM python:3.12-slim

WORKDIR /attacker
RUN apt-get update && apt-get install -y --no-install-recommends nmap && rm -rf /var/lib/apt/lists/*
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY runner.py .

RUN useradd --create-home attacker
USER attacker
ENTRYPOINT ["python", "runner.py"]
