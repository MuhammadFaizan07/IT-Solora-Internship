FROM python:3.12-slim

LABEL maintainer="Muhammad Faizan"
LABEL description="ReconForge - Modular Reconnaissance Tool (ITsolera Offensive Security Internship Task 1)"

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY recontool.py .
COPY modules/ ./modules/

RUN mkdir -p /app/reports
VOLUME ["/app/reports"]

ENTRYPOINT ["python", "recontool.py"]
CMD ["--help"]
