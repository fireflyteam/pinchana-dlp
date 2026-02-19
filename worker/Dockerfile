FROM python:3.12-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    ffmpeg ca-certificates curl unzip && \
    rm -rf /var/lib/apt/lists/*

RUN curl -fsSL https://deno.land/install.sh | sh
ENV DENO_INSTALL="/root/.deno"
ENV PATH="$DENO_INSTALL/bin:$PATH"

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

RUN useradd -m -s /bin/bash workeruser

RUN mv /root/.deno /home/workeruser/.deno && \
    chown -R workeruser:workeruser /home/workeruser/.deno && \
    chown -R workeruser:workeruser /app

USER workeruser
ENV DENO_INSTALL="/home/workeruser/.deno"
ENV PATH="$DENO_INSTALL/bin:$PATH"

COPY main.py .

CMD ["python", "main.py"]
