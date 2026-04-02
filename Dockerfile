FROM python:3.12-slim

# Install Node.js (required for OpenClaw CLI).
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl ca-certificates && \
    curl -fsSL https://deb.nodesource.com/setup_22.x | bash - && \
    apt-get install -y nodejs && \
    apt-get clean && rm -rf /var/lib/apt/lists/*

# Install OpenClaw globally so `openclaw agent` works as a subprocess.
RUN npm install -g openclaw

WORKDIR /app

# Python dependencies.
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Application code.
COPY aces/ aces/
COPY config/ config/
COPY run_experiment.py .
COPY docker/generate_agent_configs.py docker/

# Regenerate agent workspaces with Docker-correct paths.
# The host-generated configs have host absolute paths in openclaw.json;
# --runtime-prefix rewrites them to the container mount point.
RUN python docker/generate_agent_configs.py \
    --runtime-prefix /app/docker/agents

ENTRYPOINT ["python", "run_experiment.py"]
CMD ["single", "--backend", "openclaw", "--seed", "42"]
