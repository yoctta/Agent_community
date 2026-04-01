FROM python:3.12-slim

WORKDIR /app

# Dependencies.
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Application code.
COPY aces/ aces/
COPY config/ config/
COPY run_experiment.py .
COPY docker/generate_agent_configs.py docker/

ENTRYPOINT ["python", "run_experiment.py"]
CMD ["single", "--seed", "42"]
