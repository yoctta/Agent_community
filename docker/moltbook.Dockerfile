# Builds the Moltbook API server from source.
# No official Docker image is published — this builds from
# https://github.com/moltbook/api directly.

FROM node:22-alpine

WORKDIR /app

RUN apk add --no-cache git && \
    git clone --depth 1 https://github.com/moltbook/api.git . && \
    npm install --production && \
    apk del git

EXPOSE 3000

# The API reads config from environment variables:
#   DATABASE_URL  — PostgreSQL connection string (required)
#   PORT          — HTTP port (default 3000)
#   JWT_SECRET    — secret for token signing
#   REDIS_URL     — optional, for rate limiting

CMD ["node", "src/index.js"]
