FROM node:20-bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends chromium fonts-liberation ca-certificates \
    && rm -rf /var/lib/apt/lists/*
ENV PUPPETEER_SKIP_DOWNLOAD=1 \
    CHROME_PATH=/usr/bin/chromium \
    HOST=0.0.0.0 \
    TRUST_PROXY=1 \
    COOKIE_SECURE=1 \
    WA_DATA_PATH=/data
WORKDIR /app
COPY package*.json ./
RUN npm install --omit=dev
COPY . .
VOLUME /data
EXPOSE 3000
CMD ["node", "server.js"]
