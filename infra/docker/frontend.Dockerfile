FROM node:22-slim
RUN groupadd -g 10004 bayoraui && useradd -u 10004 -g bayoraui -m -s /usr/sbin/nologin bayoraui
WORKDIR /app
COPY package.json /app/package.json
RUN npm install --no-audit --no-fund
COPY . /app
RUN npm run build && chown -R 10004:10004 /app
USER 10004:10004
ENV NODE_ENV=production
EXPOSE 3000
# Gateway only: BAYORA_BACKEND_URL must point at the control plane (no Python spawned here).
CMD ["npm", "run", "start"]
