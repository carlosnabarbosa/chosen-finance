FROM node:22-slim
WORKDIR /app
COPY package*.json ./
RUN npm ci --omit=dev && npm cache clean --force
COPY . .
ENV NODE_ENV=production HOST=0.0.0.0 PORT=4780 PASTA_ENTRADA=/entrada
USER node
EXPOSE 4780
CMD ["node", "src/server.js"]
