FROM node:18-alpine
WORKDIR /app
COPY package*.json ./
RUN npm install
COPY server.js .
COPY liferay-private.pem .
EXPOSE 8089
CMD ["node", "server.js"]
