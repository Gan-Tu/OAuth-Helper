# syntax=docker/dockerfile:1

FROM node:18-alpine

# Set working directory
WORKDIR /app

# Install dependencies (only production)
ENV NODE_ENV=production
COPY package*.json ./
RUN npm ci --omit=dev

# Copy app source
COPY . .

# Non-root user for security (provided by base image)
USER node

# App port
ENV PORT=8080
EXPOSE 8080

# Start the server
CMD ["node", "server.js"]

