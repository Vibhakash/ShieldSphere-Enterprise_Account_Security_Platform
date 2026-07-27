FROM node:22-alpine AS build

WORKDIR /app

COPY package.json package-lock.json ./
RUN npm ci --no-audit --no-fund

COPY . .

ARG VITE_API_ORIGIN
ARG VITE_API_BASE_URL
ARG VITE_SIMULATOR_WS_URL
ENV VITE_API_ORIGIN=$VITE_API_ORIGIN \
    VITE_API_BASE_URL=$VITE_API_BASE_URL \
    VITE_SIMULATOR_WS_URL=$VITE_SIMULATOR_WS_URL

RUN npm run build

FROM nginx:1.27-alpine

COPY nginx.conf /etc/nginx/conf.d/default.conf
COPY --from=build /app/dist /usr/share/nginx/html

EXPOSE 80

HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
    CMD wget -q -O /dev/null http://127.0.0.1/healthz || exit 1
