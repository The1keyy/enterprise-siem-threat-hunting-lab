FROM node:24-bookworm-slim AS build

WORKDIR /src/frontend

COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci

COPY frontend/ ./
COPY fixtures/ /src/fixtures

ARG VITE_DATA_MODE=live
ARG VITE_API_URL=http://localhost:8000
ENV VITE_DATA_MODE=$VITE_DATA_MODE
ENV VITE_API_URL=$VITE_API_URL

RUN npm run build

FROM nginx:1.27-alpine

COPY frontend/nginx.conf /etc/nginx/conf.d/default.conf
COPY --from=build /src/frontend/dist /usr/share/nginx/html
