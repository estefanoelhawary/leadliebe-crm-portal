FROM node:22-alpine

WORKDIR /app

ENV NODE_ENV=production
ENV PORT=80

COPY dist ./dist
COPY runtime ./runtime

EXPOSE 80

CMD ["node", "runtime/server.mjs"]
