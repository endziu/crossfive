FROM oven/bun
WORKDIR /app
COPY server.ts index.html ./
EXPOSE 3000
CMD ["bun", "run", "server.ts"]
