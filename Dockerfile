FROM oven/bun:1-distroless
WORKDIR /app
COPY server.ts index.html ./
USER nonroot
EXPOSE 3000
CMD ["server.ts"]
