# Thin local API gateway proxy (Cognito-validating). See server.js.
FROM node:20-alpine
RUN addgroup --system appgroup && adduser --system --ingroup appgroup appuser
WORKDIR /app
COPY package.json ./
RUN npm install --omit=dev
COPY server.js ./
RUN chown -R appuser:appgroup /app
USER appuser
ENV PORT=3000
EXPOSE 3000
HEALTHCHECK --interval=15s --timeout=4s --retries=10 \
  CMD wget -q --spider http://localhost:3000/health || exit 1
CMD ["node", "server.js"]
