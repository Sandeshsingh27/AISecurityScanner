import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

const proxyTarget = process.env.VITE_DEV_API_PROXY_TARGET || "http://localhost:8080";

export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    proxy: {
      "/api": {
        target: proxyTarget,
        changeOrigin: true,
        configure: (proxy) => {
          proxy.on("proxyReq", (proxyReq, req) => {
            console.log(`[vite-proxy] -> ${req.method || "GET"} ${req.url || ""} => ${proxyTarget}${req.url || ""}`);
          });

          proxy.on("proxyRes", (proxyRes, req) => {
            console.log(`[vite-proxy] <- ${proxyRes.statusCode || 0} ${req.method || "GET"} ${req.url || ""}`);
          });

          proxy.on("error", (err, req) => {
            console.error(`[vite-proxy] xx ${req?.method || "GET"} ${req?.url || ""}: ${err.message}`);
          });
        }
      }
    }
  }
});

