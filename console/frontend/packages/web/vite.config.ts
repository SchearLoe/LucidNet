import react from "@vitejs/plugin-react";
import { defineConfig } from "vite";

// lucid-gateway 本地地址（生产经反代同源）。
const GATEWAY = process.env.LUCID_GATEWAY_ORIGIN ?? "http://127.0.0.1:8080";

export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    proxy: {
      "/api": { target: GATEWAY, changeOrigin: true, ws: true },
    },
  },
  build: { sourcemap: false },
});
