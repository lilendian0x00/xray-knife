import path from "path"
import tailwindcss from "@tailwindcss/vite"
import react from "@vitejs/plugin-react"
import { defineConfig } from "vite"

// https://vite.dev/config/
export default defineConfig({
  plugins: [react(), tailwindcss()],
  resolve: {
    alias: {
      "@": path.resolve(__dirname, "./src"),
    },
  },
  server: {
    proxy: {
      // Any request starting with '/api' will be forwarded to the Go backend.
      // Example: A request to '/api/v1/proxy/start' from the frontend
      // will be sent to 'http://127.0.0.1:8080/api/v1/proxy/start'.
      '/api': {
        target: 'http://127.0.0.1:8080', // The address of your Go backend.
        changeOrigin: true, // Recommended for virtual hosts and proper proxying.
      },
      // Any WebSocket connection attempt to '/ws' will be forwarded.
      '/ws': {
        target: 'ws://127.0.0.1:8080', // The WebSocket endpoint of your Go backend.
        ws: true, // This enables WebSocket proxying.
      },
    },
  },
})