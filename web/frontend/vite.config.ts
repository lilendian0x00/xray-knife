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
      // Proxy API requests to the Go backend
      '/api': {
        target: 'http://127.0.0.1:8080', // Default address of the Go backend
        changeOrigin: true, // Recommended for virtual hosts
      },
      // Proxy WebSocket connections for live logs
      '/ws': {
        target: 'ws://127.0.0.1:8080', // WebSocket endpoint
        ws: true, // Enable WebSocket proxying
      },
    },
  },
})