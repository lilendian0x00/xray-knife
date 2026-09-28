import path from "path"
import tailwindcss from "@tailwindcss/vite"
import react from "@vitejs/plugin-react"
import { defineConfig } from "vite"

// Go's //go:embed skips files whose names start with "_" or ".", so no
// emitted asset may start with either (Rollup names some chunks "_foo").
const safe = (name: string) => name.replace(/^[_.]+/, "") || "chunk"

// https://vite.dev/config/
export default defineConfig({
  plugins: [react(), tailwindcss()],
  resolve: {
    alias: {
      "@": path.resolve(__dirname, "./src"),
    },
  },
  build: {
    target: "es2022",
    cssCodeSplit: true,
    rollupOptions: {
      output: {
        entryFileNames: "assets/[name]-[hash].js",
        chunkFileNames: (chunk) => `assets/${safe(chunk.name)}-[hash].js`,
        assetFileNames: (asset) => `assets/${safe(asset.names?.[0]?.replace(/\.[^.]+$/, "") ?? "asset")}-[hash][extname]`,
        manualChunks: (id) => {
          if (!id.includes("node_modules")) return undefined
          if (/[\\/]node_modules[\\/](react|react-dom|scheduler)[\\/]/.test(id)) return "react"
          if (id.includes("@radix-ui") || id.includes("@floating-ui")) return "radix"
          return undefined
        },
      },
    },
  },
  server: {
    proxy: {
      // The Go backend (xray-knife webui) serves /api and /events.
      // XK_BACKEND overrides the default, e.g. XK_BACKEND=http://127.0.0.1:9090 npm run dev
      "/api": { target: process.env.XK_BACKEND ?? "http://127.0.0.1:8080", changeOrigin: true },
      "/events": { target: process.env.XK_BACKEND ?? "http://127.0.0.1:8080", changeOrigin: true },
    },
  },
})
