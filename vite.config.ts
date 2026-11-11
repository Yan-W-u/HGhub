import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import tailwindcss from "@tailwindcss/vite";
import { readFileSync } from "node:fs";
import { hgMediaProxy } from "./vite.hgweb";

const host = process.env.TAURI_DEV_HOST;
const { version } = JSON.parse(
  readFileSync(new URL("./package.json", import.meta.url), "utf8"),
) as { version: string };

export default defineConfig({
  plugins: [react(), tailwindcss(), hgMediaProxy()],
  clearScreen: false,
  // 版本号只维护 package.json（CI 会按 tag 改写它），界面里的版本由这里注入，避免写死后漂移
  define: {
    __APP_VERSION__: JSON.stringify(version),
  },
  server: {
    port: 1420,
    strictPort: true,
    // 默认只听 ::1，Windows 上 localhost 有时解析到 127.0.0.1 会连不上；
    // 显式绑 127.0.0.1，浏览器与右侧栏都能稳定访问。
    host: host || "127.0.0.1",
    hmr: host ? { protocol: "ws", host, port: 1421 } : undefined,
    watch: {
      ignored: [
        "**/src-tauri/**",
        // 编辑器/工具写入时留下的临时目录会让 chokidar 抛 EBUSY 直接崩掉 dev server
        "**/.*.tmpdir/**",
        "**/*.tmp",
      ],
    },
    // Web 预览端口：/web.html 走纯浏览器构建（右侧栏实时调前端用）
    fs: { allow: [".."] },
  },
  envPrefix: ["VITE_", "TAURI_ENV_*"],
  build: {
    target: "es2021",
    minify: "esbuild",
    sourcemap: false,
  },
});
