/**
 * 纯浏览器构建的入口（右侧栏实时预览 / 网页调试用）。
 *
 * 与 `main.tsx` 的唯一区别：挂载 App 之前先装上 `installWebBridge()`，
 * 把 Tauri 的 `invoke` 换成 WebCrypto + fetch 实现。
 */

import React from "react";
import ReactDOM from "react-dom/client";
import { installWebBridge } from "./web/bridge";
import "./index.css";

installWebBridge();

void (async () => {
  const { default: App } = await import("./App");
  const { AppProvider } = await import("./store");
  const { initPlaybackLog, installPlaybackPageEvents } = await import("./playbackDiagnostics");

  installPlaybackPageEvents();
  void initPlaybackLog();

  const report = (kind: string, msg: string) => console.warn(`[web:${kind}] ${msg}`);
  window.addEventListener("error", (e) => report("error", `${e.message} @ ${e.filename}:${e.lineno}`));
  window.addEventListener("unhandledrejection", (e) => {
    const reason = e.reason as { stack?: string; message?: string } | string;
    report("reject", String((reason as { stack?: string })?.stack ?? (reason as { message?: string })?.message ?? reason));
  });

  ReactDOM.createRoot(document.getElementById("root")!).render(
    <React.StrictMode>
      <AppProvider>
        <App />
      </AppProvider>
    </React.StrictMode>,
  );
})();
