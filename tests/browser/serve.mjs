import { build } from "esbuild";
import { createServer } from "node:http";
import { readFile } from "node:fs/promises";
await build({ entryPoints: ["tests/browser/host.jsx"], bundle: true, outfile: ".build/browser/host.js", platform: "browser", format: "esm" });
const server = createServer(async (request, response) => {
  if (request.url === "/host.js") {
    response.setHeader("Content-Type", "text/javascript");
    response.end(await readFile(".build/browser/host.js"));
  } else {
    response.setHeader("Content-Type", "text/html");
    response.end(`<!doctype html><meta name="viewport" content="width=device-width,initial-scale=1">
      <style>
        * { box-sizing: border-box; } body { margin: 0; font: 14px system-ui, sans-serif; color: #18181b; background: #fff; }
        :root { --border: #e4e4e7; --muted: #f4f4f5; --muted-foreground: #71717a; --background: #fff; --popover: #fff; --primary: #18181b; }
        #root { height: 100dvh; display: flex; flex-direction: column; }
        #root > main { flex: 1; min-height: 0; overflow-y: auto; }
        #root > header, #root > button { flex-shrink: 0; }
        button, input, select { font: inherit; color: inherit; } button { cursor: pointer; } button:disabled { opacity: .5; cursor: default; }
        .host-button { display: inline-flex; align-items: center; justify-content: center; gap: 6px; min-height: 32px; border: 1px solid #e4e4e7; border-radius: 6px; padding: 6px 12px; background: #fff; }
        .host-button[data-variant="ghost"] { border-color: transparent; background: transparent; } .host-button:hover { background: #f4f4f5; }
        .host-input { max-width: 100%; border: 1px solid #e4e4e7; border-radius: 6px; padding: 4px 10px; }
        .host-topbar { display: flex; gap: 12px; align-items: center; justify-content: space-between; padding: 10px 24px; border-bottom: 1px solid #e4e4e7; }
        .host-topbar h1 { margin: 0; font-size: 14px; font-weight: 600; }
        .host-menu { z-index: 50; background: #fff; padding: 4px; border: 1px solid #e4e4e7; border-radius: 8px; box-shadow: 0 4px 12px #0002; }
        .host-menu [role="menuitem"] { display: flex; align-items: center; gap: 8px; padding: 8px; font-size: 12px; cursor: pointer; outline: none; border-radius: 4px; }
        .host-menu [data-highlighted] { background: #f4f4f5; }
        @media (pointer: coarse) { .host-menu [role="menuitem"] { min-height: 44px; } }
      </style><div id="root"></div><script type="module" src="/host.js"></script>`);
  }
});
server.listen(18843, "127.0.0.1", () => console.log("Security test host ready"));
process.on("SIGTERM", () => server.close());
