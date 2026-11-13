import { defineConfig } from "wxt";

export default defineConfig({
  modules: ["@wxt-dev/module-react"],
  manifest: {
    name: "sns vault",
    description: "Standard Notes secrets vault — key/value pairs decrypted entirely in the browser.",
    // storage: chrome.storage.session for the master key + session (memory-only,
    // cleared when the browser exits). clipboardWrite: copy from the popup;
    // also lets the offscreen document blank the clipboard without a gesture.
    // offscreen: the hidden page that runs the 30 s clipboard-clear timer —
    // popups die on blur and the service worker sleeps, so neither can host it.
    // declarativeNetRequest: strips the Origin header on API calls — the
    // hosted API 500s on the chrome-extension:// origin scheme (see
    // lib/origin.ts).
    permissions: ["storage", "clipboardWrite", "offscreen", "declarativeNetRequest"],
    declarative_net_request: {
      rule_resources: [{ id: "sns_origin_rules", enabled: true, path: "rules.json" }],
    },
    // api.standardnotes.com is declared outright; a self-hosted API URL is
    // requested (user gesture, at first login) via optional permissions.
    host_permissions: ["https://api.standardnotes.com/*"],
    optional_host_permissions: ["http://*/*", "https://*/*"],
    icons: {
      "16": "icons/16.png",
      "32": "icons/32.png",
      "48": "icons/48.png",
      "128": "icons/128.png",
    },
    action: {
      default_icon: {
        "16": "icons/16.png",
        "32": "icons/32.png",
      },
    },
    // libsodium is WASM — Argon2id cannot run under the default MV3 CSP.
    content_security_policy: {
      extension_pages: "script-src 'self' 'wasm-unsafe-eval'; object-src 'self'",
    },
  },
});
