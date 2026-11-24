import { defineConfig } from "wxt";

export default defineConfig({
  modules: ["@wxt-dev/module-react"],
  manifest: {
    name: "sns vault",
    description: "Standard Notes secrets vault — key/value pairs decrypted entirely in the browser.",
    // storage: chrome.storage.session for the master key + session (memory-only,
    // cleared when the browser exits). alarms: the one-shot auto-lock timer the
    // service worker arms — the only clock that survives worker sleep and
    // surface close. clipboardWrite: copy from the popup; also lets the
    // offscreen document blank the clipboard without a gesture.
    // offscreen: the hidden page that runs the 30 s clipboard-clear timer —
    // popups die on blur and the service worker sleeps, so neither can host it.
    // declarativeNetRequest: strips the Origin header on the extension's own
    // API calls — the hosted API 500s on the chrome-extension:// origin
    // scheme. Rules are installed dynamically at unlock (lib/origin.ts,
    // scoped via initiatorDomains to this extension only) rather than shipped
    // as a static ruleset, so the rule can name the runtime extension id.
    permissions: ["storage", "alarms", "clipboardWrite", "offscreen", "declarativeNetRequest"],
    // api.standardnotes.com is declared outright; a self-hosted API URL is
    // requested (user gesture, at first login) via optional permissions.
    host_permissions: ["https://api.standardnotes.com/*"],
    // http stays loopback-only: normalizeApiUrl (lib/session.ts) refuses
    // every plaintext host except localhost/127.0.0.1, and Chrome match
    // patterns are port-agnostic, so these two patterns cover exactly the
    // http origins the unlock flow can ever request — no wildcard http
    // breadth beyond what the code can ask for.
    optional_host_permissions: ["https://*/*", "http://localhost/*", "http://127.0.0.1/*"],
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
