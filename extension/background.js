// Background service worker. Content scripts run inside the page's own
// context and can hit page CSP restrictions on cross-origin fetch; the
// background worker doesn't, so all backend calls are routed through here.
// No API key lives in this extension — the backend endpoint itself does
// not require one (see backend/app.py); if a future version needs auth,
// it must be added server-side (e.g. a backend-issued session token),
// never a raw provider key shipped inside the extension bundle.

const DEFAULT_BACKEND_URL = "http://localhost:8000";

async function getBackendUrl() {
  const stored = await chrome.storage.sync.get("backend_url");
  return stored.backend_url || DEFAULT_BACKEND_URL;
}

async function analyze(text) {
  const backendUrl = await getBackendUrl();
  try {
    const res = await fetch(`${backendUrl}/api/scan`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ text, warning_language: "en" }),
    });
    if (!res.ok) throw new Error(`Backend returned ${res.status}`);
    return await res.json();
  } catch (err) {
    return { error: true, message: err.message };
  }
}

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.type === "ANALYZE_PAGE") {
    analyze(message.text).then(sendResponse);
    return true; // keep the message channel open for the async response
  }
});
