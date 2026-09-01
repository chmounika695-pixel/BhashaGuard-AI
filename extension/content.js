// Runs on every page. Sends the page URL (plus current-page title as a
// small text signal) to the backend via the background worker, and only
// injects a visible warning banner if the result is HIGH RISK or
// PHISHING — not for SAFE/SUSPICIOUS, per the "don't be aggressive unless
// confidence is high" rule. This is a real, working prototype: it makes
// a genuine backend call and reacts to a genuine verdict, not a canned
// demo response.

(function () {
  if (window.top !== window.self) return; // skip iframes

  const pageUrl = window.location.href;
  const pageSignal = `${pageUrl} ${document.title}`;

  chrome.runtime.sendMessage({ type: "ANALYZE_PAGE", text: pageSignal }, (result) => {
    if (!result || result.error) return; // fail silently — never block browsing on a network error
    const verdict = result.verdict;
    if (!verdict) return;

    if (verdict.tier === "HIGH RISK" || verdict.tier === "PHISHING") {
      showBanner(verdict);
    }
  });

  function showBanner(verdict) {
    const banner = document.createElement("div");
    banner.id = "bhashaguard-warning-banner";
    banner.style.cssText = `
      position: fixed; top: 0; left: 0; right: 0; z-index: 2147483647;
      background: ${verdict.tier === "PHISHING" ? "#dc2626" : "#ea580c"};
      color: white; font-family: system-ui, sans-serif; font-size: 14px;
      padding: 12px 20px; display: flex; align-items: center;
      justify-content: space-between; box-shadow: 0 2px 8px rgba(0,0,0,0.3);
    `;

    const reasonsText = (verdict.reasons || []).slice(0, 3).join(" · ");

    banner.innerHTML = `
      <div style="display:flex; align-items:center; gap:12px;">
        <strong>🛡️ BhashaGuard — ${verdict.tier}</strong>
        <span>Risk: ${verdict.final_risk_score}/100</span>
        <span style="opacity:0.9;">${reasonsText}</span>
      </div>
      <div style="display:flex; gap:8px;">
        <button id="bg-leave-btn" style="background:white; color:#111; border:none; padding:6px 14px; border-radius:4px; cursor:pointer; font-weight:600;">Leave Website</button>
        <button id="bg-dismiss-btn" style="background:transparent; color:white; border:1px solid white; padding:6px 14px; border-radius:4px; cursor:pointer;">Dismiss</button>
      </div>
    `;

    document.documentElement.prepend(banner);

    document.getElementById("bg-leave-btn").addEventListener("click", () => {
      window.location.href = "about:blank";
    });
    document.getElementById("bg-dismiss-btn").addEventListener("click", () => {
      banner.remove();
    });
  }
})();
