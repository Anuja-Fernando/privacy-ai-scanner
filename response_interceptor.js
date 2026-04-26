/**
 * response_interceptor.js
 * ─────────────────────────────────────────────────────────────
 * Content script that intercepts LLM responses from ChatGPT / Claude.ai
 * BEFORE they are fully rendered to the user.
 *
 * How it works:
 *   1. MutationObserver watches for new response nodes appearing in DOM
 *   2. When a complete response is detected, it's captured
 *   3. Sent to background.js for HE + DP analysis via FastAPI backend
 *   4. If reconstruction risk is high → response is blurred + warning shown
 *   5. User can choose to view anyway or block
 *
 * Supports: ChatGPT (chat.openai.com) and Claude.ai
 */

// ── Site-specific DOM selectors ───────────────────────────────
const SITE_CONFIG = {
  "chat.openai.com": {
    responseSelector: '[data-message-author-role="assistant"] .markdown',
    streamingIndicator: ".result-streaming",
    inputSelector: "#prompt-textarea",
  },
  "claude.ai": {
    responseSelector: '[data-is-streaming="false"] .font-claude-message',
    streamingIndicator: '[data-is-streaming="true"]',
    inputSelector: 'div[contenteditable="true"]',
  },
  // Extend here for Gemini, Copilot etc.
  "gemini.google.com": {
    responseSelector: "message-content .markdown",
    streamingIndicator: ".loading-indicator",
    inputSelector: "rich-textarea",
  },
};

// ── State ─────────────────────────────────────────────────────
let originalPromptEmbedding = null; // set when user submits prompt
let processedResponses      = new WeakSet(); // avoid double-processing
let siteConfig              = null;

// ── Init ──────────────────────────────────────────────────────
function init() {
  const host = window.location.hostname;
  siteConfig = Object.entries(SITE_CONFIG).find(([domain]) =>
    host.includes(domain)
  )?.[1];

  if (!siteConfig) {
    console.log("[PrivacyScanner] Site not supported for response interception");
    return;
  }

  console.log(`[PrivacyScanner] Response interceptor active on ${host}`);
  watchForResponses();
  captureOriginalPrompt();
}

// ── Capture the original prompt when user submits ─────────────
function captureOriginalPrompt() {
  // Listen for the prompt being submitted so we can store its embedding
  // for later similarity comparison against the response
  document.addEventListener("keydown", async (e) => {
    if (e.key === "Enter" && !e.shiftKey) {
      const inputEl = document.querySelector(siteConfig.inputSelector);
      if (!inputEl) return;

      const promptText = inputEl.innerText || inputEl.value || "";
      if (!promptText.trim()) return;

      // Ask background script to compute + store embedding of ORIGINAL prompt
      // (before anonymization — this is what we'll compare against later)
      chrome.runtime.sendMessage({
        action:  "STORE_PROMPT_EMBEDDING",
        payload: { text: promptText },
      });

      console.log("[PrivacyScanner] Original prompt captured for similarity check");
    }
  });
}

// ── Watch DOM for completed LLM responses ─────────────────────
function watchForResponses() {
  const observer = new MutationObserver((mutations) => {
    for (const mutation of mutations) {
      for (const node of mutation.addedNodes) {
        if (node.nodeType !== Node.ELEMENT_NODE) continue;

        // Check if streaming is complete (no streaming indicator present)
        const isStreaming = document.querySelector(siteConfig.streamingIndicator);
        if (isStreaming) continue; // wait for full response

        // Find response elements
        const responseEls = node.querySelectorAll
          ? node.querySelectorAll(siteConfig.responseSelector)
          : [];

        // Also check if the node itself is a response
        const allResponses = [
          ...(node.matches?.(siteConfig.responseSelector) ? [node] : []),
          ...Array.from(responseEls),
        ];

        for (const el of allResponses) {
          if (processedResponses.has(el)) continue;
          processedResponses.add(el);

          const responseText = el.innerText?.trim();
          if (!responseText || responseText.length < 20) continue;

          console.log("[PrivacyScanner] Response detected, analyzing...");
          analyzeResponse(el, responseText);
        }
      }
    }
  });

  observer.observe(document.body, { childList: true, subtree: true });
}

// ── Analyze response via FastAPI backend ──────────────────────
async function analyzeResponse(responseEl, responseText) {
  // Blur the response immediately while analysis runs
  applyBlur(responseEl, "Analyzing response for privacy risks...");

  try {
    // Get auth token
    const authRes  = await fetch("http://localhost:8000/auth/token", {
      method:  "POST",
      headers: { "Content-Type": "application/json" },
    });
    const { access_token } = await authRes.json();

    // ← FIX: get session_id for DP similarity check
    const { privacySessionId } = await chrome.storage.session.get('privacySessionId');

    // Send response text to our new /analyze/response endpoint
    const res = await fetch("http://localhost:8000/analyze/response", {
      method:  "POST",
      headers: {
        "Content-Type":  "application/json",
        "Authorization": `Bearer ${access_token}`,
      },
      // ← FIX: include session_id for DP similarity check
      body: JSON.stringify({ 
          response_text: responseText,
          session_id:    privacySessionId || "",
      }),
    });

    const result = await res.json();
    console.log("[PrivacyScanner] Response analysis:", result);

    handleAnalysisResult(responseEl, responseText, result);

    const dpPayload = {
      action:                 result.action,
      dp_reconstruction_risk: result.dp_reconstruction_risk,
      noised_similarity:      result.noised_similarity || result.dp_noised_similarity, // ← FIX: handle both key names
      echoed_entities:        result.echoed_entities,
      budget:                 result.budget,
    };

    // ← FIX: store so popup can read it even if closed
    chrome.storage.local.set({ lastDPResult: dpPayload });

    // Also try live message if popup is open
    chrome.runtime.sendMessage({
      action:  "DP_RESULT",
      payload: dpPayload,
    }).catch(() => {}); // popup might be closed

  } catch (err) {
    console.error("[PrivacyScanner] Analysis failed:", err);
    removeBlur(responseEl); // fail open — show response if backend down
  }
}

// ── Handle the analysis result ────────────────────────────────
function handleAnalysisResult(responseEl, responseText, result) {
  const { psi_risk, dp_reconstruction_risk, sanitized_response, action } = result;

  if (action === "BLOCK") {
    // High reconstruction risk — show warning overlay
    showWarningOverlay(responseEl, result);
  } else if (action === "WARN") {
    // Medium risk — show response but with warning badge
    removeBlur(responseEl);
    showWarningBadge(responseEl, result);
  } else {
    // Safe — remove blur and show normally
    removeBlur(responseEl);
  }

  // If backend provided a sanitized version, offer it as alternative
  if (sanitized_response && sanitized_response !== responseText) {
    offerSanitizedVersion(responseEl, sanitized_response, result);
  }
}

// ── UI helpers ────────────────────────────────────────────────
function applyBlur(el, message) {
  el.style.filter    = "blur(6px)";
  el.style.userSelect = "none";
  el.style.transition = "filter 0.3s ease";

  const overlay = document.createElement("div");
  overlay.id    = "privacy-scanner-overlay";
  overlay.style.cssText = `
    position: absolute;
    top: 50%; left: 50%;
    transform: translate(-50%, -50%);
    background: rgba(0,0,0,0.7);
    color: white;
    padding: 8px 16px;
    border-radius: 8px;
    font-size: 13px;
    z-index: 9999;
    pointer-events: none;
  `;
  overlay.textContent = `🔍 ${message}`;

  const parent = el.parentElement;
  if (parent) {
    parent.style.position = "relative";
    parent.appendChild(overlay);
  }
}

function removeBlur(el) {
  el.style.filter    = "";
  el.style.userSelect = "";
  const overlay = el.parentElement?.querySelector("#privacy-scanner-overlay");
  if (overlay) overlay.remove();
}

function showWarningOverlay(el, result) {
  removeBlur(el);
  el.style.filter = "blur(4px)";

  const banner = document.createElement("div");
  banner.style.cssText = `
    background: #ff4444;
    color: white;
    padding: 10px 14px;
    border-radius: 8px;
    font-size: 13px;
    margin-bottom: 8px;
    display: flex;
    gap: 10px;
    align-items: center;
  `;
  banner.innerHTML = `
    <span>🚨 <strong>High reconstruction risk</strong> — 
    PSI match: ${(result.psi_risk * 100).toFixed(1)}% | 
    DP similarity: ${(result.dp_reconstruction_risk * 100).toFixed(1)}%</span>
    <button id="ps-reveal" style="background:white;color:#ff4444;border:none;
      padding:4px 10px;border-radius:4px;cursor:pointer;font-size:12px;">
      Show anyway
    </button>
  `;
  el.parentElement?.insertBefore(banner, el);
  banner.querySelector("#ps-reveal").addEventListener("click", () => {
    el.style.filter = "";
    banner.remove();
  });
}

function showWarningBadge(el, result) {
  const badge = document.createElement("div");
  badge.style.cssText = `
    background: #ff8800;
    color: white;
    padding: 4px 10px;
    border-radius: 4px;
    font-size: 11px;
    margin-bottom: 6px;
    display: inline-block;
  `;
  badge.textContent =
    `⚠️ Medium privacy risk — similarity ${(result.dp_reconstruction_risk * 100).toFixed(1)}%`;
  el.parentElement?.insertBefore(badge, el);
}

function offerSanitizedVersion(el, sanitized, result) {
  const btn = document.createElement("button");
  btn.style.cssText = `
    background: #4CAF50; color: white;
    border: none; padding: 5px 12px;
    border-radius: 4px; cursor: pointer;
    font-size: 11px; margin-top: 6px; display: block;
  `;
  btn.textContent = "🛡️ Show DP-sanitized version";
  btn.addEventListener("click", () => {
    el.innerText = sanitized;
    btn.remove();
  });
  el.parentElement?.appendChild(btn);
}

// ── Start ─────────────────────────────────────────────────────
init();