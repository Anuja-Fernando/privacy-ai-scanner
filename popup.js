import { preprocess } from "./preprocess-focused.js";

document.addEventListener("DOMContentLoaded", () => {

  const button = document.getElementById("scanBtn");
  const output = document.getElementById("output");
  const status = document.getElementById("status");

  button.addEventListener("click", async () => {
    try {
      status.innerText = "Scanning...";

      const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });

      if (tab.url.startsWith("chrome://") ||
          tab.url.startsWith("chrome-extension://") ||
          tab.url.startsWith("moz-extension://") ||
          tab.url.startsWith("edge://") ||
          tab.url.startsWith("about:")) {
        throw new Error("Cannot scan browser internal pages.");
      }

      try {
        await chrome.scripting.executeScript({
          target: { tabId: tab.id },
          files: ["content-simple.js"]
        });
      } catch (injectError) {
        throw new Error("Cannot inject content script. The page may be restricted.");
      }

      await new Promise(resolve => setTimeout(resolve, 2000));

      let response;
      let retryCount = 0;
      while (retryCount < 3) {
        try {
          response = await chrome.tabs.sendMessage(tab.id, { action: "GET_TEXT" });
          break;
        } catch (e) {
          retryCount++;
          if (retryCount >= 3) throw new Error("Failed to communicate with page. Please refresh and try again.");
          await new Promise(resolve => setTimeout(resolve, 1000));
        }
      }

      if (!response || !response.text) {
        throw new Error(response?.error || "No text received from prompt box.");
      }

      const rawText = response.text;

      // ── Preprocessing ──────────────────────────────────────
      let cleanedText;
      try {
        cleanedText = await preprocess(rawText);
      } catch (e) {
        console.error("Preprocessing failed:", e);
        cleanedText = rawText;
      }

      // ── Get auth token ─────────────────────────────────────
      status.innerText = "Authenticating...";
      const authResponse = await fetch("http://localhost:8000/auth/token", {
        method: "POST",
        headers: { "Content-Type": "application/json" }
      });
      if (!authResponse.ok) throw new Error("Failed to authenticate with backend");
      const { access_token: authToken } = await authResponse.json();

      // ── STEP A: Store original prompt embedding for DP ─────
      const sessionId = crypto.randomUUID();

      try {
        const storeRes = await fetch("http://localhost:8000/analyze/store-prompt", {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            "Authorization": `Bearer ${authToken}`,
          },
          body: JSON.stringify({
            session_id:    sessionId,
            original_text: rawText,
          }),
        });
        if (storeRes.ok) {
          await chrome.storage.session.set({ privacySessionId: sessionId });
          console.log("✅ Prompt embedding stored, session:", sessionId);
        }
      } catch (e) {
        console.warn("Could not store prompt embedding:", e);
      }

      // ── STEP B: Run 7-phase enclave pipeline ───────────────
      status.innerText = "Running enclave pipeline...";

      const apiResponse = await fetch("http://localhost:8000/ml/inference", {
        method: "POST",
        headers: {
          "Content-Type":  "application/json",
          "Authorization": `Bearer ${authToken}`
        },
        body: JSON.stringify({
          text:       cleanedText,
          operation:  "ml_inference",
          session_id: sessionId,
        })
      });

      if (!apiResponse.ok) throw new Error(`Backend returned ${apiResponse.status}`);

      const data = await apiResponse.json();
      console.log("Enclave response:", JSON.stringify(data, null, 2));

      // ── STEP C: Display results ────────────────────────────
      // FIX: displayResults() is the ONLY place that renders HE and DP.
      // updateHEPanel() and updateDPPanel() are removed — they were
      // causing duplicate blocks by appending into #he-live-result
      // and #dp-live-result after displayResults() already rendered them.
      displayResults(data, output);
      status.innerText = data.status === "blocked" ? "Blocked 🚫" : "Done ✅";

    } catch (error) {
      console.error(error);
      status.innerText = "Error ❌";
      output.innerText = "Something went wrong: " + error.message;
    }
  });
});


// ══════════════════════════════════════════════════════════
// DISPLAY RESULTS — single source of truth for all rendering
// ══════════════════════════════════════════════════════════
function displayResults(data, output) {
  const riskIcons     = { safe: "✅", sensitive: "⚠️", malicious: "🚨" };
  const scopeIcons    = { user_pii: "🔐", aggregate: "📊", public: "🌍", unknown: "❓" };
  const privacyColors = { maximum: "#ff4444", high: "#ff8800", standard: "#00aa00", elevated: "#ff8800" };

  if (data.status === "blocked") {
    const meta = data.metadata || {};
    output.innerHTML = `
      <div style="background:#ffe0e0;border:1px solid #ff4444;border-radius:8px;padding:12px;margin-top:8px;">
        <div style="font-weight:bold;color:#cc0000;font-size:14px;">🚫 REQUEST BLOCKED</div>
        <div style="margin-top:6px;font-size:12px;color:#333;">${data.error || "Blocked by policy"}</div>
        ${meta.dp_result?.action === "BLOCK" ? `
        <div style="margin-top:6px;font-size:11px;color:#666;">
          DP reconstruction risk: ${((meta.dp_result.dp_reconstruction_risk || 0) * 100).toFixed(1)}%
          &nbsp;|&nbsp; ε budget remaining: ${100 - (meta.dp_result.budget?.percent_used || 0)}%
        </div>` : ""}
      </div>`;
    return;
  }

  const metadata    = data.metadata    || {};
  const risk        = metadata.risk_result  || {};
  const scope       = metadata.scope_result || {};
  const trust       = metadata.trust_score  || {};
  const gate        = metadata.gate_decision || {};
  const policy      = metadata.policy_result || {};
  const advancedML  = metadata.advanced_ml  || {};
  const piiDetected = metadata.pii_detected || [];

  // HE — from metadata.he (normalized in enclave_controller + main.py)
  const he       = metadata.he || {};
  const heActive = he.active         || false;
  const heTopics = he.flagged_topics || [];
  const heRisk   = he.max_risk       || 0;
  const heCT     = he.ct_size_bytes  || 0;

  // DP — from metadata.dp (normalized in main.py)
  const dp          = metadata.dp || {};
  const dpActive    = dp.active    || false;
  const dpAction    = dp.action    || "N/A";
  // FIX: read both possible key names — backend uses dp_reconstruction_risk,
  // main.py also exposes reconstruction_risk as an alias
  const dpRisk      = dp.dp_reconstruction_risk ?? dp.reconstruction_risk ?? 0;
  const dpNoised    = dp.noised_similarity ?? 0;
  const dpBudget    = dp.budget            || {};
  const dpEchoed    = dp.echoed_entities   || [];

  // DEBUG: Log DP state to diagnose why panel might be missing
  console.log("DP active:", dp.active, "action:", dp.action, "risk:", dp.reconstruction_risk);

  const privColor = privacyColors[metadata.privacy_level] || "#888";

  // DP action color
  const dpColor = dpAction === "ALLOW" ? "#388e3c"
                : dpAction === "WARN"  ? "#f57c00"
                : "#d32f2f";
  const dpIcon  = dpAction === "ALLOW" ? "✅"
                : dpAction === "WARN"  ? "⚠️"
                : "🚨";

  // FIX: processed output — reads data.result which enclave sets in Phase 6
  const processedOutput = data.result || "(no processed output)";

  output.innerHTML = `
    <div style="font-family:sans-serif;font-size:12px;margin-top:8px;">

      <!-- Gate status -->
      <div style="background:${gate.action === 'allow' ? '#e8f5e9' : '#ffe0e0'};
           border:1px solid ${gate.action === 'allow' ? '#4caf50' : '#ff4444'};
           border-radius:8px;padding:10px;margin-bottom:8px;">
        <div style="font-weight:bold;color:${gate.action === 'allow' ? '#2e7d32' : '#cc0000'};font-size:14px;">
          ${gate.action === 'allow' ? '✅ REQUEST ALLOWED' : '🚫 REQUEST BLOCKED'}
        </div>
        <div style="margin-top:4px;font-size:11px;color:#555;">
          Audit ID: ${metadata.audit_id || "N/A"}
        </div>
      </div>

      <!-- PII Override (Phase 2) — only shown if triggered -->
      ${piiDetected.length > 0 ? `
      <div style="background:#fff3e0;border:1px solid #ff9800;border-radius:8px;padding:10px;margin-bottom:6px;">
        <div style="font-weight:bold;">Phase 2 — PII Override</div>
        <div style="margin-top:4px;color:#e65100;">
          🔴 PII types detected: <strong>${piiDetected.join(", ")}</strong>
        </div>
        <div style="font-size:11px;color:#666;margin-top:2px;">
          ML model overridden → risk escalated to SENSITIVE
        </div>
      </div>` : ""}

      <!-- Risk Classification (Phase 2b) -->
      <div style="background:#fff8e1;border:1px solid #ffc107;border-radius:8px;padding:10px;margin-bottom:6px;">
        <div style="font-weight:bold;">Phase 2b — Risk Classification</div>
        <div style="margin-top:4px;">
          ${riskIcons[risk.label] || "?"}
          <strong>${(risk.label || "unknown").toUpperCase()}</strong>
          &nbsp; Confidence: ${
            typeof risk.confidence === "number"
              ? (risk.confidence * 100).toFixed(1) + "%"
              : risk.confidence || "N/A"
          }
        </div>
        ${risk.overridden_by ? `
          <div style="font-size:11px;color:#666;margin-top:2px;">
            ⚠️ Original ML label: ${risk.original_label?.toUpperCase()} → overridden by ${risk.overridden_by}
          </div>` : ""}
      </div>

      <!-- Scope Classification (Phase 5) -->
      <div style="background:#e3f2fd;border:1px solid #2196f3;border-radius:8px;padding:10px;margin-bottom:6px;">
        <div style="font-weight:bold;">Phase 5 — Scope Classification</div>
        <div style="margin-top:4px;">
          ${scopeIcons[scope.label] || "?"}
          <strong>${(scope.label || "unknown").toUpperCase()}</strong>
          &nbsp; Confidence: ${
            typeof scope.confidence === "number"
              ? (scope.confidence * 100).toFixed(1) + "%"
              : scope.confidence || "N/A"
          }
        </div>
      </div>

      <!-- Trust Score (Phase 1) -->
      <div style="background:#f3e5f5;border:1px solid #9c27b0;border-radius:8px;padding:10px;margin-bottom:6px;">
        <div style="font-weight:bold;">Phase 1 — Trust Score</div>
        <div style="margin-top:4px;">
          Score: <strong>${trust.trust_score || 0}/${trust.max_score || 5}</strong>
        </div>
        <div style="color:#666;margin-top:2px;font-size:11px;">
          MFA: ${trust.breakdown?.mfa_verified || 0} &nbsp;|&nbsp;
          Session: ${trust.breakdown?.session_fresh || 0} &nbsp;|&nbsp;
          Extension: ${trust.breakdown?.verified_extension || 0} &nbsp;|&nbsp;
          Anomaly: ${trust.breakdown?.low_anomaly || 0}
        </div>
      </div>

      <!-- Privacy Level (Phase 6) -->
      <div style="background:#fafafa;border:1px solid #ddd;border-radius:8px;padding:10px;margin-bottom:6px;">
        <div style="font-weight:bold;">Phase 6 — Privacy Level</div>
        <div style="margin-top:4px;color:${privColor};font-weight:bold;">
          ${(metadata.privacy_level || "standard").toUpperCase()}
        </div>
      </div>

      <!-- Advanced ML (Phase 2c) -->
      ${advancedML.anomaly || advancedML.phishing ? `
      <div style="background:#e8f5e9;border:1px solid #4caf50;border-radius:8px;padding:10px;margin-bottom:6px;">
        <div style="font-weight:bold;">Phase 2c — Advanced ML</div>
        <div style="margin-top:4px;">
          ${advancedML.anomaly?.is_anomaly
            ? `<div style="color:#d32f2f;">🔴 Anomaly: ${advancedML.anomaly.anomaly_score?.toFixed(3)}</div>`
            : `<div style="color:#388e3c;">✅ Anomaly: Normal (${advancedML.anomaly?.anomaly_score?.toFixed(3) || "N/A"})</div>`}
          ${advancedML.phishing?.is_phishing
            ? `<div style="color:#d32f2f;">🎣 Phishing: ${advancedML.phishing.phishing_score?.toFixed(3)}</div>`
            : `<div style="color:#388e3c;">✅ Phishing: Safe (${advancedML.phishing?.phishing_score?.toFixed(3) || "N/A"})</div>`}
        </div>
      </div>` : ""}

      <!-- Policy Security (Phase 3a) -->
      ${policy.sensitivity_level ? `
      <div style="background:#fff8e1;border:1px solid #ffc107;border-radius:8px;padding:10px;margin-bottom:6px;">
        <div style="font-weight:bold;">Phase 3a — Policy Security (GDPR/DPDP)</div>
        <div style="margin-top:4px;">
          Sensitivity: <strong style="color:#ff6f00;">${policy.sensitivity_level?.toUpperCase()}</strong>
          &nbsp;
          ${policy.allowed
            ? `<span style="color:#388e3c;">✅ ALLOWED</span>`
            : `<span style="color:#d32f2f;">🚫 BLOCKED</span>`}
        </div>
        ${policy.privacy_budget ? `
          <div style="font-size:11px;color:#666;margin-top:2px;">
            Budget: ${policy.privacy_budget.daily_available}/${policy.privacy_budget.daily_limit} remaining
          </div>` : ""}
      </div>` : ""}

      <!-- HE Private Set Intersection (Phase 2d) -->
      <!-- FIX: rendered ONCE here only — updateHEPanel() removed -->
      <div style="background:#fce4ec;border:1px solid #e91e63;border-radius:8px;padding:10px;margin-bottom:6px;">
        <div style="font-weight:bold;">Phase 2d — HE Private Set Intersection</div>
        <div style="margin-top:4px;font-size:12px;">
          ${heActive
            ? `🔐 Active &nbsp;|&nbsp; Risk: <strong>${(heRisk * 100).toFixed(1)}%</strong>
               &nbsp;|&nbsp; Topics: <strong>${heTopics.length > 0 ? heTopics.join(", ") : "none"}</strong>`
            : `⚠️ HE not active`}
        </div>
        ${heCT > 0 ? `
        <div style="font-size:11px;color:#666;margin-top:2px;">
          Ciphertext: ${heCT.toLocaleString()} bytes — backend saw only encrypted data
        </div>` : ""}
        <div style="font-size:11px;margin-top:2px;color:${heTopics.length > 0 ? '#c62828' : '#388e3c'};">
          ${heTopics.length > 0
            ? "⚠️ Sensitive topics detected in anonymized text — further protection applied"
            : "✅ No sensitive topics leaked through anonymization"}
        </div>
      </div>

      <!-- DP Reconstruction Resistance (Phase 4b) -->
      <!-- FIX: rendered ONCE here only — updateDPPanel() removed -->
      <div style="background:#e8f5e9;border:1px solid #4caf50;border-radius:8px;padding:10px;margin-bottom:6px;">
        <div style="font-weight:bold;">Phase 4b — DP Reconstruction Resistance</div>
        ${dpActive ? `
          <div style="margin-top:4px;font-size:12px;color:${dpColor};">
            ${dpIcon} Active &nbsp;|&nbsp; Action: <strong>${dpAction}</strong>
          </div>
          <div style="font-size:11px;color:#555;margin-top:2px;">
        ` : `
          <div style="margin-top:4px;font-size:12px;color:#555;">
            ⏳ DP analysis not available for this request
          </div>
        `}
      </div>

      <!-- Processed Output -->
      <div style="background:#f5f5f5;border:1px solid #ccc;border-radius:8px;padding:10px;">
        <div style="font-weight:bold;margin-bottom:6px;">Processed Output</div>
        <div style="font-size:11px;color:#333;word-break:break-all;white-space:pre-wrap;font-family:monospace;">
          ${processedOutput}
        </div>
      </div>

    </div>
  `;
}

// ── Listen for DP result from response_interceptor.js ─────
// Only used when the LLM response is analyzed AFTER submission
// (separate flow from the main scan pipeline above)
chrome.runtime.onMessage.addListener((msg) => {
  if (msg.action === "DP_RESULT") {
    // Find the DP panel and append the intercepted result below it
    const panel = document.querySelector("#dp-interceptor-result");
    if (panel) updateDPInterceptPanel(msg.payload);
  }
});

// Check if a DP result arrived while popup was closed
chrome.storage.local.get("lastDPResult", (stored) => {
  if (stored.lastDPResult) {
    chrome.storage.local.remove("lastDPResult");
  }
});

// Only used for response_interceptor.js LLM response analysis (separate flow)
function updateDPInterceptPanel(dp) {
  const panel = document.getElementById("dp-interceptor-result");
  if (!panel || !dp?.active) return;

  const icon   = dp.action === "ALLOW" ? "✅" : dp.action === "WARN" ? "⚠️" : "🚨";
  const color  = dp.action === "ALLOW" ? "#388e3c" : dp.action === "WARN" ? "#f57c00" : "#d32f2f";
  const risk   = ((dp.reconstruction_risk || 0) * 100).toFixed(1);
  const budget = dp.budget || {};

  panel.innerHTML = `
    <div style="border-top:1px solid #c8e6c9;padding-top:6px;margin-top:4px;font-size:11px;color:${color};">
      ${icon} LLM Response Analysis: <strong>${dp.action}</strong>
      &nbsp;|&nbsp; Similarity: ${risk}%
      &nbsp;|&nbsp; Budget: ${budget.eps_remaining ?? 10}/${budget.max_eps ?? 10}
    </div>
  `;
}