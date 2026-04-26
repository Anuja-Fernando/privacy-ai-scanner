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
      // This stores the PRE-anonymization embedding so that when
      // response_interceptor.js calls /analyze/response later,
      // it can compare the LLM response against this original.
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
            original_text: rawText,   // ORIGINAL — before anonymization
          }),
        });
        if (storeRes.ok) {
          // Save session_id so response_interceptor.js can read it
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
          session_id: sessionId,      // passed so enclave logs it
        })
      });

      if (!apiResponse.ok) throw new Error(`Backend returned ${apiResponse.status}`);

      const data = await apiResponse.json();
      console.log("Enclave response:", JSON.stringify(data, null, 2));

      // ── STEP C: Display results ────────────────────────────
      displayResults(data, output);
      status.innerText = data.status === "blocked" ? "Blocked 🚫" : "Done ✅";

      // ── STEP D: Update live panels AFTER DOM is rendered ──
      // Use setTimeout(0) to wait for innerHTML to finish painting
      setTimeout(() => {
        const dp = data.metadata?.dp;
        const he = data.metadata?.he;

        console.log(" DP data:", dp);
        console.log(" HE data:", he);

        if (dp) updateDPPanel(dp);
        if (he) updateHEPanel(he);
      }, 0);

    } catch (error) {
      console.error(error);
      status.innerText = "Error ❌";
      output.innerText = "Something went wrong: " + error.message;
    }
  });
});


// ══════════════════════════════════════════════════════════
// DISPLAY RESULTS
// Reads from data.metadata.he and data.metadata.dp
// ══════════════════════════════════════════════════════════
function displayResults(data, output) {
  const riskIcons     = { safe: "✅", sensitive: "⚠️", malicious: "🚨" };
  const scopeIcons    = { user_pii: "🔐", aggregate: "📊", public: "🌍", unknown: "❓" };
  const privacyColors = { maximum: "#ff4444", high: "#ff8800", standard: "#00aa00", elevated: "#ff8800" };

  if (data.status === "blocked") {
    const meta = data.metadata || {};
    const gate = meta.gate_decision || {};
    output.innerHTML = `
      <div style="background:#ffe0e0;border:1px solid #ff4444;border-radius:8px;padding:12px;margin-top:8px;">
        <div style="font-weight:bold;color:#cc0000;font-size:14px;">🚫 REQUEST BLOCKED</div>
        <div style="margin-top:6px;font-size:12px;color:#333;">${data.error || gate.reason || "Blocked by policy"}</div>
      </div>`;
    return;
  }

  // ── Extract from correct nested location ─────────────────
  const metadata     = data.metadata    || {};
  const risk         = metadata.risk_result  || {};
  const scope        = metadata.scope_result || {};
  const trust        = metadata.trust_score  || {};
  const gate         = metadata.gate_decision || {};
  const policy       = metadata.policy_result || {};
  const advancedML   = metadata.advanced_ml  || {};
  const piiDetected  = metadata.pii_detected || [];

  // ── HE result — from metadata.he ─────────────────────────
  const he           = metadata.he || {};
  const heActive     = he.active         || false;
  const heTopics     = he.flagged_topics || [];
  const heMaxRisk    = he.max_risk       || 0;
  const heCTSize     = he.ct_size_bytes  || 0;

  // Debug: Log HE data
  console.log("HE block:", JSON.stringify(metadata.he));
  console.log("HE active value:", metadata.he?.active);

  // ── DP result ────────────────────────────────────────
  const dp           = metadata.dp || {};
  
  // Debug: Log DP data
  console.log("DP block:", JSON.stringify(metadata.dp));
  console.log("DP active value:", metadata.dp?.active);

  // FIX: Normalize DP data to ensure it's always available
  const normalizedDP = {
    active: metadata.dp?.active || false,
    action: metadata.dp?.action || "N/A",
    reconstruction_risk: metadata.dp?.reconstruction_risk || 0,
    noised_similarity: metadata.dp?.noised_similarity || 0,
    budget: metadata.dp?.budget || {},
    echoed_entities: metadata.dp?.echoed_entities || [],
  };
  
  console.log("Normalized DP:", normalizedDP);

  const privColor    = privacyColors[metadata.privacy_level] || "#888";

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

      <!-- PII detected (Phase 2 override) -->
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

      <!-- Risk Classification -->
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

      <!-- Scope -->
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

      <!-- Trust -->
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

      <!-- Privacy Level -->
      <div style="background:#fafafa;border:1px solid #ddd;border-radius:8px;padding:10px;margin-bottom:6px;">
        <div style="font-weight:bold;">Phase 6 — Privacy Level</div>
        <div style="margin-top:4px;color:${privColor};font-weight:bold;">
          ${(metadata.privacy_level || "standard").toUpperCase()}
        </div>
      </div>

      <!-- Advanced ML -->
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

      <!-- Policy Security -->
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
      <div style="background:#fce4ec;border:1px solid #e91e63;border-radius:8px;padding:10px;margin-bottom:6px;">
        <div style="font-weight:bold;">Phase 2d — HE Private Set Intersection</div>
        <div style="margin-top:4px;font-size:12px;">
          ${heActive
            ? `🔐 Active &nbsp;|&nbsp; Risk: <strong>${(heMaxRisk * 100).toFixed(1)}%</strong>
               &nbsp;|&nbsp; Topics: <strong>${heTopics.length > 0 ? heTopics.join(", ") : "none"}</strong>`
            : `⚠️ HE not active`}
        </div>
        ${heCTSize > 0 ? `
        <div style="font-size:11px;color:#666;margin-top:2px;">
          Ciphertext: ${heCTSize.toLocaleString()} bytes — backend saw only encrypted data
        </div>` : ""}
        ${heTopics.length > 0 ? `
        <div style="font-size:11px;color:#c62828;margin-top:2px;">
          ⚠️ Sensitive topics detected in anonymized text — further protection applied
        </div>` : `
        <div style="font-size:11px;color:#388e3c;margin-top:2px;">
          ✅ No sensitive topics leaked through anonymization
        </div>`}
        <div id="he-live-result" style="margin-top:6px;"></div>
      </div>

      <!-- DP Reconstruction Resistance (Phase 4b) -->
      <div style="background:#e8f5e9;border:1px solid #4caf50;border-radius:8px;padding:10px;margin-bottom:6px;">
        <div style="font-weight:bold;">Phase 4b — DP Reconstruction Resistance</div>
        ${normalizedDP.active && normalizedDP.action !== 'N/A' ? `
          <div style="margin-top:4px;font-size:12px;color:#388e3c;">
            🔐 Active | Action: <strong>${normalizedDP.action}</strong>
          </div>
          <div style="font-size:11px;color:#555;margin-top:2px;">
            Reconstruction risk: <strong>${((normalizedDP.reconstruction_risk || 0) * 100).toFixed(1)}%</strong>
            &nbsp;|&nbsp;
            After noise: <strong>${((normalizedDP.noised_similarity || 0) * 100).toFixed(1)}%</strong>
          </div>
          <div style="font-size:11px;color:#666;margin-top:2px;">
            ε budget remaining: ${100 - (normalizedDP.budget?.percent_used || 0)}%
            (${normalizedDP.budget?.eps_remaining || 10} / ${normalizedDP.budget?.max_eps || 10})
          </div>
          ${normalizedDP.echoed_entities?.length > 0 ? `
            <div style="font-size:11px;color:#d32f2f;margin-top:2px;">
              ⚠️ LLM echoed PII: ${normalizedDP.echoed_entities.join(", ")}
            </div>` : ""}
        ` : `
          <div style="margin-top:4px;font-size:12px;color:#555;">
            ${normalizedDP.active ? '🔐 DP Analysis Complete' : '⏳ Waiting for DP analysis...'}
          </div>
          <div style="font-size:11px;color:#666;margin-top:2px;">
            ${normalizedDP.active ? 'DP analysis completed successfully.' : 'DP analysis runs automatically during privacy processing.'}
          </div>
        `}
        <div id="dp-live-result" style="margin-top:6px;"></div>
      </div>

      <!-- Processed Output -->
      <div style="background:#f5f5f5;border:1px solid #ccc;border-radius:8px;padding:10px;">
        <div style="font-weight:bold;">Processed Output</div>
    </div>
  </div>

</div>
`;
} // <--- Added missing closing brace here

// Listen for DP result from response_interceptor.js
// It sends a message when /analyze/response completes
chrome.runtime.onMessage.addListener((msg) => {
  if (msg.action === "DP_RESULT") {
    updateDPPanel(msg.payload);
  }
});

// ← FIX: Check if DP already ran while popup was closed
chrome.storage.local.get('lastDPResult', (data) => {
  if (data.lastDPResult) {
    updateDPPanel(data.lastDPResult);
    chrome.storage.local.remove('lastDPResult'); // clear after showing
  }
});

// ── Update DP panel when response_interceptor.js sends result ─
function updateDPPanel(dp) {
  const panel = document.getElementById("dp-live-result");
  if (!panel) return;

  if (!dp?.active) {
    panel.innerHTML = `⚠️ DP filter not active`;
    return;
  }

  const icon = dp.action === "ALLOW" ? "✅" : "�";
  const risk = ((dp.reconstruction_risk || 0) * 100).toFixed(1);
  const noised = ((dp.noised_similarity || 0) * 100).toFixed(1);
  const budget = dp.budget || {};

  panel.innerHTML = `
    <div style="border-top:1px solid #c8e6c9;padding-top:6px;margin-top:4px;">
      <div style="color:${dp.action === "ALLOW" ? "#388e3c" : dp.action === "WARN" ? "#f57c00" : "#d32f2f"};font-weight:bold;font-size:12px;">
        ${icon} <strong>${dp.action}</strong>
        &nbsp;|&nbsp; Similarity: ${risk}%
        &nbsp;|&nbsp; Noised: ${noised}%
        &nbsp;|&nbsp; Budget: ${budget.eps_remaining || 10}/${budget.max_eps || 10} 
          (${100 - (budget.percent_used || 0)}% remaining)
      </div>
    </div>
  `;
}

// ── Update HE panel for immediate display ─
function updateHEPanel(he) {
  const hePanel = document.getElementById("he-live-result");
  if (!hePanel || !he?.active) return;

  const topics = he.flagged_topics?.join(", ") || "none";
  const risk = ((he.max_risk || 0) * 100).toFixed(1);

  hePanel.innerHTML = `
    <div style="border-top:1px solid #fce4ec;padding-top:6px;margin-top:4px;">
      <div style="color:#388e3c;font-weight:bold;font-size:12px;">
        🔐 Active &nbsp;|&nbsp; Risk: <strong>${risk}%</strong>
        &nbsp;|&nbsp; Topics: <strong>${topics}</strong>
        &nbsp;|&nbsp; Ciphertext: ${he.ct_size_bytes?.toLocaleString()} bytes
      </div>
    </div>
  `;
}

// ── Fix: Add DP display handler for backend response ─
function updateDPDisplay(response) {
  const dp = response.dp_result || response.dp; // Handle both key names
  
  if (!dp || !dp.active) {
    console.log("⚠️ DP not active in response");
    return;
  }

  // Handle BOTH key names from backend inconsistency
  const risk = dp.dp_reconstruction_risk ?? dp.reconstruction_risk ?? 0;
  const action = dp.action || "N/A";
  const budget = dp.budget || {};

  console.log("🔍 DP Display Update:", { active: dp.active, action, risk, budget });

  const dpPanel = document.getElementById("dp-live-result");
  if (dpPanel) {
    dpPanel.innerHTML = `
      <div style="border-top:1px solid #c8e6c9;padding-top:6px;margin-top:4px;">
        <div style="color:${action === "ALLOW" ? "#388e3c" : action === "WARN" ? "#f57c00" : "#d32f2f"};font-weight:bold;font-size:12px;">
          ${action === "ALLOW" ? "✅" : action === "WARN" ? "⚠️" : "🚨"} ${action}
          | Similarity: ${(risk * 100).toFixed(1)}%
          | Budget: ${budget.eps_remaining || 10}/${budget.max_eps || 10} 
            (${100 - (budget.percent_used || 0)}% remaining)
        </div>
      </div>
    `;
  }
}