// Offscreen BERT management
let offscreenCreated = false;

async function ensureOffscreenDocument() {
    if (offscreenCreated) return;
    
    try {
        // Check if offscreen document already exists
        const existingContexts = await chrome.runtime.getContexts({
            contextTypes: ['OFFSCREEN_DOCUMENT']
        });
        
        if (existingContexts.length === 0) {
            await chrome.offscreen.createDocument({
                url: 'offscreen.html',
                reasons: ['WORKERS'],
                justification: 'BERT NER inference via Transformers.js'
            });
            console.log("[Background] Offscreen document created for BERT");
        } else {
            console.log("[Background] Offscreen document already exists");
        }
        
        offscreenCreated = true;
    } catch (error) {
        console.error("[Background] Failed to create offscreen:", error);
    }
}

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    // Handle BERT processing requests
    if (message.type === "RUN_BERT") {
        ensureOffscreenDocument().then(() => {
            // Forward to offscreen document
            chrome.runtime.sendMessage({
                type: "RUN_BERT",
                text: message.text
            }, response => {
                sendResponse(response);
            });
        }).catch(error => {
            sendResponse({ success: false, error: error.message, entities: [] });
        });
        return true; // Keep message channel open
    }
    
    if (message.action === "sendToBackend") {
        console.log("Sanitized data:", message.text);

        // Example API call
        fetch("http://localhost:8000/api", {
            method: "POST",
            headers: {
                "Content-Type": "application/json"
            },
            body: JSON.stringify({ text: message.text })
        });

        sendResponse({ status: "sent" });
    }
    
    // Handle prompt embedding storage from response interceptor
    if (message.action === "STORE_PROMPT_EMBEDDING") {
        console.log("Storing prompt embedding for:", message.payload.text);
        
        // Send to backend to compute and store embedding
        fetch("http://localhost:8000/analyze/store-prompt", {
            method: "POST",
            headers: {
                "Content-Type": "application/json"
            },
            body: JSON.stringify({ 
                prompt_text: message.payload.text,
                timestamp: new Date().toISOString()
            })
        })
        .then(response => response.json())
        .then(data => {
            console.log("Prompt embedding stored:", data);
            sendResponse({ status: "stored", embedding_id: data.embedding_id });
        })
        .catch(error => {
            console.error("Failed to store prompt embedding:", error);
            sendResponse({ status: "error", error: error.message });
        });
        
        return true; // Keep message channel open for async response
    }
});