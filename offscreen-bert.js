// Offscreen BERT Worker Manager
// Handles Transformers.js BERT model in offscreen document to avoid CSP issues

let bertModel = null;
let tokenizer = null;
let isInitialized = false;

// Initialize BERT model
async function initializeBERT() {
    if (isInitialized) return;
    
    try {
        console.log("[Offscreen] Initializing BERT model...");
        
        // Import Transformers.js from local node_modules
        const { pipeline, env } = await import('./node_modules/@xenova/transformers/dist/transformers.js');
        
        // Configure environment
        env.allowLocalModels = false;
        env.allowRemoteModels = true;
        
        // Initialize pipeline
        bertModel = await pipeline('token-classification', 'dbmdz/bert-large-cased-finetuned-conll03-english');
        tokenizer = bertModel.tokenizer;
        
        isInitialized = true;
        console.log("[Offscreen] BERT model initialized successfully");
        
        // Notify main extension
        chrome.runtime.sendMessage({ 
            action: "BERT_READY",
            status: "ready"
        });
        
    } catch (error) {
        console.error("[Offscreen] Failed to initialize BERT:", error);
        chrome.runtime.sendMessage({ 
            action: "BERT_READY",
            status: "error",
            error: error.message
        });
    }
}

// Process text with BERT NER
async function processText(text) {
    if (!isInitialized) {
        await initializeBERT();
    }
    
    if (!bertModel) {
        throw new Error("BERT model not initialized");
    }
    
    try {
        console.log("[Offscreen] Processing text with BERT...");
        const results = await bertModel(text);
        console.log("[Offscreen] BERT results:", results);
        
        return {
            success: true,
            entities: results.map(entity => ({
                word: entity.word,
                label: entity.entity_group,
                score: entity.score,
                start: entity.start,
                end: entity.end,
                isBERT: true
            }))
        };
    } catch (error) {
        console.error("[Offscreen] BERT processing error:", error);
        return {
            success: false,
            error: error.message,
            entities: []
        };
    }
}

// Listen for messages from main extension
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    if (message.action === "BERT_PROCESS") {
        processText(message.text)
            .then(result => sendResponse(result))
            .catch(error => sendResponse({ success: false, error: error.message }));
        return true; // Keep message channel open for async response
    }
    
    if (message.action === "BERT_INIT") {
        initializeBERT()
            .then(() => sendResponse({ success: true }))
            .catch(error => sendResponse({ success: false, error: error.message }));
        return true;
    }
});

// Auto-initialize on load
initializeBERT();
