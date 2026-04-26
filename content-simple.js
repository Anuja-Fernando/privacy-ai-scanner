console.log("🚀 Simple content script loaded");

// Basic message listener for testing
chrome.runtime.onMessage.addListener(function(request, sender, sendResponse) {
    console.log("📨 Simple script received message:", request.action);
    
    if (request.action === "GET_TEXT") {
        console.log("✅ Processing GET_TEXT request");
        
        // Try to find LLM prompt boxes specifically
        let promptText = "";
        
        // ChatGPT prompt box selectors
        const chatGptSelectors = [
            'textarea[data-id="root"]',
            'textarea[placeholder*="Message"]',
            'textarea[placeholder*="Ask"]',
            'div[contenteditable="true"][data-contenteditable="true"]',
            'div[contenteditable="true"]',
            'textarea[placeholder*="Type a message"]',
            'textarea[placeholder*="Send a message"]'
        ];
        
        // Claude prompt box selectors
        const claudeSelectors = [
            'div[contenteditable="true"]',
            'textarea[placeholder*="Talk"]',
            'div[role="textbox"]',
            'textarea[placeholder*="Message Claude"]'
        ];
        
        // Gemini prompt box selectors
        const geminiSelectors = [
            'rich-textarea',
            'textarea[placeholder*="Enter"]',
            'div[contenteditable="true"]'
        ];
        
        // General LLM prompt selectors
        const generalSelectors = [
            'textarea[placeholder*="prompt"]',
            'textarea[placeholder*="message"]',
            'div[role="textbox"]',
            '[data-testid="prompt-textarea"]',
            'textarea[placeholder*="Ask anything"]',
            'textarea[placeholder*="Type your prompt"]'
        ];
        
        // Combine all selectors
        const allSelectors = [...chatGptSelectors, ...claudeSelectors, ...geminiSelectors, ...generalSelectors];
        
        // Try each selector
        for (const selector of allSelectors) {
            const element = document.querySelector(selector);
            if (element) {
                console.log("🎯 Found prompt box with selector:", selector);
                
                if (element.tagName === 'TEXTAREA') {
                    promptText = element.value || "";
                } else if (element.tagName === 'DIV' && element.contentEditable === 'true') {
                    promptText = element.innerText || element.textContent || "";
                } else {
                    promptText = element.value || element.innerText || element.textContent || "";
                }
                
                if (promptText.trim().length > 0) {
                    console.log("✅ Found prompt text length:", promptText.length);
                    break;
                }
            }
        }
        
        // If no prompt box found or it's empty, don't fall back to full page
        if (!promptText || promptText.trim().length === 0) {
            console.log("⚠️ No prompt text found. Please navigate to a page with an active LLM prompt box.");
            sendResponse({ 
                text: "", 
                error: "No prompt text found. Please navigate to a page with an active LLM prompt box.",
                source: "prompt-only"
            });
            return true;
        }
        
        console.log("📄 Prompt text preview:", promptText.substring(0, 100) + "...");
        
        // Send the prompt text only
        sendResponse({ 
            text: promptText,
            source: "prompt-only"
        });
        return true;
    }
});

console.log("🔧 Simple content script ready");
