// REAL BERT-based PII Detection using Hugging Face Transformers
import { pipeline, env } from './node_modules/@xenova/transformers/dist/transformers.js';

// Fix: Disable worker to avoid CSP violations in Manifest V3
if (typeof globalThis !== 'undefined') {
    globalThis.TRANSFORMERS_JS_DISABLE_WORKER = true;
}

// Configure environment for local models and browser cache
env.allowLocalModels = true;
env.useBrowserCache = true;
env.localModelPath = './models/';
env.remoteHost = 'https://huggingface.co';
env.remotePathTemplate = '{model}/resolve/{revision}/';

console.log("🤖 BERT environment configured for local models and browser cache");

// Global pipeline instance
let nerPipeline = null;

// Initialize the BERT NER pipeline
async function initializeNERPipeline() {
    if (nerPipeline) {
        return nerPipeline;
    }
    
    console.log("🤖 Loading BERT NER model...");
    
    try {
        // Load pre-trained BERT model for Named Entity Recognition
        nerPipeline = await pipeline('token-classification', 'Xenova/bert-base-NER', {
            device: 'wasm',
            // Fix: Disable worker to avoid CSP violations
            no_worker: true
        });
        console.log("✅ BERT NER model loaded successfully");
        return nerPipeline;
    } catch (error) {
        console.error("❌ Failed to load BERT model:", error);
        throw error;
    }
}

// REAL MACHINE LEARNING PII Detection
export async function detectPII(text) {
    console.log("🧠 BERT-based PII detection starting...");
    
    const entities = [];
    
    try {
        // Initialize BERT pipeline
        const ner = await initializeNERPipeline();
        
        // Run BERT inference
        console.log("🔍 Running BERT inference on text:", text.substring(0, 100) + "...");
        
        // Use different aggregation strategies for better results
        const bertResults = await ner(text, {
            aggregation_strategy: 'none'  // Get token-level results first
        });
        
        console.log("🎯 Raw BERT token results:", bertResults);
        
        // Process token-level results to merge subwords properly
        const mergedResults = mergeBERTTokens(bertResults);
        console.log("🔗 Merged BERT results:", mergedResults);
        
        // Convert BERT results to our format
        mergedResults.forEach(result => {
            console.log(`🏷️ Processing BERT result: "${result.word}" -> ${JSON.stringify(result)}`);
            
            // Handle different BERT result formats
            let entityGroup = result.entity_group || result.entity || result.label;
            
            console.log(`🏷️ Processing BERT result: "${result.word}" -> ${entityGroup} (${result.score})`);
            
            const entity = {
                word: result.word,
                label: mapBERTLabelToPII(entityGroup),
                score: result.score,
                method: 'bert-transformer',
                start: result.start,
                end: result.end,
                confidence: result.score,
                detectedBy: 'bert-transformer',
                timestamp: new Date().toISOString(),
                isBERT: true
            };
            
            entities.push(entity);
        });
        
        // Additional processing for PII types not covered by standard NER
        const additionalEntities = await detectAdditionalPII(text);
        entities.push(...additionalEntities);
        
        // Post-process and deduplicate
        const finalEntities = postProcessBERTEntities(entities);
        
        console.log(`✅ BERT detection found ${finalEntities.length} entities`);
        return finalEntities;
        
    } catch (error) {
        console.error("❌ BERT detection failed:", error);
        
        // Fallback to basic detection if BERT fails
        console.log("🔄 Falling back to basic detection...");
        return fallbackDetection(text);
    }
}

// Merge BERT subword tokens into complete entities
function mergeBERTTokens(tokens) {
    const merged = [];
    let currentEntity = null;
    
    tokens.forEach(token => {
        // Skip tokens with very low confidence
        if (token.score < 0.3) {
            if (currentEntity) {
                merged.push(currentEntity);
                currentEntity = null;
            }
            return;
        }
        
        // Handle subword tokens (starting with ##)
        if (token.word.startsWith('##')) {
            if (currentEntity) {
                // Append to current entity
                currentEntity.word += token.word.replace('##', '');
                currentEntity.end = token.end;
                currentEntity.score = Math.max(currentEntity.score, token.score);
                // Preserve the entity group from the first token
                if (!currentEntity.entity_group && token.entity_group) {
                    currentEntity.entity_group = token.entity_group;
                }
            }
        } else {
            // Save previous entity if exists
            if (currentEntity) {
                merged.push(currentEntity);
            }
            
            // Start new entity
            currentEntity = {
                word: token.word,
                entity_group: token.entity_group || token.entity || token.label,
                score: token.score,
                start: token.start,
                end: token.end
            };
        }
    });
    
    // Don't forget the last entity
    if (currentEntity) {
        merged.push(currentEntity);
    }
    
    return merged;
}

// Map BERT entity labels to PII categories
function mapBERTLabelToPII(bertLabel) {
    const labelMapping = {
        // Standard BERT labels
        'PER': 'PER',           // Person
        'PERSON': 'PER',        // Person (alternative)
        'LOC': 'LOC',           // Location
        'LOCATION': 'LOC',      // Location (alternative)
        'ORG': 'ORG',           // Organization
        'ORGANIZATION': 'ORG',  // Organization (alternative)
        'MISC': 'OTHER',        // Miscellaneous
        'GPE': 'LOC',           // Geopolitical Entity
        'FAC': 'ORG',           // Facility
        'EVENT': 'OTHER',       // Event
        'WORK_OF_ART': 'OTHER', // Work of Art
        'LAW': 'LEGAL',         // Law/Legal
        'PRODUCT': 'OTHER',     // Product
        'LANGUAGE': 'OTHER',    // Language
        'DATE': 'DATE',         // Date
        'TIME': 'TIME',         // Time
        'CARDINAL': 'NUMBER',   // Cardinal Number
        'ORDINAL': 'NUMBER',    // Ordinal Number
        'MONEY': 'MONEY',      // Money
        'QUANTITY': 'NUMBER',   // Quantity
        'NORP': 'OTHER',        // Nationality/Religious/Political Group
        
        // B- prefix labels (Beginning of entity)
        'B-PER': 'PER',         // Beginning of Person
        'B-PERSON': 'PER',      // Beginning of Person
        'B-LOC': 'LOC',         // Beginning of Location
        'B-LOCATION': 'LOC',    // Beginning of Location
        'B-ORG': 'ORG',         // Beginning of Organization
        'B-ORGANIZATION': 'ORG', // Beginning of Organization
        'B-MISC': 'OTHER',      // Beginning of Miscellaneous
        'B-GPE': 'LOC',         // Beginning of Geopolitical Entity
        'B-FAC': 'ORG',         // Beginning of Facility
        'B-EVENT': 'OTHER',     // Beginning of Event
        'B-PRODUCT': 'OTHER',   // Beginning of Product
        'B-LAW': 'LEGAL',       // Beginning of Law
        'B-DATE': 'DATE',       // Beginning of Date
        'B-TIME': 'TIME',       // Beginning of Time
        'B-MONEY': 'MONEY',     // Beginning of Money
        'B-CARDINAL': 'NUMBER', // Beginning of Cardinal Number
        'B-ORDINAL': 'NUMBER',  // Beginning of Ordinal Number
        'B-QUANTITY': 'NUMBER', // Beginning of Quantity
        'B-NORP': 'OTHER',      // Beginning of NORP
        
        // I- prefix labels (Inside/Continuation of entity)
        'I-PER': 'PER',         // Inside Person
        'I-PERSON': 'PER',      // Inside Person
        'I-LOC': 'LOC',         // Inside Location
        'I-LOCATION': 'LOC',    // Inside Location
        'I-ORG': 'ORG',         // Inside Organization
        'I-ORGANIZATION': 'ORG', // Inside Organization
        'I-MISC': 'OTHER',      // Inside Miscellaneous
        'I-GPE': 'LOC',         // Inside Geopolitical Entity
        'I-FAC': 'ORG',         // Inside Facility
        'I-EVENT': 'OTHER',     // Inside Event
        'I-PRODUCT': 'OTHER',   // Inside Product
        'I-LAW': 'LEGAL',       // Inside Law
        'I-DATE': 'DATE',       // Inside Date
        'I-TIME': 'TIME',       // Inside Time
        'I-MONEY': 'MONEY',     // Inside Money
        'I-CARDINAL': 'NUMBER', // Inside Cardinal Number
        'I-ORDINAL': 'NUMBER',  // Inside Ordinal Number
        'I-QUANTITY': 'NUMBER', // Inside Quantity
        'I-NORP': 'OTHER',      // Inside NORP
    };
    
    // Handle undefined/null labels
    if (!bertLabel) {
        console.log("⚠️ BERT entity has no label, classifying as OTHER");
        return 'OTHER';
    }
    
    const mappedLabel = labelMapping[bertLabel.toUpperCase()];
    if (mappedLabel) {
        return mappedLabel;
    }
    
    console.log(`⚠️ Unknown BERT label: ${bertLabel}, mapping to OTHER`);
    return 'OTHER';
}

// Detect additional PII types not covered by standard NER
async function detectAdditionalPII(text) {
    const entities = [];
    
    // Email detection (BERT doesn't always catch emails)
    const emailPattern = /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b/g;
    const emails = text.match(emailPattern) || [];
    emails.forEach(email => {
        entities.push({
            word: email,
            label: 'EMAIL',
            score: 0.95,
            method: 'pattern-email',
            confidence: 0.95
        });
    });
    
    // Phone detection (BERT doesn't always catch phone numbers)
    const phonePatterns = [
        /\b\d{10}\b/g,
        /\b\d{3}-\d{3}-\d{4}\b/g,
        /\b\(\d{3}\)\s*\d{3}-\d{4}\b/g,
        /\+\d{1,3}\s*\d{3,4}\s*\d{3,4}\s*\d{4}\b/g
    ];
    
    phonePatterns.forEach(pattern => {
        const phones = text.match(pattern) || [];
        phones.forEach(phone => {
            entities.push({
                word: phone,
                label: 'PHONE',
                score: 0.90,
                method: 'pattern-phone',
                confidence: 0.90
            });
        });
    });
    
    // Credit card detection
    const ccPattern = /\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b/g;
    const creditCards = text.match(ccPattern) || [];
    creditCards.forEach(cc => {
        entities.push({
            word: cc,
            label: 'CREDIT_CARD',
            score: 0.95,
            method: 'pattern-cc',
            confidence: 0.95
        });
    });
    
    // SSN detection
    const ssnPattern = /\b\d{3}-\d{2}-\d{4}\b/g;
    const ssns = text.match(ssnPattern) || [];
    ssns.forEach(ssn => {
        entities.push({
            word: ssn,
            label: 'SSN',
            score: 0.95,
            method: 'pattern-ssn',
            confidence: 0.95
        });
    });
    
    // URL detection
    const urlPattern = /https?:\/\/[^\s]+/g;
    const urls = text.match(urlPattern) || [];
    urls.forEach(url => {
        entities.push({
            word: url,
            label: 'URL',
            score: 0.85,
            method: 'pattern-url',
            confidence: 0.85
        });
    });
    
    // IP address detection
    const ipPattern = /\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/g;
    const ips = text.match(ipPattern) || [];
    ips.forEach(ip => {
        entities.push({
            word: ip,
            label: 'IP_ADDRESS',
            score: 0.80,
            method: 'pattern-ip',
            confidence: 0.80
        });
    });
    
    return entities;
}

// Post-process BERT entities
function postProcessBERTEntities(entities) {
    console.log("🔧 Post-processing BERT entities...");
    
    // Remove duplicates with confidence weighting
    const uniqueEntities = {};
    entities.forEach(entity => {
        const key = entity.word.toLowerCase();
        if (!uniqueEntities[key] || uniqueEntities[key].score < entity.score) {
            uniqueEntities[key] = entity;
        }
    });
    
    // Filter by confidence threshold
    const filteredEntities = Object.values(uniqueEntities).filter(
        entity => entity.score > 0.5
    );
    
    // Sort by confidence
    const sortedEntities = filteredEntities.sort((a, b) => b.score - a.score);
    
    // Add metadata
    const finalEntities = sortedEntities.map(entity => ({
        ...entity,
        detectedBy: entity.method,
        timestamp: new Date().toISOString(),
        isBERT: entity.method === 'bert-transformer'
    }));
    
    console.log(`✅ Post-processed ${finalEntities.length} entities`);
    return finalEntities;
}

// Fallback detection if BERT fails
function fallbackDetection(text) {
    console.log("🔄 Using fallback detection...");
    
    const entities = [];
    
    // Basic pattern-based detection as fallback
    const patterns = [
        { pattern: /\b[A-Z][a-z]+\s+[A-Z][a-z]+\b/g, label: 'PER', score: 0.7 },
        { pattern: /\b[A-Z][a-z]+,\s*[A-Z]{2}\b/g, label: 'LOC', score: 0.8 },
        { pattern: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b/g, label: 'EMAIL', score: 0.95 },
        { pattern: /\b\d{3}-\d{3}-\d{4}\b/g, label: 'PHONE', score: 0.9 }
    ];
    
    patterns.forEach(({ pattern, label, score }) => {
        const matches = text.match(pattern) || [];
        matches.forEach(match => {
            entities.push({
                word: match,
                label: label,
                score: score,
                method: 'fallback-pattern',
                confidence: score
            });
        });
    });
    
    return entities;
}

// Advanced BERT-based context analysis
export async function analyzeContext(text, entities) {
    console.log("🔍 Analyzing context with BERT...");
    
    try {
        const ner = await initializeNERPipeline();
        
        // Analyze each entity in context
        const contextualEntities = [];
        
        for (const entity of entities) {
            // Extract context around the entity
            const start = Math.max(0, entity.start - 50);
            const end = Math.min(text.length, entity.end + 50);
            const context = text.substring(start, end);
            
            // Run BERT on the context
            const contextResults = await ner(context, {
                aggregation_strategy: 'simple'
            });
            
            // Find the entity in context results
            const contextEntity = contextResults.find(result => 
                result.word.toLowerCase() === entity.word.toLowerCase()
            );
            
            if (contextEntity) {
                contextualEntities.push({
                    ...entity,
                    contextScore: contextEntity.score,
                    contextLabel: mapBERTLabelToPII(contextEntity.entity_group),
                    contextText: context
                });
            }
        }
        
        return contextualEntities;
        
    } catch (error) {
        console.error("❌ Context analysis failed:", error);
        return entities;
    }
}

// Batch processing for multiple texts
export async function batchDetectPII(texts) {
    console.log("📦 Running batch BERT detection...");
    
    const results = [];
    
    for (const text of texts) {
        try {
            const entities = await detectPII(text);
            results.push({
                text: text,
                entities: entities,
                success: true
            });
        } catch (error) {
            console.error(`❌ Failed to process text: ${text.substring(0, 50)}...`, error);
            results.push({
                text: text,
                entities: [],
                success: false,
                error: error.message
            });
        }
    }
    
    return results;
}

// Real-time PII detection for streaming text
export class StreamingPIIDetector {
    constructor() {
        this.buffer = '';
        this.entities = [];
        this.isInitialized = false;
    }
    
    async initialize() {
        if (!this.isInitialized) {
            await initializeNERPipeline();
            this.isInitialized = true;
        }
    }
    
    async addText(text) {
        await this.initialize();
        
        this.buffer += text;
        
        // Process when buffer is substantial
        if (this.buffer.length > 100) {
            const newEntities = await detectPII(this.buffer);
            this.entities = this.entities.concat(newEntities);
            this.buffer = this.buffer.substring(-50); // Keep some overlap
        }
        
        return this.entities;
    }
    
    async finalize() {
        // Process remaining buffer
        if (this.buffer.length > 0) {
            const finalEntities = await detectPII(this.buffer);
            this.entities = this.entities.concat(finalEntities);
        }
        
        return postProcessBERTEntities(this.entities);
    }
}

// Export utility functions
export { initializeNERPipeline };

// Model information
export const modelInfo = {
    name: 'Xenova/bert-base-NER',
    type: 'BERT-based Named Entity Recognition',
    size: '~420MB',
    accuracy: 'F1: ~0.92 on CoNLL-2003',
    supportedEntities: ['PER', 'LOC', 'ORG', 'MISC'],
    description: 'Pre-trained BERT model for Named Entity Recognition'
};
