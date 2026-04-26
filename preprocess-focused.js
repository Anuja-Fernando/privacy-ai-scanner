// FOCUSED PRIVACY PIPELINE - Attribute Forgery & Generalization Only
import { detectPII } from "./ner-bert.js";

// Offscreen BERT communication
async function detectPIIWithOffscreen(text) {
    try {
        // Try offscreen BERT first
        const bertResult = await chrome.runtime.sendMessage({
            type: "RUN_BERT",
            text: text
        });
        
        if (bertResult && bertResult.success && bertResult.entities.length > 0) {
            console.log("✅ Offscreen BERT detected entities:", bertResult.entities);
            return bertResult.entities.map(ent => ({
                ...ent,
                detectedBy: 'bert-transformer',
                timestamp: new Date().toISOString(),
                isBERT: true
            }));
        }
    } catch (error) {
        console.warn("⚠️ Offscreen BERT failed, falling back to local:", error);
    }
    
    // Fallback to local detection (regex-based)
    console.log("🔄 Using fallback PII detection");
    return await detectPII(text);
}

// ─────────────────────────────────────────────
// STEP 1 — PROMPT INTENT CLASSIFIER
// Runs BEFORE NER. Decides whether to even scan.
// ─────────────────────────────────────────────

const TECHNICAL_KEYWORDS = [
  // Programming languages & versions
  "python", "javascript", "java", "c++", "typescript", "rust", "golang", "ruby",
  "react", "angular", "vue", "node", "django", "flask", "spring",
  // Technical concepts
  "function", "array", "object", "class", "method", "variable", "loop",
  "api", "rest", "graphql", "http", "https", "tcp", "sql", "nosql",
  "database", "server", "client", "backend", "frontend", "deploy",
  "docker", "kubernetes", "git", "github", "algorithm", "recursion",
  "async", "await", "promise", "callback", "thread", "memory", "cache",
  // Math / science
  "equation", "theorem", "matrix", "vector", "gradient", "integral",
  "derivative", "probability", "statistics", "hypothesis",
  // Generic question starters that are never personal
  "explain", "what is", "how does", "define", "summarize", "translate",
  "difference between", "compare", "list", "give me an example"
];

const PERSONAL_SIGNALS = [
  "my name is", "i am", "i'm", "my email", "my phone", "my address",
  "my age is", "i was born", "my dob", "my ssn", "my passport",
  "my bank", "my credit card", "my account", "i live at", "i live in",
  "contact me", "reach me", "call me", "text me", "my id",
  "my aadhaar", "my pan", "my salary", "i earn", "i make"
];

const DIRECT_PII_PATTERNS = [
  /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b/,      // email
  /\b(\+91[\-\s]?)?[6-9]\d{9}\b/,                               // Indian mobile
  /\b(\+1[\-\s]?)?\(?\d{3}\)?[\-\s]?\d{3}[\-\s]?\d{4}\b/,      // US phone
  /\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b/,                // credit card
  /\b\d{3}-\d{2}-\d{4}\b/,                                      // SSN
  /\b[2-9]{1}[0-9]{3}\s[0-9]{4}\s[0-9]{4}\b/,                  // Aadhaar
  /\b[A-Z]{5}[0-9]{4}[A-Z]{1}\b/                                // PAN card
];

function classifyPromptIntent(text) {
  const lower = text.toLowerCase();

  // DIRECT_PII — always process regardless of anything else
  for (const pattern of DIRECT_PII_PATTERNS) {
    if (pattern.test(text)) {
      console.log("🔴 Intent: DIRECT_PII — regex match found");
      return "DIRECT_PII";
    }
  }

  // PERSONAL — first-person PII signals
  for (const signal of PERSONAL_SIGNALS) {
    if (lower.includes(signal)) {
      console.log(`🟠 Intent: PERSONAL — signal matched: "${signal}"`);
      return "PERSONAL";
    }
  }

  // TECHNICAL — skip anonymization entirely
  const techMatches = TECHNICAL_KEYWORDS.filter(kw => lower.includes(kw));
  if (techMatches.length >= 2) {
    console.log(`🟢 Intent: TECHNICAL — matched keywords: ${techMatches.slice(0, 3).join(", ")}`);
    return "TECHNICAL";
  }

  // Short prompts with no personal signals and no tech = AMBIGUOUS
  console.log("🟡 Intent: AMBIGUOUS — running NER with strict thresholds");
  return "AMBIGUOUS";
}

// ─────────────────────────────────────────────
// STEP 2 — CONTEXT SENSITIVITY SCORER
// Runs AFTER NER. Decides if each entity is truly sensitive.
// ─────────────────────────────────────────────

// Well-known public figures, brands, places that should never be forged
const PUBLIC_ENTITY_WHITELIST = new Set([
  // Tech companies & products
  "google", "microsoft", "apple", "amazon", "facebook", "twitter", "meta",
  "openai", "anthropic", "nvidia", "intel", "amd", "linux", "windows",
  "python", "javascript", "react", "angular", "node", "docker",
  // Historical / public figures
  "einstein", "newton", "shakespeare", "gandhi", "tesla", "darwin",
  "aristotle", "plato", "socrates", "napoleon", "lincoln", "churchill",
  // Countries, major cities (generic references)
  "india", "usa", "london", "paris", "tokyo", "berlin", "china",
  "new york", "los angeles", "silicon valley", "bangalore", "chennai",
  // Months, days (BERT sometimes tags these as entities)
  "january", "february", "march", "april", "may", "june",
  "july", "august", "september", "october", "november", "december",
  "monday", "tuesday", "wednesday", "thursday", "friday", "saturday", "sunday"
]);

// Patterns that look like numbers but are NOT personal data
const TECHNICAL_NUMBER_PATTERNS = [
  /^\d+\.\d+(\.\d+)?$/,      // version numbers: 3.11, 2.0.1
  /^\d{1,5}$/,                // port numbers, small counts (handled by range check below)
  /^0x[0-9a-fA-F]+$/,        // hex
  /^\d+px$/, /^\d+rem$/,     // CSS units
  /^\d+ms$/, /^\d+s$/        // time units
];

// Confidence thresholds — only anonymize above these
const CONFIDENCE_THRESHOLDS = {
  PER: 0.85,   // names need high confidence — too many false positives
  LOC: 0.80,
  ORG: 0.75,
  EMAIL: 0.50, // regex-detected, always reliable
  PHONE: 0.50,
  AGE: 0.80,
  DEFAULT: 0.85
};

function scoreSensitivity(entity, fullText) {
  const word = entity.word.toLowerCase().trim();
  const label = entity.label;
  const score = entity.score || 0;

  // 1. Confidence threshold gate
  const threshold = CONFIDENCE_THRESHOLDS[label] || CONFIDENCE_THRESHOLDS.DEFAULT;
  if (score < threshold) {
    console.log(`⬇️ Dropped "${entity.word}" (${label}) — score ${score.toFixed(2)} below threshold ${threshold}`);
    return false;
  }

  // 2. Public entity whitelist
  if (PUBLIC_ENTITY_WHITELIST.has(word)) {
    console.log(`⬇️ Dropped "${entity.word}" — public entity whitelist`);
    return false;
  }

  // 3. For PERSON entities — check if it's a public/historical figure
  // heuristic: if the name appears without any personal context signal nearby, skip
  if (label === "PER") {
    const hasPersonalContext = PERSONAL_SIGNALS.some(sig =>
      fullText.toLowerCase().includes(sig)
    );
    if (!hasPersonalContext) {
      // Check if the name is followed by a title that suggests it's a real person
      // being discussed (like "Einstein discovered..." vs "my name is Anuja")
      const nameInContext = new RegExp(
        `(my name is|i am|i'm|contact|email|call|text)\\s+${word}`,
        "i"
      ).test(fullText);
      if (!nameInContext) {
        console.log(`⬇️ Dropped PER "${entity.word}" — no personal context around it`);
        return false;
      }
    }
  }

  // 4. For numeric entities — check if it's a version/port/index
  if (label === "AGE" || (entity.word.match(/^\d/))) {
    for (const techPattern of TECHNICAL_NUMBER_PATTERNS) {
      if (techPattern.test(entity.word)) {
        console.log(`⬇️ Dropped numeric "${entity.word}" — matches technical pattern`);
        return false;
      }
    }
    // Port number range (1–65535) without personal context = skip
    const num = parseInt(entity.word);
    if (!isNaN(num) && num >= 1 && num <= 65535) {
      const hasAgeContext = /(age|years old|born|dob)/i.test(fullText);
      if (!hasAgeContext) {
        console.log(`⬇️ Dropped number "${entity.word}" — looks like port/count, no age context`);
        return false;
      }
    }
  }

  // 5. For LOC entities — check if it's a generic place reference vs personal address
  if (label === "LOC") {
    const hasAddressContext = /(i live|my address|i'm from|i am from|i stay|my home)/i.test(fullText);
    if (!hasAddressContext) {
      console.log(`⬇️ Dropped LOC "${entity.word}" — no address context`);
      return false;
    }
  }

  console.log(`✅ Keeping "${entity.word}" (${label}) — score ${score.toFixed(2)}, passed all checks`);
  return true;
}

// ─────────────────────────────────────────────
// REALISTIC DATA POOLS FOR FORGERY
// ─────────────────────────────────────────────

const FORGERY_POOLS = {
  names: {
    first: ["James", "Mary", "Robert", "Patricia", "John", "Jennifer", "Michael", "Linda", "David", "Elizabeth"],
    last: ["Smith", "Johnson", "Williams", "Brown", "Jones", "Garcia", "Miller", "Davis", "Rodriguez", "Martinez"]
  },
  domains: ["gmail.com", "yahoo.com", "outlook.com", "hotmail.com", "protonmail.com"],
  companies: ["TechCorp", "DataInc", "SystemsLLC", "InnovateCo", "SolutionsLtd", "GlobalTech"],
  cities: ["Springfield", "Riverside", "Franklin", "Georgetown", "Madison", "Salem"]
};

// ─────────────────────────────────────────────
// MAIN EXPORT
// ─────────────────────────────────────────────

export async function preprocess(text) {
  console.log("🎯 Privacy pipeline starting");
  console.log("📝 Original text:", text);

  // ── STEP 1: Classify intent ──────────────────
  const intent = classifyPromptIntent(text);

  if (intent === "TECHNICAL") {
    console.log(" TECHNICAL prompt — skipping all anonymization, passing through as-is");
    return text;
  }

  // ── STEP 2: Detect PII entities ──────────────────
  let entities = [];
  try {
    entities = await detectPIIWithOffscreen(text);
    console.log(" Raw entities detected:", entities.length);

    // Merge BERT subword tokens first
    entities = mergeSubwordTokens(entities);
    console.log(" After subword merge:", entities);
  } catch (e) {
    console.error(" BERT NER failed:", e);
    entities = [];
  }

  // For DIRECT_PII — always add regex-detected entities
  if (intent === "DIRECT_PII" || intent === "PERSONAL" || intent === "AMBIGUOUS") {
    const patternEntities = detectPatternBasedPII(text);
    entities = mergeEntities(entities, patternEntities);
    console.log("🔗 After merging pattern entities:", entities);
  }

  // ── STEP 3: Context sensitivity scoring ──────
  // Skip this strict filtering for DIRECT_PII (regex hits are always real)
  let sensitiveEntities;
  if (intent === "DIRECT_PII") {
    sensitiveEntities = entities; // trust regex detections fully
  } else {
    sensitiveEntities = entities.filter(ent => scoreSensitivity(ent, text));
  }

  console.log(`📊 Entities after sensitivity scoring: ${sensitiveEntities.length}/${entities.length} kept`);

  // ── STEP 4: Apply forgery + generalization ────
  let result = text;

  result = applyAttributeForgery(result, sensitiveEntities);
  console.log("🔄 After forgery:", result);

  // Only generalize if intent is PERSONAL or DIRECT_PII
  // AMBIGUOUS prompts get forgery but NOT aggressive number generalization
  if (intent === "PERSONAL" || intent === "DIRECT_PII") {
    result = applyGeneralization(result);
    console.log("📏 After generalization:", result);
  } else {
    // AMBIGUOUS: only generalize if clear personal data markers are present
    result = applySelectiveGeneralization(result, sensitiveEntities);
    console.log("📏 After selective generalization:", result);
  }

  console.log("✨ Final result:", result);
  return result;
}

// ─────────────────────────────────────────────
// FORGERY HELPERS (unchanged from your original)
// ─────────────────────────────────────────────

function applyAttributeForgery(text, entities) {
  let result = text;

  const freshEntities = entities.filter(ent => {
    const word = ent.word.toLowerCase();

    // Skip already forged/anonymized entities
    if (word.startsWith('dummy_') || word.startsWith('user_') ||
        word.startsWith('test_') || word.startsWith('sample_')) return false;
    if (word.includes('_')) return false;
    if (word.includes('(')) return false;
    if (word.startsWith('##')) return false;
    if (word.match(/^(under-18|18-24|25-34|35-44|45-54|55-64|65\+|small_number|medium_number|large_number|\$0-50k|\$50k-100k|\$100k-150k|\$150k\+|recent_date)$/)) return false;
    if (word.match(/^james|mary|robert|patricia|john|jennifer|michael|linda|david|elizabeth$/i)) return false;
    if (word.match(/^springfield|riverside|franklin|georgetown|madison|salem$/i)) return false;
    if (word.match(/^techcorp|datainc|systemsllc|innovateco|solutionsltd|globaltech$/i)) return false;

    // IMPORTANT: Handle both BERT and regex-detected entities
    // isBERT: false entities from regex fallback should still be forged
    // Only skip if explicitly marked as non-sensitive
    if (ent.isBERT === false && ent.method && ent.method.startsWith('pattern-')) {
      // These are regex-detected PII - always forge them
      return true;
    }

    return true;
  });

  freshEntities.forEach(ent => {
    // IMPORTANT: Handle both BERT and pattern-detected entities
    if (ent.isBERT || (ent.method && ent.method.startsWith('pattern-'))) {
      const forgedValue = forgeAttribute(ent);
      console.log(`🔁 Replacing "${ent.word}" → "${forgedValue}" (method: ${ent.method || 'BERT'})`);
      const regex = new RegExp(ent.word.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), 'gi');
      result = result.replace(regex, forgedValue);
    } else {
      console.log(`⚠️ Skipping entity "${ent.word}" - not BERT or pattern detected`);
    }
  });

  return result;
}

function forgeAttribute(entity) {
  switch (entity.label) {
    case "PER":   return forgeName(entity.word);
    case "EMAIL": return forgeEmail(entity.word);
    case "PHONE": return forgePhone(entity.word);
    case "LOC":   return forgeLocation(entity.word);
    case "ORG":   return forgeOrganization(entity.word);
    case "AGE":   return forgeAge(entity.word);
    case "SSN":   return forgeSSN(entity.word);
    default:      return forgeGeneric(entity.word);
  }
}

function forgeName(originalName) {
  const forgedFirst = FORGERY_POOLS.names.first[Math.floor(Math.random() * FORGERY_POOLS.names.first.length)];
  const forgedLast  = FORGERY_POOLS.names.last[Math.floor(Math.random() * FORGERY_POOLS.names.last.length)];
  return originalName.includes(' ') ? `${forgedFirst} ${forgedLast}` : forgedFirst;
}

function forgeEmail(originalEmail) {
  const id     = Math.floor(Math.random() * 9000) + 1000;
  const domain = FORGERY_POOLS.domains[Math.floor(Math.random() * FORGERY_POOLS.domains.length)];
  return `user_${id}@${domain}`;
}

function forgePhone(originalPhone) {
  const a = Math.floor(Math.random() * 900) + 100;
  const b = Math.floor(Math.random() * 900) + 100;
  const c = Math.floor(Math.random() * 9000) + 1000;
  return `(${a}) ${b}-${c}`;
}

function forgeLocation(originalLocation) {
  return FORGERY_POOLS.cities[Math.floor(Math.random() * FORGERY_POOLS.cities.length)];
}

function forgeOrganization(originalOrg) {
  return FORGERY_POOLS.companies[Math.floor(Math.random() * FORGERY_POOLS.companies.length)];
}

function forgeAge(originalAge) {
  const baseAge  = parseInt(originalAge) || 25;
  const variation = Math.floor(Math.random() * 10) - 5;
  return Math.max(18, Math.min(80, baseAge + variation)).toString();
}

function forgeSSN(original) {
  const id = Math.floor(Math.random() * 9000) + 1000;
  return `anon_${id}`;
}

function forgeGeneric(original) {
  return `dummy_${Math.floor(Math.random() * 9000) + 1000}`;
}

// ─────────────────────────────────────────────
// SUBWORD MERGE (unchanged from your original)
// ─────────────────────────────────────────────

function mergeSubwordTokens(entities) {
  const merged = [];
  let current = null;

  entities.forEach(ent => {
    if (ent.word.startsWith('##')) {
      if (current) {
        current.word  += ent.word.replace('##', '');
        current.score  = Math.max(current.score, ent.score || 0);
      }
    } else {
      if (current) merged.push(current);
      current = { ...ent, score: ent.score || 0 };
    }
  });

  if (current) merged.push(current);
  return merged;
}

// ─────────────────────────────────────────────
// PATTERN-BASED PII (FIXED — removed aggressive capitalized-word detection)
// ─────────────────────────────────────────────

function detectPatternBasedPII(text) {
  const entities = [];

  // Only detect "my name is X" — NOT all capitalized words
  const namePattern = /(?:my name is|i am|i'm called)\s+([A-Z][a-z]+(?:\s+[A-Z][a-z]+)?)/gi;
  let match;
  while ((match = namePattern.exec(text)) !== null) {
    entities.push({ word: match[1], label: "PER", score: 0.92, method: "pattern-name", confidence: 0.92 });
  }

  // Email
  const emailPattern = /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b/g;
  while ((match = emailPattern.exec(text)) !== null) {
    entities.push({ word: match[0], label: "EMAIL", score: 0.99, method: "pattern-email", confidence: 0.99 });
  }

  // Phone (Indian + US)
  const phonePattern = /\b(\+91[\-\s]?)?[6-9]\d{9}\b|\b(\+1[\-\s]?)?\(?\d{3}\)?[\-\s]?\d{3}[\-\s]?\d{4}\b/g;
  while ((match = phonePattern.exec(text)) !== null) {
    entities.push({ word: match[0], label: "PHONE", score: 0.99, method: "pattern-phone", confidence: 0.99 });
  }

  // Aadhaar
  const aadhaarPattern = /\b[2-9]{1}[0-9]{3}\s[0-9]{4}\s[0-9]{4}\b/g;
  while ((match = aadhaarPattern.exec(text)) !== null) {
    entities.push({ word: match[0], label: "AADHAAR", score: 0.99, method: "pattern-aadhaar", confidence: 0.99 });
  }

  // PAN card
  const panPattern = /\b[A-Z]{5}[0-9]{4}[A-Z]{1}\b/g;
  while ((match = panPattern.exec(text)) !== null) {
    entities.push({ word: match[0], label: "PAN", score: 0.99, method: "pattern-pan", confidence: 0.99 });
  }

  // SSN
  const ssnPattern = /\b\d{3}-\d{2}-\d{4}\b/g;
  while ((match = ssnPattern.exec(text)) !== null) {
    entities.push({ word: match[0], label: "SSN", score: 0.99, method: "pattern-ssn", confidence: 0.99 });
  }

  return entities;
}

function mergeEntities(bertEntities, patternEntities) {
  const merged = [...bertEntities];
  patternEntities.forEach(patternEnt => {
    const exists = merged.some(e => e.word.toLowerCase() === patternEnt.word.toLowerCase());
    if (!exists) merged.push(patternEnt);
  });
  return merged;
}

// ─────────────────────────────────────────────
// GENERALIZATION (FIXED — only runs on personal prompts)
// ─────────────────────────────────────────────

// Full generalization — for PERSONAL / DIRECT_PII prompts
function applyGeneralization(text) {
  let result = text;
  result = generalizeAges(result);
  result = generalizeDates(result);
  result = generalizeMoney(result);
  // NOTE: generalizeNumbers removed from here — too aggressive for general use
  return result;
}

// Selective generalization — for AMBIGUOUS prompts
// Only generalizes something if a related sensitive entity was actually found
function applySelectiveGeneralization(text, sensitiveEntities) {
  let result = text;
  const labels = new Set(sensitiveEntities.map(e => e.label));

  if (labels.has("AGE")) result = generalizeAges(result);
  if (labels.has("EMAIL") || labels.has("PHONE") || labels.has("PER")) result = generalizeDates(result);

  return result;
}

function generalizeAges(text) {
  return text.replace(/\b(\d{1,2})\b(?=\s*(?:years?|yrs?)?\s*(?:old|age)?)/gi, (match, age) => {
    const n = parseInt(age);
    if (n < 18) return "under-18";
    if (n < 25) return "18-24";
    if (n < 35) return "25-34";
    if (n < 45) return "35-44";
    if (n < 55) return "45-54";
    if (n < 65) return "55-64";
    return "65+";
  });
}

function generalizeDates(text) {
  return text
    .replace(/\b\d{4}-\d{2}-\d{2}\b/g, "recent_date")
    .replace(/\b\d{1,2}\/\d{1,2}\/\d{4}\b/g, "recent_date")
    .replace(/\b(January|February|March|April|May|June|July|August|September|October|November|December)\s+\d{1,2},?\s+\d{4}\b/gi, "recent_date");
}

function generalizeMoney(text) {
  // Matches $85,000 or $85000 or $1,234,567.89
  const result = text.replace(/\$\d{1,3}(?:,\d{3})*(?:\.\d{1,2})?/g, match => {
    const amount = parseFloat(match.replace(/[$,]/g, ''));
    if (amount < 50_000)  return "SALARY_0_50K";
    if (amount < 100_000) return "SALARY_50K_100K";
    if (amount < 150_000) return "SALARY_100K_150K";
    return "SALARY_150K_PLUS";
  });
  // DEBUG: Log what generalizeMoney is doing
  console.log("📏 generalizeMoney:", {input: text, output: result});
  return result;
}