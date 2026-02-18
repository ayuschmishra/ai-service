const express = require("express");
const app = express();
app.use(express.json());

// --- SECURITY PATTERNS ---
// These are the "red flag" phrases we watch for.
// Think of these as the security guard's checklist.
const INJECTION_PATTERNS = [
    // Trying to override the AI's rules
    /ignore\s+(all\s+)?(previous|prior|above)\s+instructions?/i,
    /forget\s+(your|all)\s+(instructions?|rules?|training)/i,
    /override\s+(system|safety|all)\s*(rules?|instructions?|prompts?)?/i,
    /disregard\s+(all\s+)?(previous|prior)\s+instructions?/i,
    /you\s+are\s+now\s+in\s+developer\s+mode/i,

    // Trying to see secret system prompts
    /reveal\s+(your\s+)?(system\s+)?prompt/i,
    /show\s+(me\s+)?(your\s+)?(system\s+)?prompt/i,
    /what\s+(are\s+)?(your|the)\s+(system\s+)?(instructions?|prompt)/i,
    /print\s+(your\s+)?(system\s+)?prompt/i,

    // Trying to make the AI pretend to be something else
    /act\s+as\s+(if\s+)?(you\s+are\s+)?(an?\s+)?(unrestricted|jailbroken|evil|dan)/i,
    /pretend\s+(you\s+are|to\s+be)\s+(an?\s+)?(ai\s+without|unrestricted)/i,
    /roleplay\s+as\s+(an?\s+)?(unrestricted|evil|unfiltered)/i,
    /you\s+are\s+now\s+(an?\s+)?(unrestricted|evil|jailbroken|dan)/i,

    // Classic jailbreak phrases
    /jailbreak/i,
    /do\s+anything\s+now/i, // "DAN" attacks
    /ignore\s+(all\s+)?safety/i,
    /bypass\s+(all\s+)?(filters?|restrictions?|safety)/i,
];

// --- RATE LIMITING ---
// Prevent one user from spamming the endpoint
const rateLimitMap = new Map(); // stores { count, firstRequest } per userId
const RATE_LIMIT = 10; // max requests
const RATE_WINDOW = 60 * 1000; // per 60 seconds

function checkRateLimit(userId) {
    const now = Date.now();
    const userData = rateLimitMap.get(userId);

    if (!userData || now - userData.firstRequest > RATE_WINDOW) {
        // First request or window expired — reset
        rateLimitMap.set(userId, { count: 1, firstRequest: now });
        return { limited: false };
    }

    if (userData.count >= RATE_LIMIT) {
        return { limited: true };
    }

    userData.count++;
    return { limited: false };
}

// --- SECURITY LOG ---
// In a real app this would go to a database or logging service
const securityLog = [];

function logEvent(userId, input, result) {
    const event = {
        timestamp: new Date().toISOString(),
        userId,
        input: input.substring(0, 200), // Don't log huge inputs
        blocked: result.blocked,
        reason: result.reason,
    };
    securityLog.push(event);
    console.log("[SECURITY EVENT]", JSON.stringify(event));
}

// --- CORE VALIDATION FUNCTION ---
// This is the heart of the security guard logic
function validateInput(input) {
    // 1. Basic checks
    if (!input || typeof input !== "string") {
        return {
            blocked: true,
            reason: "Invalid input format",
            confidence: 1.0,
        };
    }

    if (input.trim().length === 0) {
        return {
            blocked: true,
            reason: "Empty input",
            confidence: 1.0,
        };
    }

    if (input.length > 5000) {
        return {
            blocked: true,
            reason: "Input exceeds maximum length",
            confidence: 1.0,
        };
    }

    // 2. Check against injection patterns
    // Count how many red flags are triggered
    let matchedPatterns = [];
    for (const pattern of INJECTION_PATTERNS) {
        if (pattern.test(input)) {
            matchedPatterns.push(pattern.toString());
        }
    }

    if (matchedPatterns.length > 0) {
        // More pattern matches = higher confidence it's an attack
        const confidence = Math.min(
            0.7 + matchedPatterns.length * 0.1,
            1.0
        ).toFixed(2);
        return {
            blocked: true,
            reason: "Prompt injection attempt detected",
            confidence: parseFloat(confidence),
        };
    }

    // 3. All checks passed!
    return {
        blocked: false,
        reason: "Input passed all security checks",
        confidence: 0.95,
    };
}

// --- SANITIZE OUTPUT ---
// Even if the AI responds, clean up anything dangerous
function sanitizeOutput(text) {
    if (!text) return "";
    return text
        .replace(/<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi, "") // Remove <script> tags
        .replace(/on\w+="[^"]*"/gi, "") // Remove inline JS handlers like onclick="..."
        .replace(/javascript:/gi, "") // Remove javascript: URLs
        .replace(/<iframe[^>]*>.*?<\/iframe>/gi, "") // Remove iframes
        .trim();
}

// --- THE MAIN ENDPOINT ---
app.post("/validate", (req, res) => {
    try {
        const { userId, input, category } = req.body;

        // Validate the request body itself
        if (!userId || !input || !category) {
            return res.status(400).json({
                error: "Missing required fields: userId, input, category",
            });
        }

        // Check rate limit first
        const rateCheck = checkRateLimit(userId);
        if (rateCheck.limited) {
            return res.status(429).json({
                blocked: true,
                reason: "Rate limit exceeded. Please try again later.",
                confidence: 1.0,
            });
        }

        // Run security validation
        const validationResult = validateInput(input);

        // Log the security event
        logEvent(userId, input, validationResult);

        // If blocked, return 200 with blocked:true (it's not an error, just blocked)
        if (validationResult.blocked) {
            return res.status(200).json({
                blocked: true,
                reason: validationResult.reason,
                sanitizedOutput: null,
                confidence: validationResult.confidence,
            });
        }

        // If allowed, simulate a sanitized AI output
        // (In real life, you'd call OpenAI/Claude here and sanitize the response)
        const simulatedAiResponse = `This is a safe AI response to: "${input}"`;
        const sanitized = sanitizeOutput(simulatedAiResponse);

        return res.status(200).json({
            blocked: false,
            reason: validationResult.reason,
            sanitizedOutput: sanitized,
            confidence: validationResult.confidence,
        });
    } catch (err) {
        // IMPORTANT: Don't leak internal error details to the user!
        console.error("Internal error:", err);
        return res.status(500).json({
            error: "An internal error occurred",
        });
    }
});

// Optional: endpoint to check logs (for development only!)
app.get("/logs", (req, res) => {
    res.json(securityLog);
});

// Start the server
const PORT = 3000;
app.listen(PORT, () => {
    console.log(`SecureAI server running on port ${PORT}`);
});