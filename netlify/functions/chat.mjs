import { createPublicKey, verify as verifySignature } from "node:crypto";

const PROJECT_ID = "drovix";
const ALLOWED_ORIGIN = "https://drovix.netlify.app";
const GOOGLE_KEYS_URL =
  "https://www.googleapis.com/service_accounts/v1/jwk/securetoken@system.gserviceaccount.com";

function json(statusCode, body) {
  return {
    statusCode,
    headers: {
      "Content-Type": "application/json; charset=utf-8",
      "Cache-Control": "no-store",
      "Access-Control-Allow-Origin": ALLOWED_ORIGIN,
      "Access-Control-Allow-Headers": "Content-Type, Authorization",
      "Access-Control-Allow-Methods": "POST, OPTIONS",
      "Vary": "Origin"
    },
    body: JSON.stringify(body)
  };
}

async function verifyFirebaseIdToken(token) {
  const parts = token.split(".");
  if (parts.length !== 3) throw new Error("Invalid token");

  const header = JSON.parse(Buffer.from(parts[0], "base64url").toString("utf8"));
  const claims = JSON.parse(Buffer.from(parts[1], "base64url").toString("utf8"));
  if (header.alg !== "RS256" || !header.kid) throw new Error("Invalid token header");

  const keysResponse = await fetch(GOOGLE_KEYS_URL);
  if (!keysResponse.ok) throw new Error("Could not retrieve Firebase signing keys");
  const keySet = await keysResponse.json();
  const jwk = keySet.keys?.find((key) => key.kid === header.kid);
  if (!jwk) throw new Error("Unknown signing key");

  const publicKey = createPublicKey({ key: jwk, format: "jwk" });
  const validSignature = verifySignature(
    "RSA-SHA256",
    Buffer.from(parts[0] + "." + parts[1]),
    publicKey,
    Buffer.from(parts[2], "base64url")
  );

  const now = Math.floor(Date.now() / 1000);
  if (
    !validSignature ||
    claims.aud !== PROJECT_ID ||
    claims.iss !== "https://securetoken.google.com/" + PROJECT_ID ||
    typeof claims.sub !== "string" ||
    claims.sub.length === 0 ||
    !claims.exp ||
    claims.exp <= now ||
    !claims.iat ||
    claims.iat > now + 300
  ) {
    throw new Error("Invalid or expired Firebase token");
  }
  return claims;
}

export const handler = async (event) => {
  const origin = event.headers?.origin || event.headers?.Origin || "";
  if (origin !== ALLOWED_ORIGIN) return json(403, { error: "Origin not allowed" });

  if (event.httpMethod === "OPTIONS") {
    return {
      statusCode: 204,
      headers: {
        "Access-Control-Allow-Origin": ALLOWED_ORIGIN,
        "Access-Control-Allow-Headers": "Content-Type, Authorization",
        "Access-Control-Allow-Methods": "POST, OPTIONS",
        "Vary": "Origin"
      },
      body: ""
    };
  }
  if (event.httpMethod !== "POST") return json(405, { error: "Method not allowed" });
  if (!process.env.GROQ_API_KEY) {
    return json(500, { error: "AI service is not configured yet." });
  }

  const authHeader = event.headers?.authorization || event.headers?.Authorization || "";
  const match = authHeader.match(/^Bearer\s+(.+)$/i);
  if (!match) return json(401, { error: "Please sign in before using AI chat." });

  try {
    await verifyFirebaseIdToken(match[1]);
  } catch {
    return json(401, { error: "Your session is invalid or expired. Please sign in again." });
  }

  let body;
  try {
    body = JSON.parse(event.body || "{}");
  } catch {
    return json(400, { error: "Invalid JSON request." });
  }

  if (!Array.isArray(body.messages) || body.messages.length < 1 || body.messages.length > 20) {
    return json(400, { error: "Send between 1 and 20 recent messages." });
  }

  const messages = body.messages
    .filter((item) => item && ["user", "assistant"].includes(item.role) && typeof item.content === "string")
    .map((item) => ({ role: item.role, content: item.content.trim().slice(0, 4000) }))
    .filter((item) => item.content);

  if (!messages.length || messages[messages.length - 1].role !== "user") {
    return json(400, { error: "The last message must be a user message." });
  }
  if (messages.reduce((sum, item) => sum + item.content.length, 0) > 12000) {
    return json(413, { error: "This conversation is too long. Please start a new chat." });
  }

  try {
    const groqResponse = await fetch("https://api.groq.com/openai/v1/chat/completions", {
      method: "POST",
      headers: {
        "Authorization": "Bearer " + process.env.GROQ_API_KEY,
        "Content-Type": "application/json"
      },
      body: JSON.stringify({
        model: process.env.GROQ_MODEL || "openai/gpt-oss-20b",
        messages: [
          {
            role: "system",
            content: "You are Laud, a helpful, natural conversational AI. Answer directly in clear, readable Markdown. Avoid decorative stars, excessive headings, unnecessary horizontal rules, and tables unless a table genuinely makes the answer clearer. Prefer short paragraphs and useful bullet lists. Complete the requested answer; if the topic is broad, prioritize the most useful details and offer to continue only when necessary. If uncertain, say so."
          },
          ...messages
        ],
        temperature: 0.7,
        max_tokens: 2048
      })
    });

    const result = await groqResponse.json().catch(() => ({}));
    if (!groqResponse.ok) {
      console.error("Groq request failed with status", groqResponse.status);
      return json(502, { error: "The AI provider could not complete that request. Please try again." });
    }

    const answer = result.choices?.[0]?.message?.content;
    if (typeof answer !== "string" || !answer.trim()) {
      return json(502, { error: "The AI provider returned an empty response." });
    }
    return json(200, { reply: answer.trim(), truncated: result.choices?.[0]?.finish_reason === "length" });
  } catch (error) {
    console.error("Chat function error:", error?.message || "Unknown error");
    return json(502, { error: "Could not reach the AI service. Please try again shortly." });
  }
};
