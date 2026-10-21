import { createPublicKey, createSign, verify as verifySignature } from "node:crypto";

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

let serviceTokenCache = { token: "", expiresAt: 0 };

function base64url(value) {
  return Buffer.from(value).toString("base64url");
}

async function getServiceAccessToken() {
  if (serviceTokenCache.token && serviceTokenCache.expiresAt > Date.now() + 60000) return serviceTokenCache.token;
  if (!process.env.FIREBASE_SERVICE_ACCOUNT_JSON) {
    throw new Error("FIREBASE_SERVICE_ACCOUNT_JSON is not configured");
  }
  const account = JSON.parse(process.env.FIREBASE_SERVICE_ACCOUNT_JSON);
  if (!account.client_email || !account.private_key) throw new Error("Service account JSON is missing required fields");
  const now = Math.floor(Date.now() / 1000);
  const header = base64url(JSON.stringify({ alg: "RS256", typ: "JWT" }));
  const claim = base64url(JSON.stringify({
    iss: account.client_email,
    scope: "https://www.googleapis.com/auth/datastore",
    aud: "https://oauth2.googleapis.com/token",
    iat: now,
    exp: now + 3600
  }));
  const unsigned = header + "." + claim;
  const signer = createSign("RSA-SHA256");
  signer.update(unsigned);
  signer.end();
  const assertion = unsigned + "." + signer.sign(account.private_key).toString("base64url");
  const response = await fetch("https://oauth2.googleapis.com/token", {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      grant_type: "urn:ietf:params:oauth:grant-type:jwt-bearer",
      assertion
    })
  });
  const result = await response.json().catch(() => ({}));
  if (!response.ok || !result.access_token) throw new Error("Could not obtain Firestore service access");
  serviceTokenCache = { token: result.access_token, expiresAt: Date.now() + Number(result.expires_in || 3600) * 1000 };
  return serviceTokenCache.token;
}

function firestoreBase() {
  return "https://firestore.googleapis.com/v1/projects/" + PROJECT_ID + "/databases/(default)/documents";
}

async function firestoreRequest(path, options = {}) {
  const token = await getServiceAccessToken();
  const response = await fetch(firestoreBase() + path, {
    ...options,
    headers: {
      "Authorization": "Bearer " + token,
      "Content-Type": "application/json",
      ...(options.headers || {})
    }
  });
  const data = await response.json().catch(() => ({}));
  if (!response.ok) {
    const error = new Error(data.error?.message || "Firestore request failed");
    error.status = response.status;
    error.data = data;
    throw error;
  }
  return data;
}

function fieldValue(field) {
  if (!field) return undefined;
  if (field.integerValue !== undefined) return Number(field.integerValue);
  if (field.doubleValue !== undefined) return Number(field.doubleValue);
  if (field.stringValue !== undefined) return field.stringValue;
  if (field.booleanValue !== undefined) return field.booleanValue;
  if (field.mapValue) {
    const output = {};
    for (const [key, value] of Object.entries(field.mapValue.fields || {})) output[key] = fieldValue(value);
    return output;
  }
  return undefined;
}

function documentFields(doc) {
  const output = {};
  for (const [key, value] of Object.entries(doc?.fields || {})) output[key] = fieldValue(value);
  return output;
}

function firestoreFields(values) {
  const fields = {};
  for (const [key, value] of Object.entries(values)) {
    if (typeof value === "number") fields[key] = { integerValue: String(Math.trunc(value)) };
    else fields[key] = { stringValue: String(value) };
  }
  return fields;
}

async function reserveDailyUsage(uid) {
  const date = new Intl.DateTimeFormat("en-CA", { timeZone: "Africa/Nairobi", year: "numeric", month: "2-digit", day: "2-digit" }).format(new Date());
  const usagePath = "/users/" + encodeURIComponent(uid) + "/usage/" + date;
  const userPath = "/users/" + encodeURIComponent(uid);
  const settingsPath = "/appSettings/global";

  for (let attempt = 0; attempt < 3; attempt++) {
    const transactionResult = await firestoreRequest(":beginTransaction", {
      method: "POST",
      body: JSON.stringify({ options: { readWrite: {} } })
    });
    const transaction = transactionResult.transaction;
    const query = "?transaction=" + encodeURIComponent(transaction);
    let settingsDoc, userDoc, usageDoc;
    try {
      [settingsDoc, userDoc, usageDoc] = await Promise.all([
        firestoreRequest(settingsPath + query).catch(error => error.status === 404 ? null : Promise.reject(error)),
        firestoreRequest(userPath + query).catch(error => error.status === 404 ? null : Promise.reject(error)),
        firestoreRequest(usagePath + query).catch(error => error.status === 404 ? null : Promise.reject(error))
      ]);
    } catch (error) {
      console.error("Could not read daily usage records", error.message);
      throw new Error("Could not verify your daily usage. Please try again.");
    }

    const settings = documentFields(settingsDoc);
    const profile = documentFields(userDoc);
    const usage = documentFields(usageDoc);
    if (profile.accountStatus === "banned") throw new Error("Your account is banned. Contact support.");
    if (profile.accountStatus === "restricted" && profile.customLimits && Number(profile.customLimits.messagesPerDay) >= 0) {
      const restrictedLimit = Number(profile.customLimits.messagesPerDay);
      if (Number(usage.messageCount || 0) >= restrictedLimit) throw new Error("Your account has reached its daily message limit.");
    } else if (String(profile.plan || "free").toLowerCase() === "free") {
      const dailyLimit = Number(settings.freeDailyMessages ?? 50);
      if (Number(usage.messageCount || 0) >= dailyLimit) throw new Error("You have reached today's free message limit. Please try again tomorrow.");
    }

    const nextUsage = {
      day: date,
      messageCount: Number(usage.messageCount || 0) + 1,
      apiCalls: Number(usage.apiCalls || 0) + 1
    };
    const write = {
      update: {
        name: "projects/" + PROJECT_ID + "/databases/(default)/documents" + usagePath,
        fields: firestoreFields(nextUsage)
      },
      updateMask: { fieldPaths: ["day", "messageCount", "apiCalls"] },
      currentDocument: usageDoc?.updateTime ? { updateTime: usageDoc.updateTime } : { exists: false }
    };
    try {
      await firestoreRequest(":commit", {
        method: "POST",
        body: JSON.stringify({ writes: [write], transaction })
      });
      return { date, ...nextUsage, plan: profile.plan || "free" };
    } catch (error) {
      if (attempt < 2 && (error.status === 409 || /ABORTED|transaction/i.test(error.message))) continue;
      console.error("Could not save daily usage", error.message);
      throw new Error("Could not record your usage securely. Please try again.");
    }
  }
  throw new Error("Your usage could not be checked. Please try again.");
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

  let claims;
  try {
    claims = await verifyFirebaseIdToken(match[1]);
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

  const requestStartedAt = Date.now();
  let usageDurationMs = 0;
  let groqDurationMs = 0;
  try {
    try {
      const usageStartedAt = Date.now();
      await reserveDailyUsage(claims.sub);
      usageDurationMs = Date.now() - usageStartedAt;
    } catch (usageError) {
      if (/FIREBASE_SERVICE_ACCOUNT_JSON/.test(usageError.message)) {
        return json(503, { error: "The AI service is waiting for secure usage tracking to be configured by the administrator." });
      }
      return json(usageError.message.includes("reached today's") || usageError.message.includes("daily message limit") || usageError.message.includes("banned") ? 429 : 503, { error: usageError.message || "Could not verify your daily usage." });
    }
    const groqStartedAt = Date.now();
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

    groqDurationMs = Date.now() - groqStartedAt;
    const result = await groqResponse.json().catch(() => ({}));
    if (!groqResponse.ok) {
      console.error("Groq request failed with status", groqResponse.status);
      return json(502, { error: "The AI provider could not complete that request. Please try again." });
    }

    const answer = result.choices?.[0]?.message?.content;
    if (typeof answer !== "string" || !answer.trim()) {
      return json(502, { error: "The AI provider returned an empty response." });
    }
    console.info("Chat timing ms", { usage: usageDurationMs, groq: groqDurationMs, total: Date.now() - requestStartedAt });
    return json(200, { reply: answer.trim(), truncated: result.choices?.[0]?.finish_reason === "length" });
  } catch (error) {
    console.error("Chat function error:", error?.message || "Unknown error");
    return json(502, { error: "Could not reach the AI service. Please try again shortly." });
  }
};
