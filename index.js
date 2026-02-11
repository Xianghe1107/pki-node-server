import express from "express";
import crypto from "crypto";

const app = express();
app.use(express.json({ limit: "2mb" }));

// id -> { id, name, publicKeyBase64, updatedAt }
const participants = new Map();

// id -> { challenge, expiresAt }
const challenges = new Map();

function nowIso() {
  return new Date().toISOString();
}

function issueChallenge(id, ttlSeconds = 300) {
  const challenge = crypto.randomUUID() + "-" + Date.now();
  challenges.set(id, { challenge, expiresAt: Date.now() + ttlSeconds * 1000 });
  return { ok: true, id, challenge, ttlSeconds };
}

function getActiveChallenge(id) {
  const item = challenges.get(id);
  if (!item) return null;
  if (Date.now() > item.expiresAt) {
    challenges.delete(id);
    return null;
  }
  return item.challenge;
}

function publicKeyFromBase64Spki(publicKeyBase64) {
  const der = Buffer.from(publicKeyBase64, "base64"); // X.509 SPKI DER
  return crypto.createPublicKey({ key: der, format: "der", type: "spki" });
}

// Health check (optional)
app.get("/", (req, res) => res.send("PKI Node Server OK"));

app.post("/register", (req, res) => {
  const { id, name, publicKeyBase64 } = req.body || {};
  if (!id || !name || !publicKeyBase64) return res.json({ ok: false, error: "missing fields" });

  participants.set(String(id), {
    id: String(id),
    name: String(name),
    publicKeyBase64: String(publicKeyBase64).trim(),
    updatedAt: nowIso()
  });

  return res.json({ ok: true, count: participants.size });
});

app.get("/challenge", (req, res) => {
  const id = String(req.query.id || "").trim();
  if (!id) return res.json({ ok: false, error: "missing id" });
  return res.json(issueChallenge(id, 300));
});

app.post("/verify", (req, res) => {
  const { id, challenge, signatureBase64 } = req.body || {};
  const userId = String(id || "").trim();
  const receivedChallenge = String(challenge || ""); // 不要trim
  const sigB64 = String(signatureBase64 || "").trim();

  if (!userId || !receivedChallenge || !sigB64) return res.json({ ok: false, error: "missing fields" });

  const p = participants.get(userId);
  if (!p) return res.json({ ok: false, error: "unknown user" });

  const expected = getActiveChallenge(userId);
  if (!expected) return res.json({ ok: false, error: "challenge expired or missing" });
  if (expected !== receivedChallenge) return res.json({ ok: false, error: "challenge mismatch" });

  try {
    const pubKey = publicKeyFromBase64Spki(p.publicKeyBase64);
    const signature = Buffer.from(sigB64, "base64");
    const data = Buffer.from(receivedChallenge, "utf8");

    const verified = crypto.verify("RSA-SHA256", data, pubKey, signature);

    // one-time challenge 防重放
    challenges.delete(userId);

    return res.json({ ok: verified });
  } catch (err) {
    return res.json({ ok: false, error: String(err) });
  }
});

// Render 会提供 PORT 环境变量：必须用它
const PORT = process.env.PORT || 8080;
app.listen(PORT, () => console.log(`PKI server running on port ${PORT}`));
