// ProofLink Verifier × Express — a receipt-verification microservice.
//
//   npm i @itechsmart/prooflink-verifier express
//   node server.js
//   curl http://localhost:3000/verify/107453ec5eadf445
//   curl http://localhost:3000/chain
//
// "Don't trust — verify." Every check runs locally against the public ledger;
// no account, no secrets.

const express = require("express");
const { fetchAndVerifyReceipt, fetchAndVerifyChain } = require("@itechsmart/prooflink-verifier");

const app = express();

// Verify one receipt by id or hash prefix.
app.get("/verify/:id", async (req, res) => {
  try {
    const result = await fetchAndVerifyReceipt(req.params.id);
    res.status(result.valid ? 200 : 422).json({
      receipt_id: req.params.id,
      valid: result.valid,
      checks: result.checks,
      verify_url: `https://verify.itechsmart.dev/${req.params.id}`,
    });
  } catch (e) {
    res.status(404).json({ error: e.message });
  }
});

// Verify pointer-linkage of the newest N receipts on the public chain.
app.get("/chain", async (_req, res) => {
  const r = await fetchAndVerifyChain(Number(_req.query.limit) || 25);
  res.status(r.chain_valid ? 200 : 422).json(r);
});

// Middleware pattern: gate an action on a caller-supplied receipt being valid.
function requireValidReceipt(header = "x-prooflink-receipt") {
  return async (req, res, next) => {
    const id = req.get(header);
    if (!id) return res.status(400).json({ error: `missing ${header}` });
    const r = await fetchAndVerifyReceipt(id).catch(() => ({ valid: false }));
    if (!r.valid) return res.status(403).json({ error: "receipt failed verification" });
    next();
  };
}

app.post("/protected", requireValidReceipt(), (_req, res) =>
  res.json({ ok: true, note: "action allowed — caller presented a verified ProofLink receipt" }),
);

app.listen(3000, () => console.log("ProofLink verifier service on :3000"));
module.exports = { requireValidReceipt };
