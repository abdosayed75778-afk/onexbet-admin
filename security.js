const crypto = require("node:crypto");
const jwt = require("jsonwebtoken");

function hashCode(code) {
  return crypto.createHash("sha256").update(code.trim().toUpperCase()).digest("hex");
}

function generateCode() {
  // Human-readable alphabet omits confusing characters such as 0/O and 1/I.
  const alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
  const bytes = crypto.randomBytes(20);
  let body = "";
  for (let i = 0; i < 20; i++) body += alphabet[bytes[i] % alphabet.length];
  return `XB-${body.match(/.{1,5}/g).join("-")}`;
}

function signAdmin(admin) {
  return jwt.sign(
    { sub: admin.id, email: admin.email, role: "admin" },
    process.env.JWT_SECRET,
    { expiresIn: "8h", issuer: "onexbet-admin", audience: "onexbet-admin-ui" }
  );
}

function verifyAdminToken(token) {
  return jwt.verify(token, process.env.JWT_SECRET, {
    issuer: "onexbet-admin",
    audience: "onexbet-admin-ui",
  });
}

module.exports = { hashCode, generateCode, signAdmin, verifyAdminToken };
