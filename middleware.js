const { verifyAdminToken } = require("./security");

function requireAdmin(req, res, next) {
  const token = req.cookies?.admin_token;
  if (!token) return res.status(401).json({ error: "يلزم تسجيل الدخول" });
  try {
    req.admin = verifyAdminToken(token);
    return next();
  } catch {
    res.clearCookie("admin_token");
    return res.status(401).json({ error: "انتهت الجلسة، سجّل الدخول مجددًا" });
  }
}

module.exports = { requireAdmin };
