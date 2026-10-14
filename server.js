require("dotenv").config();

const express = require("express");
const helmet = require("helmet");
const cookieParser = require("cookie-parser");
const rateLimit = require("express-rate-limit");
const bcrypt = require("bcryptjs");
const { z } = require("zod");
const prisma = require("./db");
const { hashCode, generateCode, signAdmin } = require("./security");
const { requireAdmin } = require("./middleware");

const app = express();
const PORT = Number(process.env.PORT || 3000);

if (!process.env.JWT_SECRET || process.env.JWT_SECRET.length < 32) {
  throw new Error("JWT_SECRET must be set to at least 32 characters");
}
if (process.env.NODE_ENV === "production" && !process.env.APP_ORIGIN?.startsWith("https://")) {
  throw new Error("APP_ORIGIN must be HTTPS in production");
}

app.disable("x-powered-by");
app.set("trust proxy", 1);
app.use(helmet());
app.use(express.json({ limit: "20kb" }));
app.use(cookieParser());

const loginLimiter = rateLimit({ windowMs: 15 * 60 * 1000, limit: 8, standardHeaders: true, legacyHeaders: false });
const apiLimiter = rateLimit({ windowMs: 60 * 1000, limit: 120, standardHeaders: true, legacyHeaders: false });

app.use("/api", apiLimiter);
app.use(express.static("public", { extensions: ["html"] }));

app.get("/api/health", (_req, res) => res.json({ ok: true, service: "activation-admin" }));

app.post("/api/auth/login", loginLimiter, async (req, res, next) => {
  try {
    const parsed = z.object({
      email: z.string().email().max(254),
      password: z.string().min(1).max(200)
    }).safeParse(req.body);
    if (!parsed.success) return res.status(400).json({ error: "بيانات الدخول غير صالحة" });

    const email = parsed.data.email.trim().toLowerCase();
    const admin = await prisma.admin.findUnique({ where: { email } });
    const valid = admin ? await bcrypt.compare(parsed.data.password, admin.passwordHash) : false;
    if (!valid) return res.status(401).json({ error: "البريد أو كلمة المرور غير صحيحة" });

    const token = signAdmin(admin);
    res.cookie("admin_token", token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "strict",
      maxAge: 8 * 60 * 60 * 1000,
      path: "/"
    });
    return res.json({ ok: true, admin: { email: admin.email } });
  } catch (err) { next(err); }
});

app.post("/api/auth/logout", (_req, res) => {
  res.clearCookie("admin_token", { httpOnly: true, sameSite: "strict", path: "/" });
  res.json({ ok: true });
});

app.get("/api/auth/me", requireAdmin, (req, res) => {
  res.json({ admin: { email: req.admin.email, role: req.admin.role } });
});

app.get("/api/admin/stats", requireAdmin, async (_req, res, next) => {
  try {
    const [total, active, revoked, activations] = await Promise.all([
      prisma.activationCode.count(),
      prisma.activationCode.count({ where: { status: "ACTIVE" } }),
      prisma.activationCode.count({ where: { status: "REVOKED" } }),
      prisma.activation.count()
    ]);
    res.json({ total, active, revoked, activations });
  } catch (err) { next(err); }
});

app.get("/api/admin/codes", requireAdmin, async (req, res, next) => {
  try {
    const page = Math.max(1, Number.parseInt(req.query.page, 10) || 1);
    const limit = Math.min(100, Math.max(1, Number.parseInt(req.query.limit, 10) || 25));
    const [items, total] = await Promise.all([
      prisma.activationCode.findMany({
        orderBy: { createdAt: "desc" }, skip: (page - 1) * limit, take: limit,
        select: { id: true, codePrefix: true, label: true, status: true, maxUses: true, uses: true, expiresAt: true, createdAt: true, revokedAt: true }
      }),
      prisma.activationCode.count()
    ]);
    res.json({ items, page, limit, total });
  } catch (err) { next(err); }
});

app.post("/api/admin/codes", requireAdmin, async (req, res, next) => {
  try {
    const parsed = z.object({
      label: z.string().trim().max(80).optional(),
      maxUses: z.number().int().min(1).max(10000).default(1),
      expiresAt: z.string().datetime().optional()
    }).safeParse(req.body);
    if (!parsed.success) return res.status(400).json({ error: "راجع بيانات الكود" });

    const code = generateCode();
    const row = await prisma.activationCode.create({
      data: {
        codeHash: hashCode(code),
        codePrefix: code.slice(0, 8),
        label: parsed.data.label || null,
        maxUses: parsed.data.maxUses,
        expiresAt: parsed.data.expiresAt ? new Date(parsed.data.expiresAt) : null
      },
      select: { id: true, codePrefix: true, label: true, status: true, maxUses: true, uses: true, expiresAt: true, createdAt: true }
    });
    // The full code is returned only at creation; only its hash is stored.
    res.status(201).json({ item: row, code });
  } catch (err) { next(err); }
});

app.post("/api/admin/codes/:id/revoke", requireAdmin, async (req, res, next) => {
  try {
    const row = await prisma.activationCode.update({
      where: { id: req.params.id },
      data: { status: "REVOKED", revokedAt: new Date() },
      select: { id: true, codePrefix: true, status: true, revokedAt: true }
    });
    res.json({ item: row });
  } catch (err) {
    if (err.code === "P2025") return res.status(404).json({ error: "الكود غير موجود" });
    next(err);
  }
});

// Public activation endpoint for a product you own. It grants no access to third-party betting services.
app.post("/api/activate", async (req, res, next) => {
  try {
    const parsed = z.object({
      code: z.string().trim().min(10).max(100),
      subject: z.string().trim().min(3).max(120).regex(/^[a-zA-Z0-9_.:@-]+$/)
    }).safeParse(req.body);
    if (!parsed.success) return res.status(400).json({ error: "الكود أو معرّف المستخدم غير صالح" });

    const codeHash = hashCode(parsed.data.code);
    const code = await prisma.activationCode.findUnique({ where: { codeHash } });
    if (!code || code.status !== "ACTIVE") return res.status(400).json({ error: "الكود غير صالح أو ملغى" });
    if (code.expiresAt && code.expiresAt <= new Date()) return res.status(400).json({ error: "انتهت صلاحية الكود" });

    const existing = await prisma.activation.findUnique({
      where: { codeId_subject: { codeId: code.id, subject: parsed.data.subject } }
    });
    if (existing) return res.json({ ok: true, message: "الكود مفعّل لهذا المستخدم بالفعل" });

    // Serializable transaction prevents simultaneous requests from exceeding maxUses.
    await prisma.$transaction(async (tx) => {
      const current = await tx.activationCode.findUnique({ where: { id: code.id } });
      if (!current || current.status !== "ACTIVE" || (current.expiresAt && current.expiresAt <= new Date()) || current.uses >= current.maxUses) {
        throw Object.assign(new Error("الكود غير متاح أو وصل إلى الحد الأقصى للاستخدام"), { status: 409 });
      }
      await tx.activation.create({ data: { codeId: current.id, subject: parsed.data.subject } });
      await tx.activationCode.update({ where: { id: current.id }, data: { uses: { increment: 1 } } });
    }, { isolationLevel: "Serializable" });

    res.json({ ok: true, message: "تم التفعيل بنجاح" });
  } catch (err) {
    if (err.code === "P2002") return res.json({ ok: true, message: "الكود مفعّل لهذا المستخدم بالفعل" });
    if (err.code === "P2034") return res.status(409).json({ error: "تعارض مؤقت، أعد المحاولة" });
    if (err.status) return res.status(err.status).json({ error: err.message });
    next(err);
  }
});

app.use((err, _req, res, _next) => {
  console.error(`[error] ${new Date().toISOString()} ${err.code || ""} ${err.message}`);
  if (res.headersSent) return;
  res.status(500).json({ error: "حدث خطأ داخلي" });
});

app.listen(PORT, () => console.log(`Activation admin listening on port ${PORT}`));

async function shutdown() {
  await prisma.$disconnect();
  process.exit(0);
}
process.on("SIGINT", shutdown);
process.on("SIGTERM", shutdown);
