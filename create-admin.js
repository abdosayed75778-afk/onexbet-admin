require("dotenv").config();
const bcrypt = require("bcryptjs");
const prisma = require("./db");

async function main() {
  const email = process.env.ADMIN_EMAIL?.trim().toLowerCase();
  const password = process.env.ADMIN_PASSWORD;
  if (!email || !password || password.length < 14) {
    throw new Error("Set ADMIN_EMAIL and ADMIN_PASSWORD (at least 14 characters) in .env");
  }
  const passwordHash = await bcrypt.hash(password, 12);
  await prisma.admin.upsert({
    where: { email },
    update: { passwordHash },
    create: { email, passwordHash },
  });
  console.log(`Admin account ready: ${email}`);
}
main().catch((err) => { console.error(err.message); process.exitCode = 1; })
  .finally(() => prisma.$disconnect());
