const $ = (id) => document.getElementById(id);
let page = 1;
let lastCode = "";

async function api(path, options = {}) {
  const response = await fetch(path, {
    credentials: "same-origin",
    ...options,
    headers: { "Content-Type": "application/json", ...(options.headers || {}) }
  });
  const data = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(data.error || `Request failed (${response.status})`);
  return data;
}
function showLoggedIn(admin) {
  $("loginView").classList.add("hidden");
  $("appView").classList.remove("hidden");
  $("logout").classList.remove("hidden");
  if (admin) $("appView").dataset.email = admin.email;
}
function showLoggedOut() {
  $("appView").classList.add("hidden");
  $("loginView").classList.remove("hidden");
  $("logout").classList.add("hidden");
}
function safeText(value) {
  const span = document.createElement("span");
  span.textContent = value == null || value === "" ? "—" : String(value);
  return span.innerHTML;
}
function dateText(value) {
  if (!value) return "بلا انتهاء";
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? "—" : date.toLocaleString("ar-EG");
}
async function loadStats() {
  const s = await api("/api/admin/stats");
  for (const key of ["total", "active", "revoked", "activations"]) $(key).textContent = s[key];
}
async function loadCodes() {
  const data = await api(`/api/admin/codes?page=${page}&limit=25`);
  const body = $("codesBody");
  body.replaceChildren();
  if (!data.items.length) {
    const tr = document.createElement("tr");
    tr.innerHTML = '<td colspan="6">لا توجد أكواد بعد.</td>';
    body.appendChild(tr);
  }
  for (const item of data.items) {
    const tr = document.createElement("tr");
    const status = item.status === "ACTIVE" ? '<span class="pill active">نشط</span>' : '<span class="pill revoked">ملغى</span>';
    tr.innerHTML = `<td dir="ltr">${safeText(item.codePrefix)}•••</td><td>${safeText(item.label)}</td><td>${status}</td><td>${item.uses} / ${item.maxUses}</td><td>${safeText(dateText(item.expiresAt))}</td><td>${item.status === "ACTIVE" ? `<button class="danger" data-revoke="${safeText(item.id)}">إلغاء</button>` : "—"}</td>`;
    body.appendChild(tr);
  }
  $("pagination").innerHTML = `<span>الإجمالي: ${data.total}</span><span><button id="prev" class="ghost" ${page <= 1 ? "disabled" : ""}>السابق</button> <b>${page}</b> <button id="next" class="ghost" ${page * data.limit >= data.total ? "disabled" : ""}>التالي</button></span>`;
  $("prev")?.addEventListener("click", async () => { page--; await refreshAll(); });
  $("next")?.addEventListener("click", async () => { page++; await refreshAll(); });
}
async function refreshAll() {
  $("appError").textContent = "";
  try { await Promise.all([loadStats(), loadCodes()]); }
  catch (e) { $("appError").textContent = e.message; if (/تسجيل الدخول|الجلسة/.test(e.message)) showLoggedOut(); }
}
$("loginForm").addEventListener("submit", async (event) => {
  event.preventDefault();
  $("loginError").textContent = "";
  const form = new FormData(event.currentTarget);
  try {
    const data = await api("/api/auth/login", { method: "POST", body: JSON.stringify({ email: form.get("email"), password: form.get("password") }) });
    showLoggedIn(data.admin);
    await refreshAll();
  } catch (e) { $("loginError").textContent = e.message; }
});
$("logout").addEventListener("click", async () => {
  try { await api("/api/auth/logout", { method: "POST", body: "{}" }); } finally { showLoggedOut(); }
});
$("createForm").addEventListener("submit", async (event) => {
  event.preventDefault();
  $("createError").textContent = "";
  const form = new FormData(event.currentTarget);
  const body = { label: form.get("label").trim() || undefined, maxUses: Number(form.get("maxUses")) };
  const expiry = form.get("expiresAt");
  if (expiry) body.expiresAt = new Date(expiry).toISOString();
  try {
    const data = await api("/api/admin/codes", { method: "POST", body: JSON.stringify(body) });
    lastCode = data.code;
    $("newCodeValue").textContent = lastCode;
    $("newCode").classList.remove("hidden");
    event.currentTarget.reset();
    event.currentTarget.elements.maxUses.value = "1";
    page = 1;
    await refreshAll();
  } catch (e) { $("createError").textContent = e.message; }
});
$("copyCode").addEventListener("click", async () => {
  try { await navigator.clipboard.writeText(lastCode); $("copyCode").textContent = "تم النسخ"; }
  catch { $("copyCode").textContent = "تعذّر النسخ"; }
});
$("codesBody").addEventListener("click", async (event) => {
  const button = event.target.closest("[data-revoke]");
  if (!button || !confirm("هل تريد إلغاء هذا الكود؟")) return;
  button.disabled = true;
  try { await api(`/api/admin/codes/${encodeURIComponent(button.dataset.revoke)}/revoke`, { method: "POST", body: "{}" }); await refreshAll(); }
  catch (e) { $("appError").textContent = e.message; button.disabled = false; }
});
$("refresh").addEventListener("click", refreshAll);
(async function init() {
  try {
    const data = await api("/api/auth/me");
    showLoggedIn(data.admin);
    await refreshAll();
  } catch { showLoggedOut(); }
})();