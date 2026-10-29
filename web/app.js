"use strict";
// Lexy Hub admin panel. No credentials live here. All authority is enforced by the server.
(function () {
  const $ = (s, r = document) => r.querySelector(s);
  const $$ = (s, r = document) => Array.from(r.querySelectorAll(s));
  const state = { csrf: null, user: null, page: 1, apage: 1, timer: null, lastKeys: [] };

  const STATUS_LABEL = { pending: "Pendiente", active: "Activa", expired: "Expirada", revoked: "Revocada" };
  const PRESET_LABEL = { "1d": "1 día", "7d": "7 días", "30d": "30 días", "90d": "90 días", permanent: "Permanente" };

  // ---------- utils
  function el(tag, props = {}, children = []) {
    const n = document.createElement(tag);
    for (const [k, v] of Object.entries(props)) {
      if (k === "class") n.className = v;
      else if (k === "text") n.textContent = v;
      else n.setAttribute(k, v);
    }
    for (const c of [].concat(children)) n.append(c);
    return n;
  }
  function fmtDate(ts) {
    if (!ts) return "—";
    return new Date(ts * 1000).toLocaleString("es-ES", { dateStyle: "short", timeStyle: "short" });
  }
  function fmtRemaining(sec) {
    if (sec == null) return "Permanente";
    if (sec <= 0) return "0s";
    const d = Math.floor(sec / 86400), h = Math.floor((sec % 86400) / 3600), m = Math.floor((sec % 3600) / 60);
    return d ? `${d}d ${h}h` : h ? `${h}h ${m}m` : `${m}m ${sec % 60}s`;
  }
  function badge(status) {
    return el("span", { class: `badge ${status}`, text: STATUS_LABEL[status] || status });
  }
  function toast(msg, bad = false) {
    const t = $("#toast");
    t.textContent = msg;
    t.className = "toast" + (bad ? " bad" : "");
    t.hidden = false;
    clearTimeout(toast._t);
    toast._t = setTimeout(() => (t.hidden = true), 3800);
  }
  async function api(path, opts = {}) {
    const headers = { Accept: "application/json", ...(opts.headers || {}) };
    if (opts.body !== undefined) headers["Content-Type"] = "application/json";
    if (state.csrf && opts.method && opts.method !== "GET") headers["X-CSRF-Token"] = state.csrf;
    let res;
    try {
      res = await fetch(path, { credentials: "same-origin", ...opts, headers,
        body: opts.body !== undefined ? JSON.stringify(opts.body) : undefined });
    } catch (e) {
      throw { code: "network", message: "No se pudo conectar con el servidor." };
    }
    let data = {};
    try { data = await res.json(); } catch (_) { /* non-json */ }
    if (!res.ok || data.ok === false) {
      const err = { code: data.code || "http_" + res.status, message: data.message || "Error inesperado.", status: res.status };
      throw err;
    }
    return data;
  }
  function confirmBox({ title, body, reason = false, okText = "Confirmar", danger = false }) {
    return new Promise((resolve) => {
      $("#modal-title").textContent = title;
      const b = $("#modal-body");
      b.textContent = "";
      b.append(el("p", { class: "muted", text: body }));
      $("#modal-reason-wrap").hidden = !reason;
      $("#modal-cancel").hidden = false;
      $("#modal-reason").value = "";
      const ok = $("#modal-ok");
      ok.textContent = okText;
      ok.className = "btn " + (danger ? "danger" : "primary");
      $("#modal").hidden = false;
      const close = (val) => {
        $("#modal").hidden = true;
        ok.onclick = $("#modal-cancel").onclick = null;
        resolve(val);
      };
      ok.onclick = () => close({ reason: $("#modal-reason").value.trim() });
      $("#modal-cancel").onclick = () => close(null);
    });
  }
  function showView(id) {
    for (const v of ["view-login", "view-password", "view-panel"]) $("#" + v).hidden = v !== id;
  }
  function showError(id, msg) {
    const e = $(id);
    e.textContent = msg || "";
    e.hidden = !msg;
  }
  function passwordProblem(pw, confirm, user) {
    if (pw.length < 12) return "La contraseña debe tener al menos 12 caracteres.";
    if (!(/[a-z]/.test(pw) && /[A-Z]/.test(pw) && /\d/.test(pw) && /[^A-Za-z0-9]/.test(pw)))
      return "Debe incluir mayúsculas, minúsculas, números y un símbolo.";
    if (pw !== confirm) return "Las contraseñas no coinciden.";
    return null;
  }

  // ---------- auth
  async function boot() {
    try {
      const me = await api("/api/admin/me");
      state.csrf = me.csrf_token;
      state.user = me.username;
      state.types = me.license_types || [];
      if (me.must_change_password) return enterPasswordGate(me.username);
      return enterPanel();
    } catch (e) {
      if (e.status === 403 && e.code === "password_change_required") return enterPasswordGate();
      showView("view-login");
    }
  }
  function enterPasswordGate() {
    showView("view-password");
    $("#password-form").current_password.focus();
  }
  async function enterPanel() {
    showView("view-panel");
    $("#whoami").textContent = "Sesión: " + (state.user || "");
    // Tras iniciar sesión con el formulario no hay lista de tipos cargada: se pide al servidor.
    if (!state.types || !state.types.length) {
      try {
        const me = await api("/api/admin/me");
        state.types = me.license_types || [];
      } catch (e) {
        if (!handleAuthError(e)) toast(e.message, true);
      }
    }
    fillTypes();
    switchTab("dashboard");
    startAutoRefresh();
  }
  function fillTypes() {
    const sel = $("#license-type");
    sel.textContent = "";
    if (!state.types || !state.types.length) {
      sel.append(el("option", { value: "", text: "Sin tipos configurados" }));
      return;
    }
    for (const t of state.types) sel.append(el("option", { value: t, text: t }));
  }

  $("#login-form").addEventListener("submit", async (ev) => {
    ev.preventDefault();
    const f = ev.target;
    showError("#login-error", "");
    const username = f.username.value.trim(), password = f.password.value;
    if (!username || !password) return showError("#login-error", "Escribe usuario y contraseña.");
    try {
      const r = await api("/api/admin/login", { method: "POST", body: { username, password } });
      state.csrf = r.csrf_token;
      state.user = r.username;
      f.password.value = "";
      if (r.must_change_password) return enterPasswordGate();
      enterPanel();
    } catch (e) {
      showError("#login-error", e.message);
    }
  });

  async function submitPassword(form, errorId, after) {
    showError(errorId, "");
    const cur = form.current_password.value, nw = form.new_password.value, cf = form.confirm.value;
    const problem = passwordProblem(nw, cf, state.user);
    if (problem) return showError(errorId, problem);
    try {
      const r = await api("/api/admin/password", { method: "POST",
        body: { current_password: cur, new_password: nw } });
      state.csrf = r.csrf_token;
      form.reset();
      after();
    } catch (e) {
      showError(errorId, e.message);
    }
  }
  $("#password-form").addEventListener("submit", (ev) => {
    ev.preventDefault();
    submitPassword(ev.target, "#password-error", () => { toast("Contraseña actualizada."); enterPanel(); });
  });
  $("#change-form").addEventListener("submit", (ev) => {
    ev.preventDefault();
    submitPassword(ev.target, "#change-error", () => toast("Contraseña actualizada."));
  });

  $("#logout-btn").addEventListener("click", async () => {
    try { await api("/api/admin/logout", { method: "POST", body: {} }); } catch (_) { /* session may already be gone */ }
    state.csrf = null;
    stopAutoRefresh();
    showView("view-login");
  });

  // ---------- navigation
  function switchTab(name) {
    for (const b of $$(".nav")) b.classList.toggle("active", b.dataset.tab === name);
    for (const p of $$("[data-pane]")) p.hidden = p.dataset.pane !== name;
    if (name === "dashboard") loadStats();
    if (name === "licenses") loadLicenses();
    if (name === "audit") loadAudit();
  }
  $$(".nav").forEach((b) => b.addEventListener("click", () => switchTab(b.dataset.tab)));
  function startAutoRefresh() {
    stopAutoRefresh();
    state.timer = setInterval(() => {
      if (!$("[data-pane=dashboard]").hidden) loadStats();
    }, 15000);
  }
  function stopAutoRefresh() { clearInterval(state.timer); }

  function handleAuthError(e) {
    if (e.status === 401) {
      toast("La sesión expiró. Vuelve a iniciar sesión.", true);
      state.csrf = null;
      stopAutoRefresh();
      showView("view-login");
      return true;
    }
    if (e.code === "password_change_required") { enterPasswordGate(); return true; }
    return false;
  }

  // ---------- dashboard
  async function loadStats() {
    try {
      const s = await api("/api/admin/stats");
      const cards = [
        ["Total de keys", s.total, ""], ["Activas", s.active, "ok"], ["Expiradas", s.expired, "warn"],
        ["Revocadas", s.revoked, "bad"], ["Pendientes", s.pending, ""], ["Cuentas vinculadas", s.linked_accounts, ""],
      ];
      const box = $("#stats-cards");
      box.textContent = "";
      for (const [l, n, cls] of cards) {
        box.append(el("div", { class: "stat " + cls }, [el("div", { class: "n", text: String(n) }), el("div", { class: "l", text: l })]));
      }
      const acts = $("#recent-activations");
      acts.textContent = "";
      if (!s.recent_activations.length) acts.append(el("p", { class: "muted", text: "Sin activaciones todavía." }));
      for (const a of s.recent_activations) {
        acts.append(el("div", { class: "item" }, [
          el("span", { text: `${a.roblox_username || "—"} · ${a.key_hint || ""}` }),
          el("span", { class: "muted", text: fmtDate(a.created_at) }),
        ]));
      }
      const evs = $("#recent-events");
      evs.textContent = "";
      if (!s.recent_events.length) evs.append(el("p", { class: "muted", text: "Sin eventos." }));
      for (const e of s.recent_events) {
        evs.append(el("div", { class: "item" }, [
          el("span", {}, [el("span", { text: e.action + " " }), el("span", { class: `badge ${e.result}`, text: e.result })]),
          el("span", { class: "muted", text: fmtDate(e.created_at) + (e.admin_name ? " · " + e.admin_name : "") }),
        ]));
      }
    } catch (e) { if (!handleAuthError(e)) toast(e.message, true); }
  }

  // ---------- generator
  $("#preset").addEventListener("change", (ev) => {
    $("#custom-box").hidden = ev.target.value !== "custom";
  });
  $("#gen-form").addEventListener("submit", async (ev) => {
    ev.preventDefault();
    const f = ev.target;
    const result = $("#gen-result");
    result.hidden = true;
    const qty = Number(f.quantity.value);
    if (!Number.isInteger(qty) || qty < 1 || qty > 500) {
      return showResult("Cantidad no válida (1 a 500).", true);
    }
    const duration = { preset: f.preset.value };
    if (duration.preset === "custom") {
      duration.custom_value = Number(f.custom_value.value);
      duration.custom_unit = f.custom_unit.value;
    }
    const preset = PRESET_LABEL[duration.preset] || "personalizada";
    const ok = await confirmBox({
      title: "Generar keys",
      body: `Se crearán ${qty} key(s) de tipo ${f.license_type.value} con duración ${preset}.`,
      okText: "Generar",
    });
    if (!ok) return;
    try {
      const r = await api("/api/admin/licenses/generate", { method: "POST", body: {
        quantity: qty, license_type: f.license_type.value, duration } });
      state.lastKeys = r.keys;
      renderKeys(r.keys);
      showResult(r.message, false);
      toast(`${r.count} key(s) generada(s).`);
    } catch (e) {
      if (!handleAuthError(e)) showResult(e.message, true);
    }
  });
  function showResult(msg, bad) {
    const r = $("#gen-result");
    r.textContent = (bad ? "✖ " : "✔ ") + msg;
    r.className = "result " + (bad ? "bad" : "ok");
    r.hidden = false;
  }
  function renderKeys(keys) {
    const box = $("#gen-list");
    box.textContent = "";
    for (const k of keys) {
      const btn = el("button", { class: "btn small", text: "Copiar" });
      btn.addEventListener("click", () => copyText(k.key));
      box.append(el("div", { class: "keyrow" }, [el("code", { text: k.key }), btn]));
    }
    $("#gen-output").hidden = keys.length === 0;
  }
  function copyText(text) {
    if (navigator.clipboard && window.isSecureContext) {
      return navigator.clipboard.writeText(text).then(() => toast("Copiado."), () => toast("No se pudo copiar.", true));
    }
    const ta = el("textarea", { class: "offscreen" });
    ta.value = text;
    document.body.append(ta);
    ta.select();
    const ok = document.execCommand("copy");
    ta.remove();
    toast(ok ? "Copiado." : "No se pudo copiar.", !ok);
  }
  $("#copy-all").addEventListener("click", () => {
    if (!state.lastKeys.length) return toast("No hay keys recientes.", true);
    copyText(state.lastKeys.map((k) => k.key).join("\n"));
  });

  // ---------- licenses table
  let qTimer;
  for (const id of ["#f-status", "#f-device"]) $(id).addEventListener("change", () => { state.page = 1; loadLicenses(); });
  $("#f-q").addEventListener("input", () => {
    clearTimeout(qTimer);
    qTimer = setTimeout(() => { state.page = 1; loadLicenses(); }, 300);
  });
  $("#prev").addEventListener("click", () => { if (state.page > 1) { state.page--; loadLicenses(); } });
  $("#next").addEventListener("click", () => { state.page++; loadLicenses(); });

  async function loadLicenses() {
    const p = new URLSearchParams({ page: state.page, per_page: 15 });
    const q = $("#f-q").value.trim(), st = $("#f-status").value, dv = $("#f-device").value;
    if (q) p.set("q", q);
    if (st) p.set("status", st);
    if (dv) p.set("device", dv);
    try {
      const r = await api("/api/admin/licenses?" + p.toString());
      if (state.page > r.pages) { state.page = r.pages; return loadLicenses(); }
      const body = $("#lic-body");
      body.textContent = "";
      if (!r.items.length) {
        body.append(el("tr", {}, [el("td", { colspan: "11", class: "muted", text: "Sin resultados." })]));
      }
      for (const it of r.items) body.append(licenseRow(it));
      $("#page-info").textContent = `Página ${r.page} de ${r.pages} · ${r.total} licencias`;
    } catch (e) { if (!handleAuthError(e)) toast(e.message, true); }
  }

  function licenseRow(it) {
    const acc = it.roblox_username ? `${it.roblox_display || it.roblox_username} (@${it.roblox_username})` : "—";
    const dev = it.device_bound ? `Vinculado · ${it.device_fingerprint}…` : "Sin dispositivo";
    const actions = el("div", { class: "actions" });
    const mk = (label, fn, cls = "") => {
      const b = el("button", { class: "btn small " + cls, text: label });
      b.addEventListener("click", fn);
      return b;
    };
    actions.append(mk("Detalles", () => openDetail(it.id)));
    if (it.status !== "revoked") actions.append(mk("Revocar", () => doAction(it, "revoke", "Revocar licencia", "La licencia dejará de funcionar de inmediato.", true), "danger"));
    if (it.device_bound) actions.append(mk("Reset HWID", () => doAction(it, "reset-hwid", "Restablecer HWID", "Se liberará el dispositivo actual. La cuenta de Roblox NO se desvincula.", false)));
    if (it.roblox_user_id) actions.append(mk("Desvincular cuenta", () => doAction(it, "unlink-account", "Desvincular cuenta de Roblox", "Se quitará la cuenta y el dispositivo. La siguiente activación requerirá verificar la nueva cuenta.", true)));
    return el("tr", {}, [
      el("td", { text: String(it.id) }),
      el("td", {}, [el("code", { text: it.key_hint })]),
      el("td", {}, [badge(it.status)]),
      el("td", { text: it.is_permanent ? "Permanente" : `${Math.round(it.duration_seconds / 86400 * 10) / 10} d` }),
      el("td", { text: fmtDate(it.created_at) }),
      el("td", { text: fmtDate(it.activated_at) }),
      el("td", { text: it.is_permanent ? "—" : fmtDate(it.expires_at) }),
      el("td", { text: acc }),
      el("td", { text: dev }),
      el("td", { text: fmtDate(it.last_validated_at) }),
      el("td", {}, [actions]),
    ]);
  }

  async function doAction(it, path, title, body, danger) {
    const res = await confirmBox({ title, body: `Licencia #${it.id} (${it.key_hint}). ${body}`, reason: true, okText: "Confirmar", danger });
    if (!res) return;
    try {
      const r = await api(`/api/admin/licenses/${it.id}/${path}`, { method: "POST", body: { reason: res.reason } });
      toast(r.message);
      loadLicenses();
      loadStats();
    } catch (e) { if (!handleAuthError(e)) toast(e.message, true); }
  }

  async function openDetail(id) {
    try {
      const { license: l, history, server_time: srv } = await api(`/api/admin/licenses/${id}`);
      const rows = [
        ["Identificador", l.id], ["Key", l.key_hint], ["Estado", STATUS_LABEL[l.status] || l.status],
        ["Tipo", l.license_type], ["Duración", l.is_permanent ? "Permanente" : fmtRemaining(l.duration_seconds)],
        ["Creada", fmtDate(l.created_at)], ["Activada", fmtDate(l.activated_at)],
        ["Expira", l.is_permanent ? "Nunca" : fmtDate(l.expires_at)],
        ["Tiempo restante", fmtRemaining(l.status === "active" && !l.is_permanent ? Math.max(0, l.expires_at - srv) : null)],
        ["Cuenta Roblox", l.roblox_username ? `${l.roblox_display} (@${l.roblox_username}, ID ${l.roblox_user_id})` : "—"],
        ["Dispositivo", l.device_bound ? `Vinculado (huella ${l.device_fingerprint}…, origen ${l.device_source})` : "Sin vincular"],
        ["Primera vinculación", fmtDate(l.device_first_bound_at)], ["Última vinculación", fmtDate(l.device_bound_at)],
        ["Última validación", fmtDate(l.last_validated_at)], ["Restablecimientos HWID", l.hwid_resets ?? 0],
      ];
      const wrap = el("div", { class: "list" }, rows.map(([k, v]) =>
        el("div", { class: "item" }, [el("span", { class: "muted", text: k }), el("span", { text: String(v) })])));
      const hist = el("div", { class: "list" }, [el("h3", { text: "Historial" })]);
      if (!history.length) hist.append(el("p", { class: "muted", text: "Sin eventos." }));
      for (const h of history) {
        hist.append(el("div", { class: "item" }, [
          el("span", {}, [el("span", { text: h.action + " " }), el("span", { class: `badge ${h.result}`, text: h.result })]),
          el("span", { class: "muted", text: fmtDate(h.created_at) + (h.admin_name ? " · " + h.admin_name : "") }),
        ]));
      }
      $("#modal-title").textContent = `Licencia #${l.id}`;
      const b = $("#modal-body");
      b.textContent = "";
      b.append(wrap, hist);
      $("#modal-reason-wrap").hidden = true;
      const ok = $("#modal-ok");
      ok.textContent = "Cerrar";
      ok.className = "btn primary";
      $("#modal").hidden = false;
      $("#modal-cancel").hidden = true;
      ok.onclick = () => { $("#modal").hidden = true; ok.onclick = null; };
    } catch (e) { if (!handleAuthError(e)) toast(e.message, true); }
  }

  // ---------- audit
  $("#audit-kind").addEventListener("change", () => { state.apage = 1; loadAudit(); });
  $("#a-prev").addEventListener("click", () => { if (state.apage > 1) { state.apage--; loadAudit(); } });
  $("#a-next").addEventListener("click", () => { state.apage++; loadAudit(); });
  async function loadAudit() {
    const p = new URLSearchParams({ page: state.apage, per_page: 20, kind: $("#audit-kind").value });
    try {
      const r = await api("/api/admin/audit?" + p.toString());
      if (state.apage > r.pages) { state.apage = r.pages; return loadAudit(); }
      const body = $("#audit-body");
      body.textContent = "";
      if (!r.items.length) body.append(el("tr", {}, [el("td", { colspan: "6", class: "muted", text: "Sin eventos." })]));
      for (const a of r.items) {
        body.append(el("tr", {}, [
          el("td", { text: fmtDate(a.created_at) }),
          el("td", { text: a.action }),
          el("td", {}, [el("span", { class: `badge ${a.result}`, text: a.result })]),
          el("td", { text: a.admin_name || "—" }),
          el("td", {}, [el("code", { text: a.key_hint || "—" })]),
          el("td", { text: a.reason || "—" }),
        ]));
      }
      $("#a-info").textContent = `Página ${r.page} de ${r.pages}`;
    } catch (e) { if (!handleAuthError(e)) toast(e.message, true); }
  }

  boot();
})();
