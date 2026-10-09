"use strict";

/* ==========================================================================
   Состояние
   ========================================================================== */

let token = localStorage.getItem("noisefloor_token") || null;
let currentPeers = [];
let currentServer = null;
let currentTunnels = [];
let lastCascadeStatus = null;  // последний ответ /server/cascade/status

// Протоколы клиентов. У каждого свой интерфейс и свой UDP-порт: маскировка
// задаётся на интерфейс, и клиент другого протокола рукопожатие не пройдёт.
const PROTOCOLS = {
  awg2: {
    name: "AmneziaWG 3.1",
    badge: "",
    hint: "Основной протокол с полной маскировкой и защитой заголовков. Импорт — в AmneziaVPN 5.0.3 или новее.",
  },
  awg20: {
    name: "AmneziaWG 2.0",
    badge: "AWG 2.0",
    hint: "Для AmneziaVPN до 5.0.3 и приложения AmneziaWG без поддержки 3.1: полная маскировка S1–S4, H1–H4, но без защиты заголовков.",
  },
  awg1: {
    name: "AmneziaWG 1.x",
    badge: "AWG 1.x",
    hint: "Для старых версий AmneziaVPN и AmneziaWG и прошивок роутеров, которые не понимают S3/S4 и I1–I5. Маскировка слабее, чем у 3.1.",
  },
  wg: {
    name: "WireGuard",
    badge: "WG",
    hint: "Обычный WireGuard без маскировки: подойдёт стандартное приложение WireGuard и почти любой роутер. DPI опознаёт его легко, в РФ часто блокируется.",
  },
};
let activePeerId = null;
let confirmCallback = null;
let statusPollTimer = null;

/* ==========================================================================
   Утилиты
   ========================================================================== */

function $(id) {
  return document.getElementById(id);
}

function escapeHtml(str) {
  const div = document.createElement("div");
  div.textContent = str == null ? "" : String(str);
  return div.innerHTML;
}

function formatBytes(n) {
  if (!n) return "0 Б";
  const units = ["Б", "КБ", "МБ", "ГБ", "ТБ"];
  let val = n;
  let i = 0;
  while (val >= 1024 && i < units.length - 1) {
    val /= 1024;
    i++;
  }
  return `${val.toFixed(val < 10 && i > 0 ? 1 : 0)} ${units[i]}`;
}

function timeAgo(date) {
  const seconds = Math.floor((Date.now() - date.getTime()) / 1000);
  if (seconds < 10) return "только что";
  if (seconds < 60) return `${seconds} с назад`;
  const minutes = Math.floor(seconds / 60);
  if (minutes < 60) return `${minutes} мин назад`;
  const hours = Math.floor(minutes / 60);
  if (hours < 24) return `${hours} ч назад`;
  const days = Math.floor(hours / 24);
  return `${days} дн назад`;
}

function showToast(message, isError) {
  const container = $("toast-container");
  const el = document.createElement("div");
  el.className = "toast" + (isError ? " is-error" : "");
  el.textContent = message;
  container.appendChild(el);
  const life = isError ? 5200 : 3200;
  setTimeout(() => {
    el.style.transition = "opacity 0.3s";
    el.style.opacity = "0";
    setTimeout(() => el.remove(), 320);
  }, life);
}

/* ==========================================================================
   API-клиент
   ========================================================================== */

async function api(path, opts = {}) {
  const headers = Object.assign({}, opts.headers || {});
  if (token) headers["Authorization"] = `Bearer ${token}`;
  if (opts.body && !(opts.body instanceof FormData)) {
    headers["Content-Type"] = "application/json";
  }

  const res = await fetch(`/api${path}`, { ...opts, headers });

  if (res.status === 401) {
    handleUnauthorized();
    throw new Error("Требуется повторный вход");
  }

  if (!res.ok) {
    let message = `Ошибка ${res.status}`;
    try {
      const data = await res.json();
      if (Array.isArray(data.detail)) {
        message = data.detail.map((d) => d.msg).join("; ");
      } else if (typeof data.detail === "string") {
        message = data.detail;
      }
    } catch (_) {
      /* тело не JSON — оставляем сообщение по умолчанию */
    }
    throw new Error(message);
  }

  const contentType = res.headers.get("content-type") || "";
  if (contentType.includes("application/json")) return res.json();
  return res;
}

async function apiBlob(path) {
  const res = await fetch(`/api${path}`, {
    headers: token ? { Authorization: `Bearer ${token}` } : {},
  });
  if (res.status === 401) {
    handleUnauthorized();
    throw new Error("Требуется повторный вход");
  }
  if (!res.ok) throw new Error(`Ошибка ${res.status}`);
  return res;
}

/* ==========================================================================
   Аутентификация
   ========================================================================== */

function handleUnauthorized() {
  token = null;
  localStorage.removeItem("noisefloor_token");
  stopStatusPolling();
  clearTimeout(updateCheckTimer);
  showLogin();
}

function showLogin() {
  $("app").hidden = true;
  $("login-screen").hidden = false;
}

function showApp() {
  $("login-screen").hidden = true;
  $("app").hidden = false;
}

$("login-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const username = $("login-username").value.trim();
  const password = $("login-password").value;
  const errBox = $("login-error");
  const btn = $("login-submit");
  errBox.hidden = true;
  btn.disabled = true;
  try {
    const res = await fetch("/api/auth/login", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ username, password }),
    });
    const data = await res.json().catch(() => ({}));
    if (!res.ok) throw new Error(data.detail || "Не удалось войти");
    token = data.access_token;
    localStorage.setItem("noisefloor_token", token);
    await afterLogin();
  } catch (err) {
    errBox.textContent = err.message;
    errBox.hidden = false;
  } finally {
    btn.disabled = false;
  }
});

$("logout-btn").addEventListener("click", () => {
  token = null;
  localStorage.removeItem("noisefloor_token");
  stopStatusPolling();
  showLogin();
});

async function afterLogin() {
  const me = await api("/auth/me");
  $("username-chip").textContent = me.username;
  showApp();
  await loadEverything();
  startStatusPolling();
  loadSelfUpdate(false);
}

/* ==========================================================================
   Обновление самой панели
   ========================================================================== */

const UPDATE_CHECK_INTERVAL_MS = 60 * 60 * 1000; // раз в час, пока открыта вкладка
let updateCheckTimer = null;
let selfUpdateState = null;

function fmtDate(iso) {
  if (!iso || iso === "unknown") return "?";
  const d = new Date(iso);
  return isNaN(d) ? iso : d.toLocaleString();
}

function renderSelfUpdate(state) {
  selfUpdateState = state;
  const cur = state.current || {};
  const comp = state.components || {};
  const relay = currentServer && currentServer.cascade_relay_version;

  $("version-chip").textContent = cur.version || "dev";
  const lines = [
    `NOISEFLOOR ${cur.version || "dev"}  (коммит ${cur.sha || "?"}, собрано ${fmtDate(cur.date)})`,
    `amneziawg-go ${comp["amneziawg-go"]}  ·  amneziawg-tools ${comp["amneziawg-tools"]}  ·  xray ${comp.xray}  ·  geoip ${comp.geoip}`,
  ];
  if (relay) {
    const same = relay === cur.version;
    lines.push(`релей ${relay}${same ? "" : "  — версии узлов разошлись, обновите и релей"}`);
  }
  $("version-summary").textContent = lines.join("\n");

  const box = $("update-available-box");
  const topBtn = $("update-btn");
  const applyBtn = $("self-update-btn");
  const hint = $("update-hint");
  const status = $("self-update-status");
  status.classList.remove("is-error", "is-ok");

  if (state.available && state.latest) {
    const l = state.latest;
    $("update-available-text").textContent =
      `${l.version}${l.date ? " от " + fmtDate(l.date) : ""} — канал «${state.channel}». ` +
      `Подробности: ${l.url}`;
    const notes = $("update-notes");
    notes.textContent = l.notes || "";
    notes.hidden = !l.notes;
    box.hidden = false;
    topBtn.hidden = false;
    topBtn.title = `Доступна версия ${l.version}`;
    applyBtn.hidden = !state.agent_available;
    hint.textContent = state.agent_available
      ? ""
      : "На хосте нет агента обновлений: запустите установщик заново или выполните на сервере  docker compose pull && docker compose up -d";
  } else {
    box.hidden = true;
    topBtn.hidden = true;
    applyBtn.hidden = true;
    hint.textContent = state.check_error
      ? ""
      : `Обновлений нет — канал «${state.channel}»${state.checked_at ? ", проверено " + fmtDate(state.checked_at) : ""}.`;
  }

  if (state.pending) {
    status.textContent = "агент обновляет — панель перезапустится через полминуты";
    applyBtn.disabled = true;
  } else if (state.check_error) {
    status.textContent = state.check_error;
    status.classList.add("is-error");
    applyBtn.disabled = false;
  } else if (state.last_result) {
    const r = state.last_result;
    const when = r.finished_at ? fmtDate(r.finished_at) : "";
    if (r.ok) {
      status.textContent = `последнее обновление прошло успешно ${when}`;
      status.classList.add("is-ok");
    } else {
      status.textContent = `последнее обновление не удалось ${when}: ${r.message || ""}${r.rolled_back ? " (возвращена прежняя версия)" : ""}`;
      status.classList.add("is-error");
    }
    applyBtn.disabled = false;
  } else {
    status.textContent = "";
    applyBtn.disabled = false;
  }
}

async function loadSelfUpdate(force) {
  clearTimeout(updateCheckTimer);
  updateCheckTimer = setTimeout(() => loadSelfUpdate(false), UPDATE_CHECK_INTERVAL_MS);
  try {
    const state = force
      ? await api("/updates/self/check", { method: "POST" })
      : await api("/updates/self");
    renderSelfUpdate(state);
  } catch (_) {
    /* тихо: проверка обновлений не должна мешать основной работе панели */
  }
}

async function requestSelfUpdate() {
  const btn = $("self-update-btn");
  btn.disabled = true;
  try {
    const result = await api("/updates/self/apply", { method: "POST" });
    showToast(result.message);
    // Панель сейчас перезапустится; опрашиваем, пока не вернётся новая.
    pollUntilBack();
  } catch (err) {
    showToast(err.message, true);
    btn.disabled = false;
  }
  await loadSelfUpdate(false);
}

function pollUntilBack() {
  const started = Date.now();
  const tick = async () => {
    if (Date.now() - started > 4 * 60 * 1000) return;
    try {
      const state = await api("/updates/self");
      if (!state.pending) {
        renderSelfUpdate(state);
        await loadServer();
        showToast(state.last_result && state.last_result.ok === false
          ? "Обновление не удалось, возвращена прежняя версия"
          : "Панель обновлена");
        return;
      }
    } catch (_) { /* панель перезапускается */ }
    setTimeout(tick, 5000);
  };
  setTimeout(tick, 8000);
}

$("update-btn").addEventListener("click", () => {
  switchTab("server");
  $("update-available-box").scrollIntoView({ behavior: "smooth", block: "center" });
});
$("self-check-btn").addEventListener("click", () => loadSelfUpdate(true));
$("self-update-btn").addEventListener("click", () => {
  const l = selfUpdateState && selfUpdateState.latest;
  openConfirm(
    "Обновить NOISEFLOOR?",
    `Будет установлена версия ${l ? l.version : "latest"}. Панель и интерфейс туннеля перезапустятся — клиенты отвалятся примерно на десять секунд. При неудаче агент вернёт прежнюю версию.`,
    requestSelfUpdate,
  );
});

/* ==========================================================================
   Вкладки
   ========================================================================== */

function switchTab(tab) {
  document.querySelectorAll(".tab-btn").forEach((b) => b.classList.toggle("is-active", b.dataset.tab === tab));
  $("tab-peers").hidden = tab !== "peers";
  $("tab-server").hidden = tab !== "server";
}

document.querySelectorAll(".tab-btn").forEach((btn) => {
  btn.addEventListener("click", () => switchTab(btn.dataset.tab));
});

/* ==========================================================================
   Сервер / интерфейс
   ========================================================================== */

async function loadEverything() {
  await Promise.all([loadServer(), loadPeers(), loadBackups(), loadTunnels()]);
}

/* ==========================================================================
   Дополнительные протоколы: AmneziaWG 2.0, 1.x и обычный WireGuard
   ========================================================================== */

async function loadTunnels() {
  const order = Object.keys(PROTOCOLS);
  currentTunnels = (await api("/tunnels")).sort((a, b) => order.indexOf(a.protocol) - order.indexOf(b.protocol));
  renderTunnels();
}

function tunnelStatusText(t) {
  if (!t.enabled) return { text: "выключен", cls: "" };
  if (t.last_apply_status === "error") return { text: `ошибка: ${t.last_apply_error || "не поднялся"}`, cls: "is-error" };
  if (t.interface_up) return { text: `работает · UDP ${t.listen_port}`, cls: "is-ok" };
  return { text: "не поднят", cls: "is-error" };
}

function tunnelCardHtml(t) {
  const info = PROTOCOLS[t.protocol];
  const st = tunnelStatusText(t);
  const p = t.protocol;
  const hasObfs = p === "awg1" || p === "awg20";
  const obfs = hasObfs ? `
      <div class="field-group">
        <span class="eyebrow">Маскировка ${info.name} — своя, не та же, что у 3.1</span>
        <div class="field-grid">
          <div class="field"><label>Jc</label><input data-t="${p}" data-f="jc" type="number" min="0" value="${t.jc}" /></div>
          <div class="field"><label>Jmin</label><input data-t="${p}" data-f="jmin" type="number" min="0" value="${t.jmin}" /></div>
          <div class="field"><label>Jmax</label><input data-t="${p}" data-f="jmax" type="number" min="0" value="${t.jmax}" /></div>
        </div>
        <div class="field-grid">
          <div class="field"><label>S1</label><input data-t="${p}" data-f="s1" type="number" min="0" value="${t.s1}" /></div>
          <div class="field"><label>S2</label><input data-t="${p}" data-f="s2" type="number" min="0" value="${t.s2}" /></div>
          ${p === "awg20" ? `
          <div class="field"><label>S3</label><input data-t="${p}" data-f="s3" type="number" min="0" value="${t.s3}" /></div>
          <div class="field"><label>S4</label><input data-t="${p}" data-f="s4" type="number" min="0" value="${t.s4}" /></div>` : ""}
        </div>
        <div class="field-grid">
          <div class="field"><label>H1</label><input data-t="${p}" data-f="h1" value="${escapeHtml(t.h1)}" /></div>
          <div class="field"><label>H2</label><input data-t="${p}" data-f="h2" value="${escapeHtml(t.h2)}" /></div>
          <div class="field"><label>H3</label><input data-t="${p}" data-f="h3" value="${escapeHtml(t.h3)}" /></div>
          <div class="field"><label>H4</label><input data-t="${p}" data-f="h4" value="${escapeHtml(t.h4)}" /></div>
        </div>
      </div>` : "";
  return `
    <div class="field-group tunnel-card" style="border-top:1px solid var(--line); padding-top:14px;">
      <div style="display:flex; justify-content:space-between; align-items:center; gap:12px; flex-wrap:wrap;">
        <label style="display:flex; align-items:center; gap:8px; font-weight:600;">
          <input data-t="${p}" data-f="enabled" type="checkbox" style="width:auto;" ${t.enabled ? "checked" : ""} />
          ${info.name}
        </label>
        <span class="apply-status ${st.cls}">${escapeHtml(st.text)}</span>
      </div>
      <p class="field-hint">${info.hint}</p>
      <div class="field-row">
        <div class="field"><label>UDP-порт</label><input data-t="${p}" data-f="listen_port" type="number" min="1" max="65535" value="${t.listen_port}" /></div>
        <div class="field"><label>Подсеть в туннеле</label><input data-t="${p}" data-f="address" value="${escapeHtml(t.address)}" /></div>
      </div>
      <p class="field-hint">Интерфейс ${escapeHtml(t.interface_name)} · клиентов: ${t.peers_total} · порт должен быть открыт по UDP в фаерволе хостинга.</p>
      ${obfs}
      <div class="server-actions">
        <button type="button" class="btn btn-primary btn-sm" data-tunnel-save="${p}">Сохранить и применить</button>
        ${hasObfs ? `<button type="button" class="btn btn-sm" data-tunnel-randomize="${p}">⟳ Пересоздать маскировку</button>` : ""}
      </div>
    </div>`;
}

function renderTunnels() {
  const box = $("tunnels-list");
  box.innerHTML = currentTunnels.map(tunnelCardHtml).join("");
  box.querySelectorAll("[data-tunnel-save]").forEach((btn) => {
    btn.addEventListener("click", () => saveTunnel(btn.dataset.tunnelSave, btn));
  });
  box.querySelectorAll("[data-tunnel-randomize]").forEach((btn) => {
    btn.addEventListener("click", () => {
      const info = PROTOCOLS[btn.dataset.tunnelRandomize];
      openConfirm(
        `Пересоздать маскировку ${info.name}?`,
        "Все выданные конфиги этого протокола перестанут подключаться — клиентам придётся раздать их заново.",
        async () => {
          try {
            await api(`/tunnels/${btn.dataset.tunnelRandomize}/randomize`, { method: "POST" });
            await loadTunnels();
            showToast(`Маскировка пересоздана — перевыпустите конфиги клиентам ${info.badge}`);
          } catch (err) {
            showToast(err.message, true);
          }
        },
      );
    });
  });
}

async function saveTunnel(protocol, btn) {
  const payload = {};
  $("tunnels-list").querySelectorAll(`[data-t="${protocol}"]`).forEach((el) => {
    const f = el.dataset.f;
    if (el.type === "checkbox") payload[f] = el.checked;
    else if (el.type === "number") payload[f] = Number(el.value);
    else payload[f] = el.value.trim();
  });
  btn.disabled = true;
  try {
    const t = await api(`/tunnels/${protocol}`, { method: "PUT", body: JSON.stringify(payload) });
    await loadTunnels();
    if (t.enabled && t.last_apply_status === "error") {
      showToast(`Сохранено, но интерфейс не поднялся: ${t.last_apply_error}`, true);
    } else {
      showToast(t.enabled ? `${PROTOCOLS[protocol].name} включён` : `${PROTOCOLS[protocol].name} выключен`);
    }
  } catch (err) {
    showToast(err.message, true);
  } finally {
    btn.disabled = false;
  }
}

async function loadServer() {
  currentServer = await api("/server");
  fillServerForm(currentServer);
}

// Поле формы → id инпута, раздел (для подсказки «что изменено») и нужен ли
// перезапуск туннеля. Тот же список перезапуска знает сервер
// (routers/server.py, RESTART_FIELDS): интерфейс лишь заранее предупреждает.
const SERVER_FIELDS = [
  ["endpoint_host", "f-endpoint-host", "Сеть", false, "text"],
  ["listen_port", "f-listen-port", "Сеть", true, "number"],
  ["address", "f-address", "Сеть", true, "text"],
  ["dns", "f-dns", "Сеть", false, "text"],
  ["egress_interface", "f-egress", "Сеть", false, "text"],
  ["mtu", "f-mtu", "Сеть", true, "nullable-number"],
  ["cascade_enabled", "f-cascade-enabled", "Каскад", false, "checkbox"],
  ["split_ru_direct", "f-split-ru-direct", "Каскад", false, "checkbox"],
  ["cascade_sync_url", "f-cascade-sync-url", "Каскад", false, "text"],
  ["cascade_sync_token", "f-cascade-sync-token", "Каскад", false, "text"],
  ["jc", "f-jc", "Обфускация", true, "number"],
  ["jmin", "f-jmin", "Обфускация", true, "number"],
  ["jmax", "f-jmax", "Обфускация", true, "number"],
  ["s1", "f-s1", "Обфускация", true, "number"],
  ["s2", "f-s2", "Обфускация", true, "number"],
  ["s3", "f-s3", "Обфускация", true, "number"],
  ["s4", "f-s4", "Обфускация", true, "number"],
  ["h1", "f-h1", "Обфускация", true, "text"],
  ["h2", "f-h2", "Обфускация", true, "text"],
  ["h3", "f-h3", "Обфускация", true, "text"],
  ["h4", "f-h4", "Обфускация", true, "text"],
];

// Значения формы в том виде, в каком они сохранены на сервере. С ними
// сравнивается текущее содержимое, чтобы показать панель сохранения.
let savedServerValues = null;
let savingServer = false;

function readServerField(id, kind) {
  const el = $(id);
  if (kind === "checkbox") return el.checked;
  if (kind === "number") return Number(el.value);
  if (kind === "nullable-number") return el.value ? Number(el.value) : null;
  return el.value.trim();
}

function writeServerField(id, kind, value) {
  const el = $(id);
  if (kind === "checkbox") el.checked = !!value;
  else el.value = value ?? "";
}

function serverFormValues() {
  const values = {};
  for (const [field, id, , , kind] of SERVER_FIELDS) values[field] = readServerField(id, kind);
  return values;
}

function changedServerFields() {
  if (!savedServerValues) return [];
  const now = serverFormValues();
  return SERVER_FIELDS.filter(([field]) => now[field] !== savedServerValues[field]);
}

function updateSaveBar() {
  const changed = changedServerFields();
  const bar = $("save-bar");
  bar.hidden = changed.length === 0 && !savingServer;
  if (savingServer) return;
  const sections = [...new Set(changed.map(([, , section]) => section))];
  const restart = changed.some(([, , , needsRestart]) => needsRestart);
  $("save-bar-title").textContent = `Изменено: ${sections.join(", ")}`;
  $("save-bar-detail").textContent = restart
    ? "Туннель перезапустится — клиенты переподключатся за несколько секунд."
    : "Применится без обрыва клиентов.";
  $("save-bar-detail").classList.toggle("is-warn", restart);
  // Кнопка в самом блоке каскада: изменения там есть — применяет их и
  // проверяет, нет — просто проверяет связь. Раньше внести релей можно было
  // только кнопкой внизу страницы (или неочевидным Enter).
  const cascadeDirty = changed.some(([field]) => isCascadeField(field));
  const checkBtn = $("cascade-check-btn");
  checkBtn.textContent = cascadeDirty ? "Применить и проверить" : "Проверить подключение";
  checkBtn.classList.toggle("btn-primary", cascadeDirty);
  $("cascade-check-hint").textContent = cascadeDirty ? "есть несохранённые изменения каскада" : "";
  if (!cascadeChecking) renderCascadeChecklist(lastCascadeStatus || {});
}

document.querySelectorAll("#server-form input").forEach((el) => {
  if (el.closest("#tunnels-list")) return;  // у протоколов своё сохранение
  el.addEventListener("input", updateSaveBar);
  el.addEventListener("change", updateSaveBar);
});

window.addEventListener("beforeunload", (e) => {
  if (changedServerFields().length) {
    e.preventDefault();
    e.returnValue = "";
  }
});

// Заполнить форму значениями с сервера. Несохранённые правки остаются на
// месте: форма перезаполняется и по фоновым поводам (проверка каскада,
// перезапуск), и стирать при этом начатое администратором нельзя.
// reset — «Отменить»: вернуть всё как на сервере. saved — поля, которые
// только что сохранены: для них верно значение с сервера.
function fillServerForm(s, { reset = false, saved = [] } = {}) {
  const edits = reset ? [] : changedServerFields().filter(([field]) => !saved.includes(field));
  const editValues = serverFormValues();
  $("server-pubkey-display").textContent = s.public_key;
  for (const [field, id, , , kind] of SERVER_FIELDS) writeServerField(id, kind, s[field]);
  savedServerValues = serverFormValues();
  for (const [field, id, , , kind] of edits) writeServerField(id, kind, editValues[field]);
  renderApplyStatus(s);
  updateSaveBar();
  // Версия релея приходит вместе с настройками сервера — обновляем блок версий.
  if (selfUpdateState) renderSelfUpdate(selfUpdateState);
}

function renderApplyStatus(s) {
  const el = $("apply-status");
  const dot = $("apply-strip-dot");
  el.classList.remove("is-error", "is-ok");
  dot.className = "apply-strip-dot";
  if (!s.last_applied_at) {
    el.textContent = "Настройки ещё не применялись на сервере";
    return;
  }
  const appliedAt = new Date(s.last_applied_at);
  el.title = appliedAt.toLocaleString();
  if (s.last_apply_status === "ok") {
    el.textContent = `Настройки применены на сервере ${timeAgo(appliedAt)}`;
    el.classList.add("is-ok");
    dot.classList.add("is-ok");
  } else {
    el.textContent = `Не применилось (${timeAgo(appliedAt)}): ${s.last_apply_error || "неизвестная ошибка"}`;
    el.classList.add("is-error");
    dot.classList.add("is-error");
  }
}

$("discard-btn").addEventListener("click", () => {
  if (currentServer) fillServerForm(currentServer, { reset: true });
});

const isCascadeField = (field) => field.startsWith("cascade_") || field === "split_ru_direct";

// Сохранить изменённые поля (все или только подходящие под only) и сразу
// применить. Несохранённые правки в остальных блоках остаются в форме.
async function saveServer(only = null) {
  const changed = changedServerFields().filter(([field]) => !only || only(field));
  if (!changed.length) return true;
  const now = serverFormValues();
  const payload = {};
  for (const [field] of changed) payload[field] = now[field];

  savingServer = true;
  $("save-btn").disabled = true;
  $("discard-btn").disabled = true;
  $("save-bar-title").textContent = "Сохраняю и применяю…";
  $("save-bar-detail").textContent = "";
  try {
    currentServer = await api("/server", { method: "PUT", body: JSON.stringify(payload) });
    savingServer = false;
    fillServerForm(currentServer, { saved: Object.keys(payload) });
    if (currentServer.last_apply_status === "error") {
      showToast(`Сохранено, но не применилось: ${currentServer.last_apply_error}`, true);
    } else {
      showToast("Сохранено и применено");
    }
    // Каскад затронут — сразу показываем, что из этого вышло, а не ждём
    // фонового опроса и пятиминутной пробы.
    if (changed.some(([field]) => isCascadeField(field))) {
      await checkCascade({ quiet: true });
    }
    return true;
  } catch (err) {
    showToast(err.message, true);
    return false;
  } finally {
    savingServer = false;
    $("save-btn").disabled = false;
    $("discard-btn").disabled = false;
    updateSaveBar();
  }
}

$("server-form").addEventListener("submit", (e) => {
  e.preventDefault();
  saveServer();
});

// Синхронизация с релеем и проба трафика через каскад — по кнопке и сразу
// после сохранения настроек каскада.
let cascadeChecking = false;

async function checkCascade({ quiet = false } = {}) {
  if (!currentServer || !currentServer.cascade_enabled) {
    renderCascadeStatus(await api("/server/cascade/status"));
    return;
  }
  const btn = $("cascade-check-btn");
  cascadeChecking = true;
  btn.disabled = true;
  btn.textContent = "Проверяю…";
  try {
    lastCascadeStatus = { ...(lastCascadeStatus || {}), checking: "sync" };
    renderCascadeChecklist(lastCascadeStatus);
    if (currentServer.cascade_sync_url) {
      lastCascadeStatus = await api("/server/cascade/sync", { method: "POST" });
    }
    renderCascadeStatus({ ...lastCascadeStatus, checking: "verify" });
    const result = await api("/server/cascade/verify", { method: "POST" });
    renderCascadeStatus(result);
    if (!quiet || result.verified_ok === false) {
      showToast(result.verified_ok ? "Каскад работает: трафик проходит через релей" : `Каскад не работает: ${cascadeProblem(result)}`,
        !result.verified_ok);
    }
    await loadServer();
  } catch (err) {
    showToast(err.message, true);
  } finally {
    cascadeChecking = false;
    btn.disabled = false;
    updateSaveBar();
  }
}

$("cascade-check-btn").addEventListener("click", async () => {
  if (changedServerFields().some(([field]) => isCascadeField(field))) {
    await saveServer(isCascadeField);  // сама проверит каскад после сохранения
  } else {
    await checkCascade();
  }
});

$("randomize-btn").addEventListener("click", () => {
  openConfirm(
    "Пересоздать параметры обфускации?",
    "Туннель перезапустится с новыми параметрами, и все выданные клиентам AmneziaWG 3.1 конфиги перестанут подключаться — их придётся раздать заново.",
    async () => {
      try {
        currentServer = await api("/server/randomize-obfuscation", { method: "POST" });
        fillServerForm(currentServer, { saved: SERVER_FIELDS.filter(([, , section]) => section === "Обфускация").map(([f]) => f) });
        showToast("Параметры пересозданы и применены — перевыпустите конфиги клиентам");
      } catch (err) {
        showToast(err.message, true);
      }
    },
  );
});

$("restart-btn").addEventListener("click", () => {
  openConfirm(
    "Перезапустить туннель?",
    "Все интерфейсы опустятся и поднимутся заново. Клиенты переподключатся сами за несколько секунд. Нужно, если что-то повисло; для применения настроек не требуется.",
    async () => {
      const btn = $("restart-btn");
      btn.disabled = true;
      try {
        const result = await api("/server/restart", { method: "POST" });
        await loadServer();
        showToast(result.ok ? "Туннель перезапущен" : result.message, !result.ok);
      } catch (err) {
        showToast(err.message, true);
      } finally {
        btn.disabled = false;
      }
    },
  );
});

function renderCascadeSummary(c) {
  const el = $("cascade-summary");
  if (!el) return;
  if (!c.relay_host) {
    el.textContent = c.configured ? "параметры получены" : "—";
    return;
  }
  // Намеренно без uuid и ключей: администратору нужно понимать, куда и
  // подо что настроен каскад, а не держать перед глазами доступ к нему.
  const parts = [`${c.relay_host}:${c.relay_port}`];
  if (c.relay_sni) parts.push(`sni ${c.relay_sni}`);
  if (c.relay_label) parts.push(c.relay_label);
  el.textContent = parts.join("  ·  ");
}

/* ==========================================================================
   Резервные копии
   ========================================================================== */

$("backup-download-btn").addEventListener("click", async () => {
  const btn = $("backup-download-btn");
  const status = $("backup-status");
  btn.disabled = true;
  status.classList.remove("is-error", "is-ok");
  status.textContent = "собираю копию…";
  try {
    // Копия собирается на лету, чтобы забрать состояние прямо сейчас,
    // а не последнее суточное.
    const res = await apiBlob("/backup/download");
    const blob = await res.blob();
    const disposition = res.headers.get("content-disposition") || "";
    const match = disposition.match(/filename="?([^"]+)"?/);
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = match ? match[1] : "noisefloor-backup.tar.gz";
    document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(url);
    status.textContent = `готово, ${formatBytes(blob.size)}`;
    status.classList.add("is-ok");
    loadBackups();
  } catch (err) {
    status.textContent = err.message;
    status.classList.add("is-error");
  } finally {
    btn.disabled = false;
  }
});

async function loadBackups() {
  const el = $("backup-list");
  if (!el) return;
  try {
    const items = await api("/backup");
    if (items.length === 0) {
      el.textContent = "копий пока нет";
      return;
    }
    const newest = items[0];
    el.textContent = `последняя: ${timeAgo(new Date(newest.created_at))}, ${formatBytes(newest.size)}`
      + (newest.encrypted ? " (зашифрована)" : "")
      + ` · всего ${items.length}`;
  } catch (_) {
    el.textContent = "";
  }
}

/* ==========================================================================
   Пиры — список
   ========================================================================== */

async function loadPeers() {
  currentPeers = await api("/peers");
  renderPeersTable();
}

function renderPeersTable() {
  const tbody = $("peers-tbody");
  const table = $("peers-table");
  const empty = $("peers-empty");

  if (currentPeers.length === 0) {
    table.hidden = true;
    empty.hidden = false;
    return;
  }
  table.hidden = false;
  empty.hidden = true;

  tbody.innerHTML = currentPeers.map(peerRowHtml).join("");

  tbody.querySelectorAll("tr[data-peer-id]").forEach((tr) => {
    tr.addEventListener("click", (e) => {
      if (e.target.closest("button")) return;
      openPeerDialog(Number(tr.dataset.peerId));
    });
  });
  tbody.querySelectorAll("[data-quick-toggle]").forEach((btn) => {
    btn.addEventListener("click", async (e) => {
      e.stopPropagation();
      const id = Number(btn.dataset.quickToggle);
      const peer = currentPeers.find((p) => p.id === id);
      if (peer) await togglePeerEnabled(peer, false);
    });
  });
}

function peerRowHtml(p) {
  const dotClass = !p.enabled ? "is-disabled" : p.online ? "is-online" : "";
  const nameClass = !p.enabled ? "is-disabled" : "";
  const handshake = p.latest_handshake ? timeAgo(new Date(p.latest_handshake)) : "—";
  const transfer = `${formatBytes(p.transfer_rx)} / ${formatBytes(p.transfer_tx)}`;
  return `
    <tr data-peer-id="${p.id}">
      <td>
        <div class="peer-name-cell">
          <span class="peer-dot ${dotClass}"></span>
          <span class="peer-name ${nameClass}">${escapeHtml(p.name)}</span>
          ${PROTOCOLS[p.protocol]?.badge ? `<span class="eyebrow" title="${PROTOCOLS[p.protocol].name}">${PROTOCOLS[p.protocol].badge}</span>` : ""}
        </div>
      </td>
      <td class="peer-meta">${escapeHtml(p.address)}</td>
      <td class="peer-meta">${transfer}</td>
      <td class="peer-meta">${handshake}</td>
      <td>
        <div class="peer-actions">
          <button class="btn btn-sm" data-quick-toggle="${p.id}">${p.enabled ? "Выключить" : "Включить"}</button>
        </div>
      </td>
    </tr>`;
}

async function togglePeerEnabled(peer, refreshDialog) {
  const newEnabled = !peer.enabled;
  try {
    await api(`/peers/${peer.id}`, { method: "PATCH", body: JSON.stringify({ enabled: newEnabled }) });
    await loadPeers();
    if (refreshDialog) await openPeerDialog(peer.id);
    showToast(newEnabled ? "Пир включён" : "Пир выключен");
  } catch (err) {
    showToast(err.message, true);
  }
}

/* ==========================================================================
   Добавление пира
   ========================================================================== */

// Протокол выбирается карточками-радиокнопками, а не <select>: выпадающий
// список рисуется браузером поверх страницы, и клик по пункту в некоторых
// браузерах долетал до <dialog> как клик «мимо окна» - окно закрывалось.
const protocolRadios = () => document.querySelectorAll('input[name="np-protocol"]');

function selectedProtocol() {
  const r = document.querySelector('input[name="np-protocol"]:checked');
  return r ? r.value : "awg2";
}

function updateProtocolHint() {
  // Подсветку ставим классами, а не :has() - он есть не во всех браузерах.
  for (const r of protocolRadios()) {
    const card = r.closest(".proto-option");
    card.classList.toggle("is-checked", r.checked);
    card.classList.toggle("is-disabled", r.disabled);
  }
  $("np-protocol-hint").textContent = PROTOCOLS[selectedProtocol()].hint;
}

protocolRadios().forEach((r) => r.addEventListener("change", updateProtocolHint));

function openAddPeerDialog() {
  $("add-peer-form").reset();
  $("np-allowed").value = "0.0.0.0/0, ::/0";
  $("np-keepalive").value = 25;
  // Выключенный протокол выбрать нельзя: сервер его не слушает.
  for (const radio of protocolRadios()) {
    const sub = radio.closest(".proto-option").querySelector(".proto-sub");
    const t = currentTunnels.find((x) => x.protocol === radio.value);
    const on = radio.value === "awg2" || !!(t && t.enabled);
    radio.disabled = !on;
    sub.textContent = on ? sub.dataset.default : "выключен - включите на вкладке «Сервер»";
    radio.checked = radio.value === "awg2";
  }
  updateProtocolHint();
  $("add-peer-error").hidden = true;
  $("add-peer-dialog").showModal();
  $("np-name").focus();
}

$("add-peer-btn").addEventListener("click", openAddPeerDialog);
document.querySelectorAll('[data-action="add-peer"]').forEach((btn) => btn.addEventListener("click", openAddPeerDialog));

$("add-peer-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const errBox = $("add-peer-error");
  errBox.hidden = true;
  const payload = {
    name: $("np-name").value.trim(),
    allowed_ips_client: $("np-allowed").value.trim() || "0.0.0.0/0, ::/0",
    persistent_keepalive: Number($("np-keepalive").value || 25),
    dns_override: $("np-dns").value.trim() || null,
    note: $("np-note").value.trim() || null,
    protocol: selectedProtocol(),
  };
  const btn = $("add-peer-submit");
  btn.disabled = true;
  try {
    const peer = await api("/peers", { method: "POST", body: JSON.stringify(payload) });
    $("add-peer-dialog").close();
    await loadPeers();
    showToast(`Пир «${peer.name}» создан`);
    openPeerDialog(peer.id);
  } catch (err) {
    errBox.textContent = err.message;
    errBox.hidden = false;
  } finally {
    btn.disabled = false;
  }
});

/* ==========================================================================
   Карточка пира: QR, конфиг, действия
   ========================================================================== */

async function openPeerDialog(id) {
  activePeerId = id;
  const peer = await api(`/peers/${id}`);

  $("peer-dialog-title").textContent = peer.name;
  const proto = PROTOCOLS[peer.protocol] || PROTOCOLS.awg2;
  $("peer-dialog-protocol").textContent = `${proto.name}. ${proto.hint}`;
  $("peer-config-text").textContent = peer.config_text;
  $("peer-toggle-btn").textContent = peer.enabled ? "Выключить" : "Включить";

  const img = $("peer-qr-img");
  img.removeAttribute("src");
  try {
    const res = await apiBlob(`/peers/${id}/qrcode`);
    const blob = await res.blob();
    if (img.dataset.objectUrl) URL.revokeObjectURL(img.dataset.objectUrl);
    const url = URL.createObjectURL(blob);
    img.src = url;
    img.dataset.objectUrl = url;
  } catch (err) {
    showToast("Не удалось загрузить QR-код", true);
  }

  $("peer-dialog").showModal();
}

$("peer-copy-btn").addEventListener("click", async () => {
  const text = $("peer-config-text").textContent;
  try {
    await navigator.clipboard.writeText(text);
    showToast("Конфиг скопирован в буфер обмена");
  } catch (_) {
    showToast("Не удалось скопировать — выделите текст вручную", true);
  }
});

// Поддержка проекта: копирование адреса кошелька.
document.querySelectorAll(".wallet-copy").forEach((btn) => {
  btn.addEventListener("click", async () => {
    const addr = btn.parentElement.querySelector(".wallet-addr").textContent.trim();
    try {
      await navigator.clipboard.writeText(addr);
      showToast("Адрес скопирован");
    } catch (_) {
      showToast("Не удалось скопировать - выделите адрес вручную", true);
    }
  });
});

$("peer-download-btn").addEventListener("click", async () => {
  try {
    const res = await apiBlob(`/peers/${activePeerId}/config`);
    const blob = await res.blob();
    const disposition = res.headers.get("content-disposition") || "";
    const match = disposition.match(/filename="(.+)"/);
    const filename = match ? match[1] : "peer.conf";
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(url);
  } catch (err) {
    showToast(err.message, true);
  }
});

$("peer-toggle-btn").addEventListener("click", () => {
  const peer = currentPeers.find((p) => p.id === activePeerId);
  if (peer) togglePeerEnabled(peer, true);
});

$("peer-regen-btn").addEventListener("click", () => {
  openConfirm(
    "Пересоздать ключи?",
    "Текущий конфиг на устройстве клиента перестанет подключаться — потребуется заново отсканировать новый QR-код или импортировать файл.",
    async () => {
      try {
        await api(`/peers/${activePeerId}/regenerate-keys`, { method: "POST" });
        await loadPeers();
        await openPeerDialog(activePeerId);
        showToast("Ключи пересозданы");
      } catch (err) {
        showToast(err.message, true);
      }
    }
  );
});

$("peer-delete-btn").addEventListener("click", () => {
  const peer = currentPeers.find((p) => p.id === activePeerId);
  const label = peer ? peer.name : "этот пир";
  openConfirm("Удалить пира?", `«${label}» будет удалён без возможности восстановления.`, async () => {
    try {
      await api(`/peers/${activePeerId}`, { method: "DELETE" });
      $("peer-dialog").close();
      await loadPeers();
      showToast("Пир удалён");
    } catch (err) {
      showToast(err.message, true);
    }
  });
});

/* ==========================================================================
   Диалог подтверждения (общий)
   ========================================================================== */

function openConfirm(title, message, onConfirm) {
  $("confirm-title").textContent = title;
  $("confirm-message").textContent = message;
  confirmCallback = onConfirm;
  $("confirm-dialog").showModal();
}

$("confirm-ok-btn").addEventListener("click", async () => {
  const cb = confirmCallback;
  confirmCallback = null;
  $("confirm-dialog").close();
  if (cb) await cb();
});

document.querySelectorAll("[data-close]").forEach((btn) => {
  btn.addEventListener("click", () => btn.closest("dialog").close());
});

// Закрываем по клику на подложку, только если и нажатие, и отпускание пришлись
// на сам <dialog> (подложка), а не на содержимое. Координаты не сравниваем:
// клики по нативным выпадающим спискам и автозаполнению приходят с координатами
// за пределами окна (или нулевыми) и раньше закрывали его. Выделение текста
// мышью с уходом за край окна тоже больше не закрывает его.
document.querySelectorAll("dialog").forEach((dlg) => {
  let downOnBackdrop = false;
  dlg.addEventListener("pointerdown", (e) => {
    downOnBackdrop = e.target === dlg;
  });
  dlg.addEventListener("click", (e) => {
    const onBackdrop = e.target === dlg && downOnBackdrop && e.detail > 0;
    downOnBackdrop = false;
    if (!onBackdrop) return;
    const rect = dlg.getBoundingClientRect();
    const outside =
      e.clientX < rect.left || e.clientX > rect.right || e.clientY < rect.top || e.clientY > rect.bottom;
    if (outside) dlg.close();
  });
});

/* ==========================================================================
   Живой статус (поллинг)
   ========================================================================== */

async function pollStatus() {
  try {
    const s = await api("/status");
    const pill = $("status-pill");
    const text = $("status-pill-text");
    pill.classList.remove("is-up", "is-down");
    if (!s.live_management_available) {
      text.textContent = `${s.interface_name} · только генерация конфигов`;
    } else if (s.interface_up) {
      pill.classList.add("is-up");
      text.textContent = `${s.interface_name} активен`;
    } else {
      pill.classList.add("is-down");
      text.textContent = `${s.interface_name} не поднят`;
    }

    renderLiveMtu(s.interface_mtu);

    const byId = new Map(s.peers.map((p) => [p.peer_id, p]));
    currentPeers = currentPeers.map((p) => {
      const live = byId.get(p.id);
      if (!live) return p;
      return {
        ...p,
        online: live.online,
        latest_handshake: live.latest_handshake,
        transfer_rx: live.transfer_rx,
        transfer_tx: live.transfer_tx,
      };
    });
    renderPeersTable();
  } catch (err) {
    console.error("status poll failed", err);
  }

  try {
    renderCascadeStatus(await api("/server/cascade/status"));
  } catch (err) {
    console.error("cascade status poll failed", err);
  }

  await loadTrafficHistory();
}

/* ==========================================================================
   Трафик: график интерфейса + индикатор каскада
   ========================================================================== */

const trafficChartState = { hist: [] };

async function loadTrafficHistory() {
  try {
    const hist = await api("/status/traffic-history");
    trafficChartState.hist = hist;
    const label = $("traffic-range-label");
    if (label && currentServer) label.textContent = `последний час · ${currentServer.interface_name}`;
    drawTrafficChart();
    renderCascadeBadge(hist);
  } catch (err) {
    console.error("traffic history poll failed", err);
  }
}

function drawTrafficChart() {
  const canvas = $("traffic-chart");
  const empty = $("traffic-chart-empty");
  if (!canvas) return;
  const hist = trafficChartState.hist;

  const rxRates = [];
  const txRates = [];
  for (let i = 1; i < hist.length; i++) {
    const dt = (new Date(hist[i].t) - new Date(hist[i - 1].t)) / 1000;
    if (dt <= 0) continue;
    rxRates.push(Math.max(0, (hist[i].iface_rx - hist[i - 1].iface_rx) / dt));
    txRates.push(Math.max(0, (hist[i].iface_tx - hist[i - 1].iface_tx) / dt));
  }

  const lastRx = rxRates.length ? rxRates[rxRates.length - 1] : 0;
  const lastTx = txRates.length ? txRates[txRates.length - 1] : 0;
  $("legend-iface-rx").textContent = `${formatBytes(lastRx)}/с`;
  $("legend-iface-tx").textContent = `${formatBytes(lastTx)}/с`;

  if (rxRates.length < 2) {
    empty.hidden = false;
    canvas.style.visibility = "hidden";
    return;
  }
  empty.hidden = true;
  canvas.style.visibility = "visible";

  const dpr = window.devicePixelRatio || 1;
  const w = canvas.clientWidth;
  const h = canvas.clientHeight || 130;
  canvas.width = w * dpr;
  canvas.height = h * dpr;
  const ctx = canvas.getContext("2d");
  ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
  ctx.clearRect(0, 0, w, h);

  const maxVal = Math.max(1, ...rxRates, ...txRates) * 1.15;
  const stepX = w / (rxRates.length - 1);
  const toY = (v) => h - 6 - (v / maxVal) * (h - 14);

  ctx.strokeStyle = "rgba(255,255,255,0.05)";
  ctx.lineWidth = 1;
  for (let g = 1; g <= 3; g++) {
    const y = Math.round(h - (g / 4) * h) + 0.5;
    ctx.beginPath();
    ctx.moveTo(0, y);
    ctx.lineTo(w, y);
    ctx.stroke();
  }

  function drawSeries(series, stroke, fill) {
    ctx.beginPath();
    series.forEach((v, idx) => {
      const x = idx * stepX;
      const y = toY(v);
      if (idx === 0) ctx.moveTo(x, y);
      else ctx.lineTo(x, y);
    });
    ctx.lineTo((series.length - 1) * stepX, h);
    ctx.lineTo(0, h);
    ctx.closePath();
    ctx.fillStyle = fill;
    ctx.fill();

    ctx.beginPath();
    series.forEach((v, idx) => {
      const x = idx * stepX;
      const y = toY(v);
      if (idx === 0) ctx.moveTo(x, y);
      else ctx.lineTo(x, y);
    });
    ctx.strokeStyle = stroke;
    ctx.lineWidth = 1.6;
    ctx.stroke();
  }

  // порядок важен только для наложения: сначала "от клиентов" (rx, зелёный),
  // затем поверх "клиентам" (tx, оранжевый)
  drawSeries(rxRates, "#4fd1a5", "rgba(79, 209, 165, 0.14)");
  drawSeries(txRates, "#ff9f45", "rgba(255, 159, 69, 0.14)");
}

// Порог в байтах/с, ниже которого считаем, что это просто keepalive-шум
// каскада, а не реальный полезный трафик — иначе бейдж мигал бы "активен"
// от одних лишь keepalive-пакетов xray/VLESS.
const CASCADE_ACTIVITY_THRESHOLD_BPS = 512;

function renderCascadeBadge(hist) {
  const badge = $("cascade-badge");
  if (!badge) return;
  if (hist.length === 0) {
    badge.hidden = true;
    return;
  }
  const last = hist[hist.length - 1];
  if (!last.cascade_enabled) {
    badge.hidden = true;
    return;
  }
  badge.hidden = false;
  badge.classList.remove("is-idle", "is-active");

  const textEl = $("cascade-badge-text");
  const rateEl = $("cascade-badge-rate");

  if (!last.cascade_running) {
    textEl.textContent = "каскад включён, но xray не запущен";
    rateEl.textContent = "";
    badge.classList.add("is-idle");
    return;
  }

  const prev = hist.length >= 2 ? hist[hist.length - 2] : null;
  let upRate = 0;
  let downRate = 0;
  if (prev) {
    const dt = (new Date(last.t) - new Date(prev.t)) / 1000;
    if (dt > 0) {
      upRate = Math.max(0, (last.cascade_uplink - prev.cascade_uplink) / dt);
      downRate = Math.max(0, (last.cascade_downlink - prev.cascade_downlink) / dt);
    }
  }

  const active = upRate > CASCADE_ACTIVITY_THRESHOLD_BPS || downRate > CASCADE_ACTIVITY_THRESHOLD_BPS;
  if (active) {
    textEl.textContent = "каскад активен — трафик реально идёт через VLESS";
    badge.classList.add("is-active");
  } else {
    textEl.textContent = "каскад запущен, ждём трафика";
    badge.classList.add("is-idle");
  }
  rateEl.textContent =
    `↑${formatBytes(upRate)}/с ↓${formatBytes(downRate)}/с` +
    ` · всего ↑${formatBytes(last.cascade_uplink)} ↓${formatBytes(last.cascade_downlink)}`;
}

function cascadeProblem(c) {
  if (c.sync_enabled && c.sync_error) return c.sync_error;
  if (c.error) return c.error;
  if (!c.running) return "xray каскада не запущен";
  return c.verify_error || "трафик через релей не проходит";
}

// Чек-лист каскада: по нему видно, на каком шаге всё стоит и чего панель
// ждёт — адреса релея, ответа от него, запуска xray или проверки трафика.
function renderCascadeChecklist(c) {
  const box = $("cascade-checklist");
  if (!box) return;
  if (!currentServer || !currentServer.cascade_enabled) {
    const pending = $("f-cascade-enabled").checked;
    box.innerHTML = pending
      ? `<div class="check-row is-wait"><span class="check-mark">…</span><span>Каскад включится, когда вы нажмёте «Применить и проверить» ниже.</span></div>`
      : `<div class="check-row is-off"><span class="check-mark">○</span><span>Каскад выключен — трафик клиентов выходит в интернет прямо с этого сервера.</span></div>`;
    return;
  }
  const rows = [];
  const row = (state, text, detail = "") =>
    rows.push(`<div class="check-row is-${state}"><span class="check-mark">${{ ok: "✓", bad: "✕", wait: "…", todo: "○" }[state]}</span><span>${text}${detail ? ` <span class="check-detail">${detail}</span>` : ""}</span></div>`);

  const hasRelay = !!(currentServer.cascade_sync_url && currentServer.cascade_sync_token);
  if (hasRelay) row("ok", "Релей указан", escapeHtml(currentServer.cascade_sync_url));
  else if (c.configured) row("ok", "Ссылка на релей задана вручную");
  else row("todo", "Укажите адрес релея и токен ниже и сохраните");

  if (c.checking === "sync") row("wait", "Спрашиваю параметры у релея…");
  else if (c.sync_enabled && c.sync_error) row("bad", "Релей не ответил", escapeHtml(c.sync_error));
  else if (c.sync_enabled && c.synced_at) {
    const extra = c.relay_host ? ` · ${escapeHtml(`${c.relay_host}:${c.relay_port}`)}${c.relay_sni ? `, SNI ${escapeHtml(c.relay_sni)}` : ""}` : "";
    row("ok", "Параметры получены от релея", `${timeAgo(new Date(c.synced_at))}${extra}`);
  } else if (hasRelay) row("todo", "Параметры от релея ещё не получены");

  if (c.configured) {
    if (c.error) row("bad", "xray каскада не запустился", escapeHtml(c.error));
    else if (c.running) row("ok", "xray каскада запущен", `↑${formatBytes(c.uplink)} ↓${formatBytes(c.downlink)}`);
    else row("bad", "xray каскада не запущен");
  }

  if (c.checking === "verify") row("wait", "Проверяю трафик через релей…");
  else if (c.verified_ok === true) row("ok", "Трафик проходит через релей", c.verified_at ? `проверено ${timeAgo(new Date(c.verified_at))}` : "");
  else if (c.verified_ok === false) row("bad", "Трафик через релей не проходит", escapeHtml(c.verify_error || ""));
  else if (c.running) row("todo", "Трафик ещё не проверялся", "нажмите «Проверить связь сейчас»");

  box.innerHTML = rows.join("");
}

function renderCascadeStatus(c) {
  if (cascadeChecking && !c.checking) return;  // идёт проверка по кнопке — не мигаем фоновым опросом
  lastCascadeStatus = c;
  renderCascadeSummary(c);
  renderCascadeChecklist(c);
  const el = $("cascade-status");
  if (!el) return;
  el.classList.remove("is-error", "is-ok");
  if (!c.enabled) {
    el.textContent = "выключен";
    return;
  }
  if (c.checking) {
    el.textContent = "проверяю…";
    return;
  }
  if (c.sync_enabled && c.sync_error && c.running && c.verified_ok) {
    // Релей не отдаёт новые параметры, но каскад пока живёт на прежних —
    // сломается при следующей смене SNI на релее.
    el.textContent = "работает на старых параметрах";
    el.classList.add("is-error");
    return;
  }
  if (!c.configured || c.error || !c.running || c.verified_ok === false || (c.sync_enabled && c.sync_error)) {
    el.textContent = c.configured ? "не работает" : "ждёт настройки";
    el.classList.add("is-error");
    return;
  }
  el.textContent = c.verified_ok ? "работает" : "запущен, не проверен";
  if (c.verified_ok) el.classList.add("is-ok");
}

function renderLiveMtu(liveMtu) {
  const el = $("f-mtu-live");
  if (!el) return;
  el.classList.remove("is-ok", "is-error");
  if (liveMtu == null) {
    el.textContent = "на интерфейсе сейчас: —";
    return;
  }
  const configured = currentServer && currentServer.mtu ? currentServer.mtu : null;
  if (configured == null) {
    el.textContent = `на интерфейсе сейчас: ${liveMtu} (в панели не задан — используется дефолт)`;
    return;
  }
  if (configured === liveMtu) {
    el.textContent = `на интерфейсе сейчас: ${liveMtu} (совпадает)`;
    el.classList.add("is-ok");
  } else {
    el.textContent = `на интерфейсе сейчас: ${liveMtu} (в панели ${configured} — не применилось, перезапустите туннель)`;
    el.classList.add("is-error");
  }
}

function startStatusPolling() {
  pollStatus();
  statusPollTimer = setInterval(pollStatus, 8000);
}

function stopStatusPolling() {
  if (statusPollTimer) clearInterval(statusPollTimer);
  statusPollTimer = null;
}

/* ==========================================================================
   Сигнальная полоса (декоративная визуализация junk/сигнальных пакетов)
   ========================================================================== */

function buildSignalStrip() {
  const strip = $("signal-strip");
  if (!strip) return;
  const count = 24;
  for (let i = 0; i < count; i++) {
    const packet = document.createElement("span");
    const isSignal = Math.random() < 0.12;
    packet.className = "packet" + (isSignal ? " is-signal" : "");
    const duration = 6 + Math.random() * 7;
    const delay = -Math.random() * duration;
    packet.style.animationDuration = `${duration}s`;
    packet.style.animationDelay = `${delay}s`;
    packet.style.top = `${3 + Math.random() * 18}px`;
    strip.appendChild(packet);
  }
}

/* ==========================================================================
   Старт
   ========================================================================== */

async function boot() {
  buildSignalStrip();
  window.addEventListener("resize", drawTrafficChart);
  if (token) {
    try {
      await afterLogin();
      return;
    } catch (_) {
      /* токен недействителен — покажем экран входа */
    }
  }
  showLogin();
}

boot();
