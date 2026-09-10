"use strict";

/* ==========================================================================
   Состояние
   ========================================================================== */

let token = localStorage.getItem("noisefloor_token") || null;
let currentPeers = [];
let currentServer = null;
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
  checkForAwgUpdate();
}

/* ==========================================================================
   Обновление бинарников AmneziaWG (официальные исходники amnezia-vpn)
   ========================================================================== */

const UPDATE_CHECK_INTERVAL_MS = 6 * 60 * 60 * 1000; // раз в 6 часов, пока открыта вкладка
let updateCheckTimer = null;

async function checkForAwgUpdate() {
  clearTimeout(updateCheckTimer);
  updateCheckTimer = setTimeout(checkForAwgUpdate, UPDATE_CHECK_INTERVAL_MS);

  const btn = $("update-btn");
  try {
    const result = await api("/updates/check");
    if (!result.checked_ok) {
      btn.hidden = true;
      return;
    }
    if (result.update_available) {
      const parts = result.components
        .filter((c) => c.update_available)
        .map((c) => `${c.name}: ${c.current || "?"} → ${c.latest}`);
      btn.title = `Доступна новая версия из официального репозитория amnezia-vpn:\n${parts.join("\n")}`;
      btn.hidden = false;
    } else {
      btn.hidden = true;
    }
  } catch (_) {
    /* тихо: проверка обновлений не должна мешать основной работе панели */
    btn.hidden = true;
  }
}

$("update-btn").addEventListener("click", async () => {
  const btn = $("update-btn");
  if (btn.disabled) return;
  btn.disabled = true;
  const originalText = btn.textContent;
  btn.textContent = "Собираю из исходников…";
  try {
    const result = await api("/updates/apply", { method: "POST" });
    if (result.ok) {
      showToast("AmneziaWG обновлён и переприменён");
      btn.hidden = true;
    } else {
      showToast(result.output || "Не удалось обновить — смотрите docker logs", true);
    }
  } catch (err) {
    showToast(err.message, true);
  } finally {
    btn.disabled = false;
    btn.textContent = originalText;
    await loadServer();
    checkForAwgUpdate();
  }
});

/* ==========================================================================
   Вкладки
   ========================================================================== */

document.querySelectorAll(".tab-btn").forEach((btn) => {
  btn.addEventListener("click", () => {
    document.querySelectorAll(".tab-btn").forEach((b) => b.classList.remove("is-active"));
    btn.classList.add("is-active");
    const tab = btn.dataset.tab;
    $("tab-peers").hidden = tab !== "peers";
    $("tab-server").hidden = tab !== "server";
  });
});

/* ==========================================================================
   Сервер / интерфейс
   ========================================================================== */

async function loadEverything() {
  await Promise.all([loadServer(), loadPeers(), loadBackups()]);
}

async function loadServer() {
  currentServer = await api("/server");
  fillServerForm(currentServer);
}

function fillServerForm(s) {
  $("server-pubkey-display").textContent = s.public_key;
  $("f-endpoint-host").value = s.endpoint_host || "";
  $("f-listen-port").value = s.listen_port;
  $("f-address").value = s.address;
  $("f-dns").value = s.dns || "";
  $("f-egress").value = s.egress_interface || "";
  $("f-mtu").value = s.mtu || "";
  $("f-cascade-enabled").checked = !!s.cascade_enabled;
  $("f-split-ru-direct").checked = !!s.split_ru_direct;
  $("f-cascade-sync-url").value = s.cascade_sync_url || "";
  $("f-cascade-sync-token").value = s.cascade_sync_token || "";
  $("f-jc").value = s.jc;
  $("f-jmin").value = s.jmin;
  $("f-jmax").value = s.jmax;
  $("f-s1").value = s.s1;
  $("f-s2").value = s.s2;
  $("f-s3").value = s.s3;
  $("f-s4").value = s.s4;
  $("f-h1").value = s.h1;
  $("f-h2").value = s.h2;
  $("f-h3").value = s.h3;
  $("f-h4").value = s.h4;
  renderApplyStatus(s);
}

function renderApplyStatus(s) {
  const el = $("apply-status");
  el.classList.remove("is-error", "is-ok");
  if (!s.last_applied_at) {
    el.textContent = "ещё не применялось на сервере";
    return;
  }
  const appliedAt = new Date(s.last_applied_at);
  const when = timeAgo(appliedAt);
  el.title = appliedAt.toLocaleString();
  if (s.last_apply_status === "ok") {
    el.textContent = `применено ${when}`;
    el.classList.add("is-ok");
  } else {
    el.textContent = `не применено (${when}): ${s.last_apply_error || "неизвестная ошибка"}`;
    el.classList.add("is-error");
  }
}

$("server-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const payload = {
    endpoint_host: $("f-endpoint-host").value.trim(),
    listen_port: Number($("f-listen-port").value),
    address: $("f-address").value.trim(),
    dns: $("f-dns").value.trim(),
    egress_interface: $("f-egress").value.trim(),
    mtu: $("f-mtu").value ? Number($("f-mtu").value) : null,
    cascade_enabled: $("f-cascade-enabled").checked,
    split_ru_direct: $("f-split-ru-direct").checked,
    cascade_sync_url: $("f-cascade-sync-url").value.trim(),
    cascade_sync_token: $("f-cascade-sync-token").value.trim(),
    jc: Number($("f-jc").value),
    jmin: Number($("f-jmin").value),
    jmax: Number($("f-jmax").value),
    s1: Number($("f-s1").value),
    s2: Number($("f-s2").value),
    s3: Number($("f-s3").value),
    s4: Number($("f-s4").value),
    h1: $("f-h1").value.trim(),
    h2: $("f-h2").value.trim(),
    h3: $("f-h3").value.trim(),
    h4: $("f-h4").value.trim(),
  };
  try {
    currentServer = await api("/server", { method: "PUT", body: JSON.stringify(payload) });
    fillServerForm(currentServer);
    showToast("Настройки сохранены. Не забудьте «Применить на сервере».");
  } catch (err) {
    showToast(err.message, true);
  }
});

$("cascade-sync-btn").addEventListener("click", async () => {
  const btn = $("cascade-sync-btn");
  const status = $("cascade-sync-status");
  btn.disabled = true;
  status.classList.remove("is-error", "is-ok");
  status.textContent = "спрашиваю релей…";
  try {
    // Сохраняем адрес и токен перед синхронизацией: иначе спросим релей
    // по старым данным и покажем непонятную ошибку.
    await api("/server", {
      method: "PUT",
      body: JSON.stringify({
        cascade_sync_url: $("f-cascade-sync-url").value.trim(),
        cascade_sync_token: $("f-cascade-sync-token").value.trim(),
      }),
    });
    const result = await api("/server/cascade/sync", { method: "POST" });
    renderCascadeSync(result);
    await loadServer();
  } catch (err) {
    status.textContent = err.message;
    status.classList.add("is-error");
  } finally {
    btn.disabled = false;
  }
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

function renderCascadeSync(c) {
  const status = $("cascade-sync-status");
  if (!status) return;
  status.classList.remove("is-error", "is-ok");
  if (!c.sync_enabled) {
    status.textContent = "";
    return;
  }
  if (c.sync_error) {
    status.textContent = c.sync_error;
    status.classList.add("is-error");
    return;
  }
  if (c.synced_at) {
    const at = new Date(c.synced_at);
    status.textContent = `параметры получены ${timeAgo(at)}`;
    // Точный момент — подсказкой: относительное время удобно читать, но
    // сразу после нажатия кнопки хочется убедиться, что это именно оно.
    status.title = at.toLocaleString();
    status.classList.add("is-ok");
  } else {
    status.textContent = "ещё не синхронизировались";
    status.title = "";
  }
}

$("randomize-btn").addEventListener("click", async () => {
  try {
    currentServer = await api("/server/randomize-obfuscation", { method: "POST" });
    fillServerForm(currentServer);
    showToast("Параметры обфускации пересозданы — сохранены, осталось применить");
  } catch (err) {
    showToast(err.message, true);
  }
});

$("apply-btn").addEventListener("click", () => runApply("/server/apply", $("apply-btn")));
$("restart-btn").addEventListener("click", () => runApply("/server/restart", $("restart-btn")));

async function runApply(path, btn) {
  btn.disabled = true;
  try {
    const result = await api(path, { method: "POST" });
    await loadServer();
    showToast(result.ok ? "Применено на сервере" : result.message, !result.ok);
  } catch (err) {
    showToast(err.message, true);
  } finally {
    btn.disabled = false;
  }
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

function openAddPeerDialog() {
  $("add-peer-form").reset();
  $("np-allowed").value = "0.0.0.0/0, ::/0";
  $("np-keepalive").value = 25;
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

document.querySelectorAll("dialog").forEach((dlg) => {
  dlg.addEventListener("click", (e) => {
    const rect = dlg.getBoundingClientRect();
    const inside =
      e.clientX >= rect.left && e.clientX <= rect.right && e.clientY >= rect.top && e.clientY <= rect.bottom;
    if (!inside) dlg.close();
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

function renderCascadeStatus(c) {
  renderCascadeSync(c);
  renderCascadeSummary(c);
  const el = $("cascade-status");
  if (!el) return;
  el.classList.remove("is-error", "is-ok");
  if (!c.enabled) {
    el.textContent = "выключен";
    return;
  }
  if (!c.configured) {
    el.textContent = "включен, но ссылка не задана";
    el.classList.add("is-error");
    return;
  }
  if (c.error) {
    el.textContent = `ошибка: ${c.error}`;
    el.classList.add("is-error");
    return;
  }
  if (!c.running) {
    el.textContent = "не запущен";
    el.classList.add("is-error");
    return;
  }
  el.textContent = `активен · ↑${formatBytes(c.uplink)} ↓${formatBytes(c.downlink)}`;
  el.classList.add("is-ok");
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
    el.textContent = `на интерфейсе сейчас: ${liveMtu} (в панели ${configured} — примените конфиг)`;
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
