"use strict";

/* ------------------------------------------------------------------ i18n */

const STRINGS = {
  ru: {
    settings: "Настройки", your_code: "Ваш код", copy: "Скопировать", copied: "Скопировано",
    connect_to_friend: "Подключиться к другу", friend_code: "Код друга", connect: "Подключиться",
    connecting_to: "Подключение", cancel: "Отменить", ms: "мс",
    route: "Канал", stream: "Поток", traffic: "Трафик", disconnect: "Отключиться",
    incoming_title: "{name} хочет подключиться к этому компьютеру",
    incoming_text: "Он увидит ваш экран и сможет управлять мышью, клавиатурой и геймпадом.",
    remember_device: "Разрешать этому устройству без вопроса",
    decline: "Отклонить", allow: "Разрешить", done: "Готово",
    quality: "Качество", q_auto: "Авто", q_max: "Максимум", q_balanced: "Баланс", q_saver: "Экономно",
    q_note_auto: "Перед запуском замерим скорость канала и подберём битрейт так, чтобы не было потерь.",
    q_note_max: "Битрейт до 80 Мбит/с. Нужен быстрый интернет у обоих.",
    q_note_balanced: "Около 25 Мбит/с для 1080p. Подходит для большинства подключений.",
    q_note_saver: "Около 10 Мбит/с. Для медленного или мобильного интернета.",
    resolution: "Разрешение", res_native: "Как у этого экрана",
    fps: "Кадров в секунду", fps_native: "Как у монитора",
    vsync: "Вертикальная синхронизация", vsync_note: "Убирает разрывы картинки, но добавляет до одного кадра задержки",
    overlay: "Статистика поверх игры", overlay_note: "Задержка декодирования, потери и кадры в углу окна",
    language: "Язык", lang_auto: "Как в системе",
    save_report: "Сохранить отчёт в «Загрузки»", forget_devices: "Забыть разрешённые устройства",
    report_saved: "Отчёт сохранён: {path}", devices_forgotten: "Разрешённые устройства удалены.",
    st_ready: "Готов принять подключение",
    st_signal_wait: "Подключаемся к серверу знакомства…",
    st_signal_down: "Нет связи с сервером знакомства, повторяем",
    st_host_missing: "Модуль трансляции не запущен, к вам пока нельзя подключиться",
    st_busy: "Идёт сеанс",
    step_preparing: "Определяем адрес в сети",
    step_contacting: "Отправляем запрос другу",
    step_waiting: "Друг получил запрос. Ждём, пока он нажмёт «Разрешить»",
    step_punching: "Устанавливаем прямое соединение (до 20 секунд)",
    step_testing: "Проверяем скорость канала",
    step_pairing: "Сопрягаем компьютеры. Когда появится окно «Pairing completed», нажмите OK (только в первый раз)",
    step_starting: "Запускаем поток",
    live_client: "Вы управляете компьютером",
    live_host: "К этому компьютеру подключён",
    grade_good: "Отличная задержка", grade_fair: "Нормальная задержка", grade_poor: "Высокая задержка", grade_wait: "Измеряем…",
    route_direct: "Прямое соединение через интернет", route_lan: "Локальная сеть",
    stream_fmt: "{h}p, {fps} кадров/с, {mbps} Мбит/с",
    traffic_fmt: "↓ {rx} Мбит/с   ↑ {tx} Мбит/с",
    hint_client: "<span class=keys><span>Выйти из потока</span><kbd>Ctrl+Alt+Shift+Q</kbd><span>Статистика в окне потока</span><kbd>Ctrl+Alt+Shift+S</kbd></span>",
    hint_host: "Друг видит ваш экран и управляет им. Чтобы остановить сеанс, нажмите «Отключить».",
    hint_starting: "Сейчас откроется окно с картинкой.",
    disconnect_host: "Отключить",
    err_title: "Не удалось подключиться",
    err_invalid_code: "Код состоит из 9 цифр.",
    err_own_code: "Это ваш собственный код. Введите код друга.",
    err_declined: "Друг отклонил подключение.",
    err_busy: "К этому компьютеру уже кто-то подключён.",
    err_version: "У друга другая версия LowLag. Обновите программу у обоих.",
    err_timeout: "Запрос не дошёл до друга. Проверьте код и что у друга открыт LowLag и под кодом горит зелёная точка. Если точка красная, пусть он откроет Настройки и нажмёт «Проверить».",
    err_no_decision: "Друг получил запрос, но не ответил на него.",
    err_offline: "Нет связи ни с одним сервером знакомства. Откройте Настройки и нажмите «Проверить» в разделе «Проверка сети».",
    err_nat: "Не получилось соединиться напрямую. Так бывает, когда оба подключены через провайдерский NAT (например, оба с мобильного интернета). Попробуйте, чтобы хотя бы один из вас подключился с домашнего интернета. В следующих версиях для таких случаев появятся серверы-посредники.",
    err_pair: "Не удалось сопрячь компьютеры. Попробуйте подключиться ещё раз.",
    err_host_not_ready: "На компьютере друга не запущен модуль трансляции. Пусть он перезапустит LowLag.",
    err_stream: "Поток не запустился.",
    err_tun: "Не удалось создать виртуальный сетевой адаптер. Запустите LowLag от имени администратора.",
    err_lost: "Связь с другом потеряна.",
    err_peer_closed: "Друг завершил сеанс.",
    err_internal: "Внутренняя ошибка.",
    ended: "Сеанс завершён",
    netcheck: "Проверка сети", netcheck_run: "Проверить", netcheck_running: "Проверяем…",
    netcheck_note: "Покажет, какие серверы доступны с этого компьютера.",
    grp_server: "Серверы знакомства", grp_stun: "Определение адреса (STUN)", grp_router: "Роутер", grp_zapret: "Zapret",
    nc_unreachable: "недоступен", nc_reachable: "доступен",
    nc_all_down: "Нет доступа ни к одному серверу знакомства, поэтому подключиться не получится. Проверьте интернет, VPN и Zapret.",
    nc_some_down: "Часть серверов недоступна, но для подключения хватит одного рабочего, если он доступен и у друга. Эти серверы нужны только чтобы найти друг друга: игра идёт напрямую, мимо них.",
    nc_all_ok: "Все серверы доступны. Они нужны только чтобы найти друг друга: игра идёт напрямую, мимо них.",
    nc_zapret: "Zapret включён в режиме, который затрагивает всё подряд (IPSet: any или Game Filter). Если подключение не проходит, в service.bat поставьте Game Filter: disabled и IPSet Filter: none, затем перезапустите Zapret.",
    nc_stun_down: "Не удалось определить внешний адрес: прямое соединение может не получиться.",
  },
  en: {
    settings: "Settings", your_code: "Your code", copy: "Copy", copied: "Copied",
    connect_to_friend: "Connect to a friend", friend_code: "Friend's code", connect: "Connect",
    connecting_to: "Connecting", cancel: "Cancel", ms: "ms",
    route: "Route", stream: "Stream", traffic: "Traffic", disconnect: "Disconnect",
    incoming_title: "{name} wants to connect to this computer",
    incoming_text: "They will see your screen and control the mouse, keyboard and gamepad.",
    remember_device: "Allow this device without asking",
    decline: "Decline", allow: "Allow", done: "Done",
    quality: "Quality", q_auto: "Auto", q_max: "Maximum", q_balanced: "Balanced", q_saver: "Saver",
    q_note_auto: "Before starting we measure the connection and pick a bitrate that avoids packet loss.",
    q_note_max: "Up to 80 Mbit/s. Both of you need fast internet.",
    q_note_balanced: "About 25 Mbit/s at 1080p. Works for most connections.",
    q_note_saver: "About 10 Mbit/s. For slow or mobile internet.",
    resolution: "Resolution", res_native: "Same as this screen",
    fps: "Frames per second", fps_native: "Same as monitor",
    vsync: "V-Sync", vsync_note: "Removes tearing but adds up to one frame of delay",
    overlay: "Stats overlay", overlay_note: "Decode time, loss and frame rate in the corner of the stream",
    language: "Language", lang_auto: "System",
    save_report: "Save a report to Downloads", forget_devices: "Forget allowed devices",
    report_saved: "Report saved: {path}", devices_forgotten: "Allowed devices removed.",
    st_ready: "Ready for connections",
    st_signal_wait: "Reaching the matchmaking server…",
    st_signal_down: "Can't reach the matchmaking server, retrying",
    st_host_missing: "The streaming module isn't running, nobody can connect to you yet",
    st_busy: "Session in progress",
    step_preparing: "Finding our network address",
    step_contacting: "Sending the request to your friend",
    step_waiting: "Your friend got the request. Waiting for them to press Allow",
    step_punching: "Opening a direct connection (up to 20 seconds)",
    step_testing: "Measuring connection speed",
    step_pairing: "Pairing the computers. When the “Pairing completed” window appears, press OK (first time only)",
    step_starting: "Starting the stream",
    live_client: "You are controlling",
    live_host: "Connected to this computer",
    grade_good: "Excellent latency", grade_fair: "Fair latency", grade_poor: "High latency", grade_wait: "Measuring…",
    route_direct: "Direct internet connection", route_lan: "Local network",
    stream_fmt: "{h}p, {fps} fps, {mbps} Mbit/s",
    traffic_fmt: "↓ {rx} Mbit/s   ↑ {tx} Mbit/s",
    hint_client: "<span class=keys><span>Leave the stream</span><kbd>Ctrl+Alt+Shift+Q</kbd><span>Stats in the stream window</span><kbd>Ctrl+Alt+Shift+S</kbd></span>",
    hint_host: "Your friend sees and controls your screen. Press Disconnect to end the session.",
    hint_starting: "The stream window is about to open.",
    disconnect_host: "Disconnect",
    err_title: "Couldn't connect",
    err_invalid_code: "A code has 9 digits.",
    err_own_code: "That's your own code. Enter your friend's code.",
    err_declined: "Your friend declined the connection.",
    err_busy: "Someone is already connected to that computer.",
    err_version: "Your friend has a different LowLag version. Update both.",
    err_timeout: "The request didn't reach your friend. Check the code and that LowLag is open on their PC with a green dot under the code. If the dot is red, ask them to open Settings and press Check.",
    err_no_decision: "Your friend got the request but didn't answer it.",
    err_offline: "None of the matchmaking servers can be reached. Open Settings and press Check under Network check.",
    err_nat: "A direct connection wasn't possible. This happens when both of you are behind a carrier-grade NAT (for example, both on mobile internet). Have at least one of you connect from a home network. Relay servers for such cases are coming in a later version.",
    err_pair: "Pairing failed. Try connecting again.",
    err_host_not_ready: "The streaming module isn't running on your friend's PC. Ask them to restart LowLag.",
    err_stream: "The stream didn't start.",
    err_tun: "Couldn't create the virtual network adapter. Run LowLag as administrator.",
    err_lost: "Connection to your friend was lost.",
    err_peer_closed: "Your friend ended the session.",
    err_internal: "Internal error.",
    ended: "Session ended",
    netcheck: "Network check", netcheck_run: "Check", netcheck_running: "Checking…",
    netcheck_note: "Shows which servers this computer can reach.",
    grp_server: "Matchmaking servers", grp_stun: "Address discovery (STUN)", grp_router: "Router", grp_zapret: "Zapret",
    nc_unreachable: "unreachable", nc_reachable: "reachable",
    nc_all_down: "No matchmaking server is reachable, so connecting won't work. Check your internet, VPN and Zapret.",
    nc_some_down: "Some servers are unreachable, but one working server is enough if your friend can reach it too.",
    nc_all_ok: "All servers are reachable.",
    nc_zapret: "Zapret is in a mode that touches all traffic (IPSet: any or Game Filter). If connecting fails, set Game Filter: disabled and IPSet Filter: none in service.bat, then restart Zapret.",
    nc_stun_down: "Couldn't detect the public address: a direct connection may fail.",
  },
};

let lang = "ru";
const t = (key, vars) => {
  let s = (STRINGS[lang] && STRINGS[lang][key]) ?? STRINGS.ru[key] ?? key;
  if (vars) for (const [k, v] of Object.entries(vars)) s = s.replaceAll(`{${k}}`, v);
  return s;
};

function applyLang(setting) {
  const sys = (navigator.language || "ru").toLowerCase();
  lang = setting === "ru" || setting === "en" ? setting : (/^(ru|uk|be|kk|ky|uz|tg|hy|az|ka|tt|ba)/.test(sys) ? "ru" : "en");
  document.documentElement.lang = lang;
  document.querySelectorAll("[data-i18n]").forEach((el) => (el.textContent = t(el.dataset.i18n)));
  document.querySelectorAll("[data-i18n-placeholder]").forEach((el) => (el.placeholder = t(el.dataset.i18nPlaceholder)));
  document.querySelectorAll("[data-i18n-title]").forEach((el) => {
    el.title = t(el.dataset.i18nTitle);
    el.setAttribute("aria-label", el.title);
  });
}

/* ------------------------------------------------------------------ backend bridge */

const tauri = window.__TAURI__;
const call = (cmd, args) => (tauri ? tauri.core.invoke(cmd, args) : mock(cmd, args));

/* ------------------------------------------------------------------ helpers */

const $ = (id) => document.getElementById(id);
const prettyCode = (d) => d.replace(/\D/g, "").slice(0, 9).replace(/(\d{3})(?=\d)/g, "$1 ");
const mbps = (bps) => (bps / 1e6).toFixed(bps >= 1e7 ? 0 : 1);
const grade = (ms) => (ms <= 0 ? "wait" : ms < 35 ? "good" : ms < 80 ? "fair" : "poor");

function show(view) {
  for (const v of ["idle", "connecting", "live"]) $("view-" + v).hidden = v !== view;
}

/* ------------------------------------------------------------------ rendering */

let state = null;
let lastView = "";
let settingsCache = null;
let traffic = { t: 0, rx: 0, tx: 0, rxRate: 0, txRate: 0 };

const CLIENT_STEPS = ["preparing", "contacting", "waiting", "punching", "testing", "pairing", "starting"];

function render(s) {
  state = s;
  if (!settingsCache || (s.settings && s.settings.lang !== settingsCache.lang)) applyLang(s.settings ? s.settings.lang : "auto");
  settingsCache = s.settings;

  $("version").textContent = "v" + s.version;
  $("foot-note").textContent = s.name || "";
  $("my-code").textContent = s.code ? prettyCode(s.code) : "— — —";

  // status line
  const dot = $("status-dot");
  let st, cls;
  if (s.phase === "live" || s.phase === "connecting") [st, cls] = [t("st_busy"), "fair"];
  else if (s.signal === "connecting") [st, cls] = [t("st_signal_wait"), "wait"];
  else if (s.signal === "error") [st, cls] = [t("st_signal_down"), "poor"];
  else if (!s.host_ready) [st, cls] = [t("st_host_missing"), "fair"];
  else [st, cls] = [t("st_ready"), "good"];
  $("status-text").textContent = st;
  dot.className = "dot " + cls;

  // error banner
  const err = $("error");
  if (s.error && s.phase === "idle") {
    const msg = t("err_" + s.error.code);
    err.innerHTML = "";
    const strong = document.createElement("strong");
    strong.textContent = s.error.code === "peer_closed" || s.error.code === "lost" ? t("ended") : t("err_title");
    err.append(strong, document.createTextNode(msg));
    err.hidden = false;
  } else err.hidden = true;

  // view
  let view = s.phase === "connecting" && s.role === "client" ? "connecting" : s.phase === "live" || s.phase === "connecting" ? "live" : "idle";
  show(view);
  if (view === "connecting") renderSteps(s);
  if (view === "live") renderLive(s, lastView !== "live");
  lastView = view;

  // incoming request
  const inc = $("incoming");
  if (s.incoming) {
    if (inc.hidden) {
      $("incoming-title").textContent = t("incoming_title", { name: s.incoming.name });
      $("incoming-remember").checked = false;
      inc.hidden = false;
      $("btn-accept").focus();
    }
  } else inc.hidden = true;
}

function renderSteps(s) {
  $("connecting-code").textContent = s.peer || prettyCode(s.target_code || "");
  const ol = $("steps");
  const visible = CLIENT_STEPS.filter((k) => k !== "pairing" || s.stage === "pairing" || (s.done_stages || []).includes("pairing"));
  const idx = visible.indexOf(s.stage);
  ol.innerHTML = "";
  visible.forEach((k, i) => {
    const li = document.createElement("li");
    li.textContent = t("step_" + k);
    if (i < idx) li.className = "done";
    else if (i === idx) li.className = "active";
    ol.append(li);
  });
}

function renderLive(s, firstFrame) {
  const host = s.role === "host";
  $("live-title").textContent = host ? t("live_host") : t("live_client");
  $("live-peer").textContent = s.peer || "";
  const rtt = s.rtt_ms || 0;
  $("rtt").textContent = rtt > 0 ? (rtt < 10 ? rtt.toFixed(1) : Math.round(rtt)) : "—";
  const g = grade(rtt);
  $("rtt-dot").className = "dot " + (g === "wait" ? "wait" : g);
  $("rtt-grade").textContent = t("grade_" + g);

  // trace
  const hist = (s.rtt_history || []).slice(-60);
  const svg = $("trace");
  if (firstFrame) {
    svg.classList.remove("draw");
    void svg.getBoundingClientRect();
    svg.classList.add("draw");
  }
  if (hist.length > 1) {
    const max = Math.max(40, ...hist) * 1.15;
    const step = 300 / 59;
    const off = 60 - hist.length;
    const d = hist.map((v, i) => `${i === 0 ? "M" : "L"}${((i + off) * step).toFixed(1)} ${(62 - (v / max) * 58).toFixed(1)}`).join("");
    $("trace-line").setAttribute("d", d);
  }

  $("fact-route").textContent = s.path === "lan" ? t("route_lan") : t("route_direct");
  const st = s.stream;
  $("fact-stream-row").hidden = !st;
  if (st) $("fact-stream").textContent = t("stream_fmt", { w: st.width, h: st.height, fps: st.fps, mbps: Math.round(st.bitrate_kbps / 1000) });

  // traffic rates
  const now = performance.now();
  if (traffic.t && now - traffic.t > 900) {
    const dt = (now - traffic.t) / 1000;
    traffic.rxRate = Math.max(0, (s.rx_bytes - traffic.rx) * 8 / dt);
    traffic.txRate = Math.max(0, (s.tx_bytes - traffic.tx) * 8 / dt);
    Object.assign(traffic, { t: now, rx: s.rx_bytes, tx: s.tx_bytes });
  } else if (!traffic.t || s.rx_bytes < traffic.rx) Object.assign(traffic, { t: now, rx: s.rx_bytes, tx: s.tx_bytes, rxRate: 0, txRate: 0 });
  $("fact-traffic").textContent = t("traffic_fmt", { rx: mbps(traffic.rxRate), tx: mbps(traffic.txRate) });

  $("live-hint").innerHTML = host ? t("hint_host") : s.stage === "streaming" ? t("hint_client") : t("hint_starting");
  $("btn-disconnect").textContent = host ? t("disconnect_host") : t("disconnect");
}

/* ------------------------------------------------------------------ actions */

$("peer-code").addEventListener("input", (e) => {
  const el = e.target;
  el.value = prettyCode(el.value);
  $("btn-connect").disabled = el.value.replace(/\D/g, "").length !== 9;
});

$("join-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const code = $("peer-code").value.replace(/\D/g, "");
  if (code.length !== 9) return;
  render(await call("connect", { code }));
});

$("btn-copy").addEventListener("click", async () => {
  if (!state || !state.code) return;
  try { await navigator.clipboard.writeText(prettyCode(state.code)); } catch (_) {}
  $("copy-icon").hidden = true;
  $("copied-icon").hidden = false;
  $("btn-copy").title = t("copied");
  setTimeout(() => { $("copy-icon").hidden = false; $("copied-icon").hidden = true; $("btn-copy").title = t("copy"); }, 1600);
});

$("btn-cancel").addEventListener("click", async () => render(await call("cancel")));
$("btn-disconnect").addEventListener("click", async () => render(await call("disconnect")));
$("btn-accept").addEventListener("click", async () => render(await call("respond", { accept: true, remember: $("incoming-remember").checked })));
$("btn-decline").addEventListener("click", async () => render(await call("respond", { accept: false, remember: false })));

/* settings sheet */
function fillSettings(s) {
  document.querySelectorAll("#set-quality button").forEach((b) => b.setAttribute("aria-pressed", String(b.dataset.v === s.quality)));
  $("quality-note").textContent = t("q_note_" + s.quality);
  $("set-resolution").value = s.resolution;
  $("set-fps").value = String(s.fps);
  $("set-vsync").checked = s.vsync;
  $("set-overlay").checked = s.overlay;
  $("set-lang").value = s.lang;
}
async function saveSettings(patch) {
  const next = Object.assign({}, settingsCache, patch);
  const s = await call("set_settings", { settings: next });
  render(s);
  fillSettings(s.settings);
}
$("btn-settings").addEventListener("click", () => {
  if (!settingsCache) return;
  fillSettings(settingsCache);
  $("settings-msg").textContent = "";
  $("settings").hidden = false;
});
$("btn-settings-close").addEventListener("click", () => ($("settings").hidden = true));
$("settings").addEventListener("click", (e) => { if (e.target.id === "settings") $("settings").hidden = true; });
document.addEventListener("keydown", (e) => { if (e.key === "Escape") $("settings").hidden = true; });
document.querySelectorAll("#set-quality button").forEach((b) => b.addEventListener("click", () => saveSettings({ quality: b.dataset.v })));
$("set-resolution").addEventListener("change", (e) => saveSettings({ resolution: e.target.value }));
$("set-fps").addEventListener("change", (e) => saveSettings({ fps: Number(e.target.value) }));
$("set-vsync").addEventListener("change", (e) => saveSettings({ vsync: e.target.checked }));
$("set-overlay").addEventListener("change", (e) => saveSettings({ overlay: e.target.checked }));
$("set-lang").addEventListener("change", async (e) => { await saveSettings({ lang: e.target.value }); applyLang(e.target.value); fillSettings(settingsCache); });
$("btn-report").addEventListener("click", async () => {
  try { $("settings-msg").textContent = t("report_saved", { path: await call("save_report") }); }
  catch (err) { $("settings-msg").textContent = String(err); }
});
$("btn-forget").addEventListener("click", async () => { await call("forget_devices"); $("settings-msg").textContent = t("devices_forgotten"); });

$("btn-netcheck").addEventListener("click", async () => {
  const btn = $("btn-netcheck");
  const list = $("netcheck-list");
  const summary = $("netcheck-summary");
  btn.disabled = true;
  btn.textContent = t("netcheck_running");
  let items = [];
  try { items = await call("check_network"); } catch (e) { items = []; summary.textContent = String(e); }
  btn.disabled = false;
  btn.textContent = t("netcheck_run");
  list.innerHTML = "";
  let group = "";
  for (const it of items) {
    if (it.group !== group) {
      group = it.group;
      const g = document.createElement("li");
      g.innerHTML = `<span class="group"></span>`;
      g.firstChild.textContent = t("grp_" + group);
      g.style.display = "block";
      list.append(g);
    }
    const li = document.createElement("li");
    const dot = document.createElement("span");
    dot.className = "dot " + (it.ok ? "good" : it.group === "router" || it.group === "zapret" ? "fair" : "poor");
    const name = document.createElement("span");
    name.textContent = it.name;
    const info = document.createElement("small");
    // Server response times are a one-off cost while connecting, not game latency: don't show them.
    info.textContent = it.ok ? t("nc_reachable") : t("nc_unreachable");
    if (it.group === "zapret") info.textContent = it.ok ? "" : "IPSet/Game Filter";
    li.title = it.detail || "";
    li.append(dot, name, info);
    list.append(li);
  }
  list.hidden = items.length === 0;
  const servers = items.filter((i) => i.group === "server");
  const up = servers.filter((i) => i.ok).length;
  const notes = [];
  if (servers.length) notes.push(up === 0 ? t("nc_all_down") : up < servers.length ? t("nc_some_down") : t("nc_all_ok"));
  const stun = items.filter((i) => i.group === "stun");
  if (stun.length && !stun.some((i) => i.ok)) notes.push(t("nc_stun_down"));
  if (items.some((i) => i.group === "zapret" && !i.ok)) notes.push(t("nc_zapret"));
  summary.textContent = notes.join(" ");
  summary.hidden = notes.length === 0;
  $("netcheck-note").hidden = true;
});

/* no context menu / text selection outside inputs: feels like an app, not a page */
document.addEventListener("contextmenu", (e) => { if (!e.target.closest("input, .code")) e.preventDefault(); });

/* ------------------------------------------------------------------ poll loop */

async function tick() {
  try { render(await call("get_state")); } catch (e) { console.error(e); }
  setTimeout(tick, state && state.phase !== "idle" ? 300 : 700);
}
applyLang("auto");
tick();

/* ------------------------------------------------------------------ browser preview mock */

function mock(cmd, args) {
  const m = (window.__mock = window.__mock || {
    s: {
      version: "0.1.0", name: "IVAN-PC", code: "482913507", signal: "ok", host_ready: true,
      phase: "idle", role: null, stage: null, peer: null, target_code: null, error: null, incoming: null,
      rtt_ms: 0, rtt_history: [], path: "direct", rx_bytes: 0, tx_bytes: 0, stream: null,
      settings: { quality: "auto", resolution: "native", fps: 0, vsync: false, overlay: false, lang: "auto" },
    },
  });
  const s = m.s;
  const scene = new URLSearchParams(location.search).get("scene");
  if (scene && !m.sceneSet) {
    m.sceneSet = true;
    if (scene === "connecting") Object.assign(s, { phase: "connecting", role: "client", stage: "punching", target_code: "715203998" });
    if (scene === "live") {
      Object.assign(s, { phase: "live", role: "client", stage: "streaming", peer: "MAXIM-GAMING", path: "direct", stream: { width: 1920, height: 1080, fps: 120, bitrate_kbps: 38000 } });
      s.rtt_history = Array.from({ length: 60 }, (_, i) => 21 + Math.sin(i / 4) * 2 + (i % 13 === 0 ? 9 : 0));
      s.rtt_ms = 22.4; s.rx_bytes = 4.1e8; s.tx_bytes = 2e6;
    }
    if (scene === "incoming") s.incoming = { name: "MAXIM-GAMING" };
    if (scene === "waiting") Object.assign(s, { phase: "connecting", role: "client", stage: "waiting", done_stages: ["preparing", "contacting"], target_code: "715203998" });
    if (scene === "error") s.error = { code: "nat" };
    if (scene === "host") Object.assign(s, { phase: "live", role: "host", stage: "streaming", peer: "MAXIM-GAMING", rtt_ms: 23, rtt_history: Array.from({ length: 40 }, (_, i) => 22 + Math.cos(i / 3) * 3) });
  }
  if (s.phase === "live") { s.rx_bytes += 4.5e6; s.tx_bytes += 1e5; }
  switch (cmd) {
    case "connect": Object.assign(s, { phase: "connecting", role: "client", stage: "preparing", target_code: args.code, error: null }); break;
    case "cancel": case "disconnect": Object.assign(s, { phase: "idle", role: null, stage: null }); break;
    case "respond": s.incoming = null; break;
    case "set_settings": s.settings = args.settings; break;
    case "save_report": return Promise.resolve("C:\\Users\\Ivan\\Downloads\\LowLag-report.txt");
    case "check_network": return new Promise((r) => setTimeout(() => r([
      { group: "server", name: "ntfy.sh", ok: false, detail: "timeout", ms: 8000 },
      { group: "server", name: "broker.emqx.io", ok: true, detail: "", ms: 140 },
      { group: "server", name: "broker.hivemq.com", ok: true, detail: "", ms: 160 },
      { group: "server", name: "test.mosquitto.org", ok: true, detail: "", ms: 90 },
      { group: "stun", name: "stun.cloudflare.com", ok: true, detail: "93.0.0.1", ms: 40 },
      { group: "stun", name: "stun.l.google.com", ok: true, detail: "93.0.0.1", ms: 55 },
      { group: "router", name: "UPnP", ok: false, detail: "not available", ms: 2000 },
      { group: "zapret", name: "Zapret", ok: false, detail: "IPSet any", ms: 0 },
    ]), 800));
  }
  return Promise.resolve(JSON.parse(JSON.stringify(s)));
}
