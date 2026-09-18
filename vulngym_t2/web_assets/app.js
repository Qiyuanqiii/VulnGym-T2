"use strict";
const $ = (id) => document.getElementById(id);
const token = document.querySelector('meta[name="t2-session"]').content;
const activeStates = new Set(["preparing", "running", "stopping"]);
const labels = {
  preparing: "检查输入中", prepared: "输入已就绪", running: "提取中",
  stopping: "正在完成当前条目", finished: "处理结束", imported: "历史结果",
  error: "需要处理", supported: "找到依据", uncertain: "待确认", missing: "缺少信息",
  conflicting: "存在冲突", complete: "字段已齐 · 待确认", draft: "信息不全 · 待补充",
  stopped_by_user: "已按要求停止", completed: "处理完成",
  completed_with_errors: "部分条目处理失败", provider_stopped: "模型调用已停止",
  interrupted: "已中断", input_failure: "输入检查失败",
};
const fieldNames = {
  entry_point: "源码入口位置", critical_operation: "关键操作", trace: "调用路径与条件",
  commit: "源码版本", vuln_title: "条目标题", vuln_category_l1: "一级分类",
  vuln_category_l2: "二级分类", vuln_ids: "公告标识",
};
const errorNames = {
  another_operation_is_active: "已有任务正在运行，请等待它结束。",
  input_preparation_failed: "输入检查未通过，请查看具体问题后修改资料。",
  provide_material_not_only_a_url: "只有链接时，请切换到“粘贴公告链接（GHSA / OSV）”。本地资料模式需要公告正文或文件。",
  no_ready_url_inputs: "本批尚无可提取的资料。请查看各链接的获取失败原因，补充资料或恢复网络后重新检查。",
  ghsa_urls_required: "请粘贴至少一个 GitHub GHSA 或 OSV 公告链接。",
  ghsa_urls_invalid: "请使用 GitHub GHSA 公告链接，或 https://osv.dev/vulnerability/公告编号 形式的 OSV 链接。",
  ghsa_urls_too_large: "链接文本过长，请拆分批次。",
  ghsa_url_limit: "每批最多 20 个不同公告链接，请拆分批次。",
  advisory_urls_required: "请粘贴至少一个 GitHub GHSA 或 OSV 公告链接。",
  advisory_urls_invalid: "请使用 GitHub GHSA 链接、OSV 公告页面链接或 api.osv.dev/v1/vulns/公告编号 链接。",
  advisory_urls_too_large: "链接文本过长，请拆分批次。",
  advisory_url_limit: "每批最多 20 个不同公告链接，请拆分批次。",
  github_rate_limited: "GitHub 暂时限制了请求；本次不会自动重试。请稍后重新检查，或切换到已有本地资料。",
  osv_urls_invalid: "OSV 链接格式不正确，请使用 https://osv.dev/vulnerability/公告编号。",
  osv_rate_limited: "OSV 暂时限制了请求（429）；本次不会自动重试或切换来源。请稍后重新检查，或使用本地资料。",
  osv_access_denied: "OSV 拒绝访问该公告（403）；本次已停止获取，不会轮换网络或自动重试。",
  osv_not_found: "OSV 未找到该公告（404），请核对公告编号。",
  osv_response_invalid: "OSV 返回的公告格式或编号不匹配，无法作为可靠输入，请核对链接。",
  osv_too_large: "OSV 公告超过自动获取的大小限制，请使用本地资料。",
  osv_redirect_blocked: "OSV 请求发生了未允许的跳转，已停止获取，请核对链接。",
  osv_http_failed: "OSV 公告接口返回错误，本次不会自动重试，请稍后检查或使用本地资料。",
  osv_download_failed: "OSV 公告下载失败，请检查网络或使用本地资料。",
  osv_cache_invalid: "已缓存的 OSV 公告无效，请保留现场并检查缓存文件。",
  osv_ghsa_missing: "该 OSV 公告未提供对应的 GHSA 编号，暂不能按本题的 GHSA 输出格式提取；请补充关联公告。",
  osv_ghsa_ambiguous: "该 OSV 公告关联了多个 GHSA，无法确定本次条目对应哪一条；请明确目标公告。",
  osv_reviewed_origin_unconfirmed: "OSV 未明确确认该公告经过 GitHub 审核，不能据此填写本题要求的 reviewed 来源，暂不能开始提取。",
  osv_record_withdrawn: "该 OSV 公告已撤回，暂不作为提取输入，请核对有效公告。",
  osv_repository_missing: "OSV 公告中未找到明确的源码仓库，请使用本地资料补充仓库。",
  osv_repository_ambiguous: "OSV 公告涉及多个候选仓库，请使用本地资料明确目标仓库。",
  osv_repository_unsupported: "OSV 公告指向的仓库暂不支持自动获取，请使用本地资料。",
  advisory_download_failed: "公告下载失败，请检查网络后重新检查，或使用本地资料。",
  advisory_access_denied: "GitHub 拒绝访问该公告，请检查是否为可公开访问的公告，或使用本地资料。",
  advisory_not_found: "未找到该公告（404），请核对 GHSA 链接。",
  advisory_material_missing: "尚未取得公告正文。",
  repository_path_missing: "尚未取得可读取的源码仓库。",
  advisory_repository_missing: "公告中未找到目标仓库，请使用本地资料并补充源码仓库路径。",
  advisory_repository_ambiguous: "公告涉及多个候选仓库，无法确定目标；请使用本地资料明确仓库。",
  advisory_repository_unsupported: "公告指向的仓库暂不支持自动获取，请使用本地资料。",
  repository_download_failed: "源码仓库下载失败，请检查网络，或使用已有本地仓库。",
  repository_download_timeout: "源码仓库下载超时，本次不会自动重试；可以使用已有本地仓库。",
  repository_download_too_large: "源码仓库超过自动下载大小限制，请使用本地仓库。",
  download_disk_space_low: "下载目录磁盘空间不足，已停止获取资料。",
  download_cache_size_limit: "本地下载缓存达到大小限制，已停止获取资料。",
  git_unavailable: "未找到 Git，暂时无法自动获取仓库；请安装 Git 后重新打开工作台。",
  provide_one_to_eight_materials: "正文和文件合计需要 1–8 份资料。",
  request_cap_exceeds_remaining: "本批上限超出剩余额度，请调低。",
  ledger_unavailable_or_unfinished_request: "用量记录暂不可用或有未结束的请求，暂时不能开始。",
  managed_usage_unavailable: "本机用量记录暂不可用，暂时不能开始提取。请检查本地服务；已用次数不会自动清零。",
  managed_request_total_reached: "本机累计请求次数已达到安全上限，暂时不能开始新的提取。已有结果仍可查看和导出。",
  managed_budget_account_conflict: "本机用量配置存在冲突，暂时不能开始。请保留现有记录并检查配置，不要清零。",
  result_unavailable_or_too_large: "预览不可用或文件过大；仍可尝试导出原文件，或查看本地输出目录。",
  absolute_local_path_required: "请填写以盘符开头的本地完整路径。",
  local_path_required: "此处需要本地文件路径。若要粘贴 URL，请切换到“粘贴公告链接（GHSA / OSV）”。",
  run_not_prepared: "本批输入尚未检查通过，请重新检查。",
  read_only_mode: "演示模式不调用模型，只能查看和导出已有结果。",
};
let snapshot = null, selectedRun = null, selectedCase = 0;
let result = null, resultRun = null, loadingResult = null, previewError = "";
let inputSignature = "", busy = false, connected = false;
let preparedId = null, preparedFingerprint = null, preparationChanged = false;
let selectionVersion = 0, stateRequest = 0, choicesSignature = "", downloadRun = null;
let returnField = null, stopPending = false;
const resultNames = new Map();
let homeIntake = false;
let capEdited = false;

const systemTheme = window.matchMedia("(prefers-color-scheme: dark)");
let themeChosen = false;
function setTheme(dark) {
  document.documentElement.dataset.theme = dark ? "dark" : "light";
  $("theme-toggle").setAttribute("aria-pressed", String(dark));
  $("theme-toggle").setAttribute("aria-label", dark ? "切换到浅色外观" : "切换到深色外观");
  $("theme-label").textContent = dark ? "浅色" : "深色";
}
setTheme(systemTheme.matches);
$("theme-toggle").addEventListener("click", () => {
  themeChosen = true;
  setTheme(document.documentElement.dataset.theme !== "dark");
});
systemTheme.addEventListener("change", (event) => { if (!themeChosen) setTheme(event.matches); });

function element(tag, text, className) {
  const node = document.createElement(tag);
  if (text !== undefined) node.textContent = String(text);
  if (className) node.className = className;
  return node;
}
function message(text) {
  $("notice").textContent = text;
  $("notice").hidden = !text;
  $("dialog-notice").textContent = text;
  $("dialog-notice").hidden = !text;
  if (text && ($("new-dialog").open || homeIntake)) $("dialog-notice").scrollIntoView({block: "nearest"});
}
function readableError(error) {
  if (error?.name === "TimeoutError" || error?.name === "AbortError")
    return "本地服务响应超时。不会自动重跑任务，请检查连接后重试查看。";
  if (error instanceof TypeError) return "连接已中断。操作是否已接收需以任务状态为准，请勿重复启动。";
  return error.message || "操作未完成，请检查本地服务。";
}
async function api(path, body) {
  const response = await fetch(path, {
    method: body === undefined ? "GET" : "POST",
    headers: {"X-T2-Session": token, ...(body === undefined ? {} : {"Content-Type": "application/json"})},
    body: body === undefined ? undefined : JSON.stringify(body),
    cache: "no-store",
    // Time out reads only. A lost start response must never trigger an automatic retry.
    ...(body === undefined ? {signal: AbortSignal.timeout(15000)} : {}),
  });
  const value = await response.json();
  if (!response.ok) throw new Error(errorNames[value.code] || "操作未完成（" + (value.code || response.status) + "）。请查看运行记录。");
  return value;
}
function current() { return snapshot?.runs.find((run) => run.id === selectedRun); }
function activeRun() { return snapshot?.runs.find((run) => activeStates.has(run.state)); }
function preparedRun() { return snapshot?.runs.find((run) => run.id === preparedId); }
function readOnlyMode() { return snapshot?.read_only === true; }
function managedUsageMode() { return !readOnlyMode() && snapshot?.budget.managed === true; }
function inputErrorText(value) {
  // Preparation can combine acquisition and local-input failures. Display each
  // cause, rather than losing the useful cause behind a compound code string.
  const codes = [...new Set(String(value || "").split(";").map((code) => code.trim()).filter(Boolean))];
  return codes.slice(0, 12).map((code) => typeof errorNames[code] === "string" ? errorNames[code]
    : /^[a-z][a-z0-9_]{0,79}$/.test(code) ? "需处理（" + code + "）" : "资料检查失败，请查看运行记录。").join(" ");
}

// The preparation binding belongs to this form, never to the history selection.
function formFingerprint() {
  return JSON.stringify({
    mode: $("mode").value, urls: $("urls").value, text: $("material").value, path: $("input-path").value,
    repo: $("repo").value, source: $("source").value, cache: $("cache").value, mapping: $("mapping").value,
    files: [...$("files").files].map((file) => [file.name, file.size, file.lastModified, file.type]),
  });
}
function invalidatePreparation() {
  if (preparedId) preparationChanged = true;
  preparedId = preparedFingerprint = null;
  $("confirmed").checked = false;
  controls();
}
// This count is only a UI estimate; the server validates and deduplicates the
// submitted text before fetching anything. Never silently raise an edited cap.
function suggestedAdvisoryKeys(text) {
  const tokens = text.match(/https:\/\/[^\s<>"\[\]()]+/gi) || [];
  const keys = [];
  const ghsaId = /^GHSA-[23456789cfghjmpqrvwx]{4}-[23456789cfghjmpqrvwx]{4}-[23456789cfghjmpqrvwx]{4}$/i;
  for (const token of tokens) {
    const url = token.replace(/[.,;!?，。；！？]+$/, "");
    const github = url.match(/^https:\/\/github\.com\/advisories\/(GHSA-[a-z0-9-]+)\/?$/i);
    if (github && ghsaId.test(github[1])) {
      keys.push("github:" + github[1].toLowerCase());
      continue;
    }
    const osv = url.match(/^https:\/\/(?:osv\.dev\/vulnerability|api\.osv\.dev\/v1\/vulns)\/([a-z0-9][a-z0-9._-]{0,159})\/?$/i);
    if (!osv || osv[1].includes("..") || osv[1].endsWith(".")
      || /^(?:CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])(?:\.|$)/i.test(osv[1])) continue;
    let id = osv[1];
    if (/^GHSA-/i.test(id)) {
      if (!ghsaId.test(id)) continue;
      id = id.toLowerCase();
    } else if (/^CVE-/i.test(id)) id = id.toUpperCase();
    keys.push("osv:" + id);
  }
  // OSV page/API aliases merge, but GitHub and OSV remain distinct sources.
  return new Set(keys);
}
function updateUrlSuggestion() {
  const count = suggestedAdvisoryKeys($("urls").value).size;
  const suggested = Math.min(20, Math.max(1, count)) * 12;
  $("urls-hint").textContent = count > 20 ? "识别到 " + count + " 个不同链接；每批最多 20 条，请拆分批次。"
    : (count ? "识别到 " + count + " 个不同链接，建议本批上限 " + suggested + " 次请求。" : "")
      + "空格、换行或 Markdown 链接都可以，自动去重；无需逐个添加。每批最多 20 条。";
  if ($("mode").value === "urls" && !capEdited && $("cap").value !== String(suggested)) {
    $("cap").value = String(suggested);
    $("confirmed").checked = false;
  }
}
function updateInputMode() {
  const mode = $("mode").value;
  $("urls-controls").hidden = mode !== "urls";
  $("material-controls").hidden = mode !== "material";
  $("batch-controls").hidden = mode !== "batch";
  $("local-controls").hidden = mode === "urls";
  updateUrlSuggestion();
  controls();
}
function startProblem() {
  const prepared = preparedRun(), budget = snapshot?.budget;
  if (readOnlyMode()) return errorNames.read_only_mode;
  if (!connected) return "本地服务未连接，暂时不能开始。";
  if (busy) return "正在提交，请稍候。";
  if (activeRun()) return "已有任务正在运行；结束后才能开始新的提取。";
  if (!preparedId || preparedFingerprint !== formFingerprint())
    return preparationChanged ? "资料已改动，请重新检查输入。" : "请先完成第 1 步“"
      + ($("mode").value === "urls" ? "获取资料并检查" : "检查输入") + "”。";
  if (prepared?.state !== "prepared") return "输入尚未检查通过，请查看上方的检查结果。";
  if (!budget?.available || budget.pending) return managedUsageMode()
    ? (errorNames[budget.code] || errorNames.managed_usage_unavailable) : "用量记录未就绪或有未结束请求，暂时不能开始。";
  const maximum = Math.min(500, budget.remaining), cap = Number($("cap").value);
  if (maximum < 1) return managedUsageMode() ? errorNames.managed_request_total_reached : "请求额度已用完。";
  if (!Number.isInteger(cap) || cap < 1 || cap > maximum) return "请将本批请求上限设为 1–" + maximum + " 次。";
  if (!$("key").value.trim()) return "请填写本次使用的 API key。";
  if (!/^[\x21-\x7e]{1,500}$/.test($("key").value)) return "API key 不能包含空格或非英文字符。";
  if (!$("confirmed").checked) return managedUsageMode()
    ? "请勾选资料发送与本批请求上限确认，然后开始。" : "请勾选资料发送与额度确认，然后开始。";
  return "";
}
function controls() {
  const active = activeRun(), readOnly = readOnlyMode();
  $("case-search").disabled = !result || resultRun !== selectedRun;
  $("case-filter").disabled = !result || resultRun !== selectedRun;
  $("new-run").disabled = readOnly;
  $("new-run").title = readOnly ? errorNames.read_only_mode : "";
  $("intake-hint").textContent = readOnly ? "可切换批次、搜索条目及导出结果" : "一次粘贴多个链接 / 正文 / 文件";
  $("prepare").disabled = readOnly || busy || Boolean(active) || !connected;
  $("input-fields").disabled = readOnly || busy;
  for (const id of ["key", "cap", "confirmed"]) $(id).disabled = readOnly;
  $("prepare").textContent = $("mode").value === "urls" ? "获取资料并检查" : "检查输入";
  $("prepare-reason").textContent = readOnly ? errorNames.read_only_mode : !connected ? "请先恢复本地服务连接" : active
    ? "请等待当前任务结束" : busy ? "正在提交…" : $("mode").value === "urls"
      ? "联网获取公开资料，不调用模型" : "免费，不调用模型";
  $("cap").max = String(Math.max(0, Math.min(500, snapshot?.budget.remaining ?? 500)));
  $("cap-hint").textContent = managedUsageMode()
    ? "这是本批的停止上限，不是要用满的次数；每批最多 500 次。已用次数会自动累计保存。"
    : "这是停止上限，不是要用满的次数。与右上角总额度共同生效。";
  $("confirmation-text").textContent = managedUsageMode()
    ? "我确认将已检查的资料和相关源码发送给模型，并允许本批最多使用上述请求次数。"
    : "我确认将已检查的资料和相关源码发送给模型，并允许使用上述额度。";
  const problem = startProblem();
  $("start").disabled = Boolean(problem);
  $("start-reason").textContent = problem || "本批已就绪，最多使用 " + $("cap").value + " 次模型请求。";
  $("active-banner").hidden = !active;
  $("active-text").textContent = active ? labels[active.state] + " · " + runName(active) : "";
  $("show-active").hidden = !active || active.id === selectedRun;
  $("stop").hidden = readOnly || !active || active.state === "preparing";
  $("stop-note").hidden = $("stop").hidden;
  $("stop").disabled = readOnly || !connected || stopPending || active?.state !== "running";
  $("stop").textContent = active?.state === "stopping" ? "已请求停止，等待当前条目保存" : "完成当前条目后停止";
  renderPrepared();
}
function renderPrepared() {
  const run = preparedRun(), box = $("prepared-summary");
  box.hidden = !run && !preparationChanged;
  const failed = run?.inputs.filter((item) => item.input_error).length || 0;
  const lines = !run ? ["资料已更改；旧检查结果不能用于当前表单，请重新检查。"] :
    [(labels[run.state] || "检查结果") + " · " + run.inputs.length + " 份资料",
      ...(run.state === "error" && run.code ? [errorNames[run.code] || run.code] : []),
      ...(failed && $("mode").value === "urls" ? [(run.inputs.length - failed) + " 份可提取，" + failed
        + " 份资料获取失败；失败项保留原因，不调用模型。"] : []),
      ...(run.state === "preparing" && $("mode").value === "urls" ? ["正在获取公开资料并检查，请保持服务运行。尚未调用模型。",
        ...(run.events?.length ? [eventText(run.events.at(-1))] : [])] : []),
      ...run.inputs.map((item) => (item.report_id || "未识别公告") + "：" + (item.input_error
        ? inputErrorText(item.input_error) : "可以开始提取"))];
  const signature = JSON.stringify(lines);
  if (box.dataset.signature !== signature) {
    box.dataset.signature = signature;
    box.replaceChildren(...lines.map((line) => element("p", line)));
  }
}
async function action(fn) {
  if (busy) return;
  busy = true;
  controls();
  message("");
  try { await fn(); }
  catch (error) { message(readableError(error)); }
  finally {
    busy = false;
    try { await refresh(); } catch { /* Connection state is shown separately. */ }
    controls();
  }
}
// Reuse the same live forms in the empty workspace and the dialog. Reparenting
// preserves selected files and input handlers; polling never rebuilds the form.
function moveIntake(home) {
  const destination = home ? $("home-intake-slot") : $("dialog-intake-slot");
  if ($("intake-content").parentElement !== destination) destination.append($("intake-content"));
  homeIntake = home;
  $("intake-home").hidden = !home;
  $("review-toolbar").hidden = home;
  $("review-panel").setAttribute("aria-labelledby", home ? "home-heading" : "evidence-heading");
  if (home) {
    $("result-empty").hidden = true;
    $("result-content").hidden = true;
  }
}
function renderHomeIntake() {
  if (!snapshot) return;
  $("workspace").dataset.empty = String(snapshot.runs.length === 0);
  if (readOnlyMode()) {
    if ($("new-dialog").open) $("new-dialog").close();
    moveIntake(false);
    if (!snapshot.runs.length) empty("演示模式 · 不调用模型", "暂无可查看的演示批次。请在启动服务时指定已有结果。");
    return;
  }
  if ($("new-dialog").open) return;
  if (snapshot.runs.length === 0) moveIntake(true);
  // Keep the inline form during its free preparation so the next step stays
  // where the user is working. Leave it only for a running task or saved result.
  if (homeIntake) {
    const run = current();
    if (run?.results_available || ["running", "stopping"].includes(run?.state)) moveIntake(false);
    else moveIntake(true);
  }
}
function openIntake() {
  if (readOnlyMode()) return;
  moveIntake(false);
  $("dialog-notice").hidden = true;
  if (!$("new-dialog").open) $("new-dialog").showModal();
  controls();
  ($("mode").value === "urls" ? $("urls") : $("mode").value === "batch" ? $("input-path") : $("material")).focus({preventScroll: true});
}
$("new-run").addEventListener("click", openIntake);
$("close-dialog").addEventListener("click", () => $("new-dialog").close());
$("new-dialog").addEventListener("close", () => {
  $("key").value = "";
  $("confirmed").checked = false;
  renderHomeIntake();
  controls();
  $("new-run").focus({preventScroll: true});
});
$("prepare-form").addEventListener("input", invalidatePreparation);
$("prepare-form").addEventListener("change", invalidatePreparation);
$("mode").addEventListener("change", updateInputMode);
$("urls").addEventListener("input", updateUrlSuggestion);
$("files").addEventListener("change", () => {
  const names = [...$("files").files].map((file) => file.name);
  $("file-list").textContent = (names.length ? names.length + " 个文件：" + names.join(" · ") + "。" : "")
    + "正文优先作为主公告，否则使用第一个文件。合计最多 8 份，每份 256 KB。";
});
$("cap").addEventListener("input", () => { capEdited = true; $("confirmed").checked = false; controls(); });
$("key").addEventListener("input", controls);
$("confirmed").addEventListener("change", controls);
$("prepare-form").addEventListener("submit", (event) => {
  event.preventDefault();
  if ($("prepare").disabled) return;
  return action(async () => {
    const fingerprint = formFingerprint();
    const payload = {mode: $("mode").value};
    if (payload.mode === "urls") {
      payload.urls = $("urls").value.trim();
      if (!payload.urls) throw new Error("请粘贴至少一个 GHSA 或 OSV 公告链接，可一次粘贴整批。");
      if (new TextEncoder().encode(payload.urls).length > 65536) throw new Error("链接文本过长，请分批粘贴；每批最多 20 个不同链接。");
    } else {
      Object.assign(payload, {repo: $("repo").value.trim(), source_link: $("source").value.trim(),
        cache_dir: $("cache").value.trim(), repo_map: $("mapping").value.trim()});
    }
    if (payload.mode === "batch") {
      payload.input_path = $("input-path").value.trim();
      if (!payload.input_path) throw new Error("请填写批次文件的完整路径。");
    } else if (payload.mode === "material") {
      const files = [...$("files").files], text = $("material").value;
      const count = files.length + Number(Boolean(text.trim()));
      if (count < 1 || count > 8) throw new Error("正文和文件合计需要 1–8 份资料；粘贴的正文也算一份。");
      if (files.some((file) => file.size > 256 * 1024) || new TextEncoder().encode(text).length > 256 * 1024)
        throw new Error("每份文件和粘贴正文均不能超过 256 KB。");
      payload.text = text;
      payload.files = await Promise.all(files.map(async (file) => ({name: file.name, text: await file.text()})));
    }
    invalidatePreparation();
    const response = await api("/api/prepare", payload);
    if (formFingerprint() === fingerprint) {
      preparedId = response.run_id;
      preparedFingerprint = fingerprint;
      preparationChanged = false;
    }
    chooseRun(response.run_id);
  });
});
$("run-form").addEventListener("submit", (event) => {
  event.preventDefault();
  const problem = startProblem();
  if (problem) { controls(); return; }
  const id = preparedId;
  return action(async () => {
    let key = $("key").value;
    $("key").value = "";
    try {
      await api("/api/start", {run_id: id, key, max_requests: Number($("cap").value), confirmed: $("confirmed").checked});
      chooseRun(id);
      $("new-dialog").close();
      message("提取已开始。请保持本地服务和电脑运行；关闭页面不会中止任务。");
    } finally {
      key = "";
      $("confirmed").checked = false;
    }
  });
});
$("show-active").addEventListener("click", () => {
  const run = activeRun();
  if (run) { chooseRun(run.id); render(); }
});
$("stop").addEventListener("click", async () => {
  const run = activeRun();
  if (readOnlyMode() || !run || run.state !== "running" || stopPending || !connected) return;
  stopPending = true;
  controls();
  try {
    await api("/api/stop", {run_id: run.id});
    message("停止请求已提交。当前条目完成并保存后停止，不会开始下一条。");
  } catch (error) { message(readableError(error)); }
  finally {
    stopPending = false;
    try { await refresh(); } catch { /* Status explains connection loss. */ }
    controls();
  }
});

function empty(title, description, retry = false) {
  $("result-empty").hidden = false;
  $("result-content").hidden = true;
  $("empty-title").textContent = title;
  $("empty-description").textContent = description;
  $("retry-preview").hidden = !retry;
}
function chooseRun(id) {
  selectedRun = id;
  selectedCase = 0;
  selectionVersion++;
  result = resultRun = loadingResult = null;
  previewError = inputSignature = "";
  returnField = null;
  $("back-to-field").hidden = true;
  $("case-search").value = "";
  $("case-filter").value = "all";
  $("cases").replaceChildren(element("p", "正在读取批次…", "empty-small"));
  $("case-count").textContent = "0 条结果";
  $("candidate-coverage").hidden = true;
  $("candidate-coverage").open = false;
  $("candidate-coverage-summary").textContent = "候选提案覆盖：未记录";
  $("candidate-coverage-detail").replaceChildren();
  $("run-select").value = id;
  renderDownloads(current()?.results_available ? id : null);
  empty("尚无结果", "提取完成后可以在这里查看条目。");
}
$("run-select").addEventListener("change", () => { chooseRun($("run-select").value); render(); });
$("run-select").addEventListener("blur", () => renderRunChoices());
$("case-search").addEventListener("input", () => renderCases());
$("case-filter").addEventListener("change", () => renderCases());
$("retry-preview").addEventListener("click", () => {
  const run = current();
  if (run?.results_available) return loadResult(run);
});
function runName(run) {
  if (resultNames.has(run.id)) return resultNames.get(run.id);
  const parts = (run.output_path || "").split(/[\\/]/).filter(Boolean);
  const name = parts.at(-1) === "output" ? parts.at(-2) : parts.at(-1);
  if (name && !/^[a-f0-9]{16}$/i.test(name)) return name;
  const date = new Date(run.created);
  return (run.state === "imported" ? "导入批次" : "新建批次") + " " + (Number.isNaN(date.getTime()) ? "" :
    date.toLocaleString("zh-CN", {month: "2-digit", day: "2-digit", hour: "2-digit", minute: "2-digit", hour12: false}))
    + " · " + run.id.slice(0, 4);
}
function renderRunChoices() {
  if (!snapshot) return;
  const select = $("run-select");
  // The option list may be unchanged while the selected batch changes. Keep
  // its tooltip/accessibility help current without rebuilding a focused menu.
  select.title = current() ? runName(current()) : "选择批次";
  if (document.activeElement === select) return;
  const rows = snapshot.runs.map((run) => [run.id, runName(run) + " · " + (labels[run.state] || "待查看")]);
  const signature = JSON.stringify(rows);
  if (signature !== choicesSignature) {
    choicesSignature = signature;
    const options = rows.map(([id, title]) => {
      const option = element("option", title); option.value = id; return option;
    });
    if (!options.length) { const placeholder = element("option", "还没有批次"); placeholder.value = ""; options.push(placeholder); }
    select.replaceChildren(...options);
  }
  select.value = selectedRun || "";
  select.disabled = !rows.length;
}
function renderChecks(run) {
  const signature = JSON.stringify(run.inputs);
  if (signature === inputSignature) return;
  inputSignature = signature;
  $("input-checks").replaceChildren(...run.inputs.map((item) => {
    const box = element("details");
    box.open = Boolean(item.input_error);
    box.append(element("summary", (item.input_error ? "需处理" : "已就绪") + " · " + item.report_id));
    box.append(element("p", "资料 " + (item.document_count ?? 0) + " 份 · 修复线索 " + (item.fix_candidates ?? 0) + " 个", "hint"));
    if (item.input_error) box.append(element("p", inputErrorText(item.input_error), "check-error"));
    for (const warning of item.input_warnings || []) box.append(element("p", warning, "hint"));
    return box;
  }));
}
function eventText(event) {
  const acquisitionLabels = {acquisition_advisory: "正在获取公开公告", acquisition_repository: "正在获取源码仓库",
    acquisition_ready: "资料已获取", acquisition_failed: "资料获取失败"};
  if (acquisitionLabels[event.event]) return "第 " + event.index + "/" + event.total + " 份 · "
    + acquisitionLabels[event.event] + " · " + (event.report_id || "")
    + (event.code ? "：" + (errorNames[event.code] || event.code) : "");
  if (event.event === "report_started") return "开始第 " + event.index + "/" + event.total + " 份资料 · " + event.report_id;
  if (event.event === "report_finished") return "第 " + event.index + " 份资料已处理 · " + (event.complete_candidate ? "有字段已齐的结果" : "结果待补充");
  if (event.event === "http_started") return "请求 #" + event.request + " 已发送";
  if (event.event === "http_finished") return "请求 #" + event.request + " · " + event.status + (event.seconds === undefined ? "" : " · " + event.seconds + "s");
  if (event.event === "format_failure_isolated") return "当前条目格式检查失败，问题已记录";
  return event.event;
}
function candidatePlanRows(reviews) {
  // Projection of saved controller plans only: no inferred proposal, status,
  // omission, or zero for records that predate this metadata.
  const groups = new Map(), object = (value) => value && typeof value === "object" && !Array.isArray(value);
  for (const [index, review] of (Array.isArray(reviews) ? reviews : []).entries()) {
    if (!object(review)) continue;
    const identity = review.input_id ?? review.entry_id;
    const identified = typeof identity === "string" && Boolean(identity.trim());
    const key = identified ? identity : Symbol(index);
    if (!groups.has(key)) groups.set(key, {id: identified ? identity : "输入标识未记录", reviews: [], identified});
    groups.get(key).reviews.push(review);
  }
  return [...groups.values()].map((group) => {
    const base = {id: group.id, state: "unrecorded"};
    if (!group.identified) return base;
    const scopes = new Set(group.reviews.map((row) => row.process_metadata_scope ?? "legacy"));
    if (scopes.size !== 1) return {...base, state: "inconsistent"};
    const scope = [...scopes][0];
    let lists;
    if (scope === "candidate_with_shared_usage" || scope === "shared_input") {
      const anchors = group.reviews.filter((row) => row.slot === 1);
      if (anchors.length !== 1) return {...base, state: anchors.length ? "inconsistent" : "unrecorded"};
      lists = [anchors[0][scope === "candidate_with_shared_usage" ? "input_actions" : "actions"]];
    } else if (scope === "legacy") lists = group.reviews.map((row) => row.actions);
    else return base;
    if (lists.some((list) => list !== undefined && !Array.isArray(list))) return {...base, state: "inconsistent"};
    const plans = lists.flatMap((list) => Array.isArray(list) ? list.filter((row) => object(row) && row.action === "candidate_plan") : []);
    if (!plans.length) return base;
    const plan = plans[0], keys = ["proposed_count", "selected_count", "omitted_count"];
    if (plans.length !== 1 || !keys.every((key) => Number.isInteger(plan[key]) && plan[key] >= 0 && plan[key] <= 500)
        || plan.proposed_count !== plan.selected_count + plan.omitted_count) return {...base, state: "inconsistent"};
    const reserve = plan.encoding_reserve;
    return {...base, state: "recorded", proposed: plan.proposed_count, selected: plan.selected_count,
      omitted: plan.omitted_count, reserve: Number.isInteger(reserve) && [0, 1].includes(reserve) ? reserve : null,
      reserveState: reserve === undefined ? "unrecorded" : Number.isInteger(reserve) && [0, 1].includes(reserve) ? "recorded" : "inconsistent"};
  });
}
function renderCandidateCoverage(reviews) {
  const rows = candidatePlanRows(reviews);
  const known = rows.length > 0 && rows.every((row) => row.state === "recorded");
  const counts = (row) => "提出 " + row.proposed + " · 选中 " + row.selected + " · 未选 " + row.omitted + "（含去重）";
  const state = (value) => value === "inconsistent" ? "记录不一致" : "未记录";
  $("candidate-coverage").hidden = false;
  $("candidate-coverage-summary").textContent = "候选提案覆盖：" + (known
    ? counts(rows.reduce((sum, row) => ({proposed: sum.proposed + row.proposed,
        selected: sum.selected + row.selected, omitted: sum.omitted + row.omitted}), {proposed: 0, selected: 0, omitted: 0}))
    : rows.some((row) => row.state === "inconsistent") ? "记录不一致（展开查看）" : "未记录或部分未记录");
  const detail = rows.map((row) => element("p", row.id.slice(0, 120) + (row.id.length > 120 ? "…" : "") + "："
    + (row.state === "recorded" ? counts(row) + "；编码预留 "
      + (row.reserveState === "recorded" ? row.reserve + " 次（未必消费）" : state(row.reserveState)) : state(row.state))));
  detail.push(element("p", "提案不是已确认漏洞；未选提案未逐条处理，不会补成结果。预留只代表预算，不代表实际请求或成功恢复；旧记录缺失时不补算。"));
  $("candidate-coverage-detail").replaceChildren(...detail);
}
async function render() {
  $("network-mode").textContent = "当前资料联网：" + (snapshot?.network_mode === "direct" ? "直连" : "系统默认");
  if (!snapshot) return;
  const budget = snapshot.budget, managed = managedUsageMode(), readOnly = readOnlyMode();
  $("budget-prefix").hidden = readOnly || managed;
  $("budget-hint").hidden = readOnly || managed;
  $("budget").textContent = readOnly ? "演示模式 · 不调用模型" : budget.available
    ? managed ? "已用 " + budget.used.toLocaleString() + " 次" : budget.used.toLocaleString() + " / " + budget.limit.toLocaleString()
    : "暂不可读";
  $("budget-detail").textContent = readOnly ? "只读查看和导出已有结果，不需要 API key，也不会使用请求额度。"
    : managed ? budget.available
      ? "本机累计用量自动保存。每批按你填写的请求上限执行；费用以模型平台为准。"
      : (errorNames[budget.code] || errorNames.managed_usage_unavailable)
    : budget.available ? "剩余 " + budget.remaining + " 次" + (budget.pending ? " · " + budget.pending + " 次进行中" : "") : "暂不能启动提取，不会重置已用额度。";
  if (!selectedRun && snapshot.runs.length) chooseRun(snapshot.runs[0].id);
  renderRunChoices();
  renderHomeIntake();
  controls();
  const run = current();
  if (!run) return;
  const summary = run.summary;
  const failed = run.state === "error" || (summary && !["completed", "stopped_by_user"].includes(summary.status));
  $("state-badge").textContent = failed ? "需查看问题" : labels[run.state] || run.state;
  $("state-badge").className = "pill " + (failed ? "red" : activeStates.has(run.state) ? "amber" : "");
  const complete = summary?.candidate_count ?? summary?.entry_count ?? 0;
  $("run-title").textContent = summary ? "已处理 " + (summary.input_count ?? 0) + " 份资料 · 字段已齐 " + complete + " 条结果" : labels[run.state];
  $("run-subtitle").textContent = run.code ? (errorNames[run.code] || "错误代码：" + run.code) : summary
    ? (summary.draft_count ?? 0) + " 条结果待补充 · " + (summary.unprocessed_input_count ?? 0) + " 份资料未处理"
    : run.progress?.report_id || run.inputs.length + " 份资料 · 尚未生成结果";
  const completed = summary?.input_count ?? run.processed_count ?? 0;
  $("progress").max = Math.max(1, summary?.requested_input_count || run.inputs.length || completed);
  $("progress").value = completed;
  $("output-path").textContent = "本地结果目录：" + run.output_path;
  $("events").replaceChildren(...run.events.slice(-60).reverse().map((event) => element("li", eventText(event))));
  renderChecks(run);
  renderDownloads(run.results_available ? run.id : null);
  if (run.results_available) {
    if (resultRun !== run.id && !loadingResult && !previewError) await loadResult(run);
  } else if (!homeIntake) {
    $("cases").replaceChildren(element("p", run.state === "error" ? "本批未生成结果。展开运行记录查看问题。" : "完成后将显示条目；无需刷新页面。", "empty-small"));
    empty(run.state === "error" ? "本批尚未生成结果" : labels[run.state] || "等待处理",
      run.state === "prepared" ? (run.id === preparedId
        ? "点击“添加资料并提取”，确认已检查的资料和用量后再开始。"
        : "这是之前的输入检查记录。请点击“添加资料并提取”重新提交资料，不会自动复用旧表单。")
        : "可在左侧查看输入检查和运行记录。");
  }
}
async function loadResult(run) {
  const id = run.id, version = selectionVersion;
  if (loadingResult === id || selectedRun !== id) return;
  loadingResult = id;
  previewError = "";
  renderDownloads(run.results_available ? id : null);
  empty("正在加载结果", "只读取已有文件，不会调用模型。");
  try {
    const data = await api("/api/result/" + id);
    if (version !== selectionVersion || selectedRun !== id) return;
    result = data;
    resultRun = id;
    const projects = [...new Set(data.entries.map((item) => item.project).filter(Boolean))];
    const revision = data.reviews[0]?.prompt_revision?.match(/v\d+$/)?.[0];
    if (projects.length) {
      resultNames.set(id, (revision ? revision + " · " : "") + data.reviews.length + " 条结果 · " + projects.join(" / "));
      renderRunChoices();
    }
    renderCases();
    controls();
  } catch (error) {
    if (version !== selectionVersion || selectedRun !== id) return;
    previewError = readableError(error);
    resultRun = null;
    $("cases").replaceChildren(element("p", "预览加载失败，可重新加载或导出原文件。", "empty-small"));
    empty("结果预览未能加载", previewError, true);
  } finally {
    if (version === selectionVersion) loadingResult = null;
  }
}
function entryFor(review) {
  return result.entries.find((item) => review.entry_id && item.entry_id === review.entry_id) || review.draft_fields || {};
}
function caseMarker(review, entry, index) {
  const ordinal = "第 " + (index + 1) + " 条";
  const locations = [[entry.critical_operation, false], [entry.entry_point, false],
    [review.suggested_values?.critical_operation, true], [review.suggested_values?.entry_point, true]];
  for (const [location, suggested] of locations) {
    if (!location || typeof location.file !== "string" || !location.file.trim()) continue;
    const file = location.file.trim(), name = file.split(/[\\/]/).filter(Boolean).at(-1);
    if (!name) continue;
    const line = (typeof location.line === "string" && location.line.trim()) ||
      (Number.isInteger(location.line) && location.line > 0 ? String(location.line) : "");
    const position = (suggested ? "建议位置 · " : "") + name + (line ? ":" + line : "");
    return {text: ordinal + " · " + position, title: ordinal + " · " +
      (suggested ? "建议位置 · " : "") + file + (line ? ":" + line : "")};
  }
  const identity = typeof review.entry_id === "string" && review.entry_id.trim() || "位置待补充";
  return {text: ordinal + " · " + identity, title: ordinal + " · " + identity};
}
function renderCases() {
  const reviews = result?.reviews || [];
  renderCandidateCoverage(reviews);
  const search = $("case-search").value.trim().toLowerCase(), filter = $("case-filter").value;
  const matching = reviews.map((review, index) => ({review, index, entry: entryFor(review)})).filter(({review, entry}) =>
    (filter === "all" || review.status === filter) &&
    [entry.project, entry.vuln_title, review.report_id].join(" ").toLowerCase().includes(search));
  $("case-count").textContent = matching.length + " / " + reviews.length + " 条结果";
  if (!matching.length) {
    $("cases").replaceChildren(element("p", reviews.length ? "没有匹配的条目，请修改搜索或筛选条件。" : "本批没有生成可预览条目，请查看运行记录或导出复核报告。", "empty-small"));
    empty(reviews.length ? "没有匹配的条目" : "本批没有可预览条目", reviews.length ? "清空搜索或切换为“全部条目”。" : "可导出复核报告查看保留的问题。");
    return;
  }
  if (!matching.some((row) => row.index === selectedCase)) selectedCase = matching[0].index;
  $("cases").replaceChildren(...matching.map(({review, index, entry}) => {
    const button = element("button", undefined, "case-button" + (index === selectedCase ? " active" : ""));
    button.type = "button";
    button.dataset.index = String(index);
    button.setAttribute("aria-pressed", String(index === selectedCase));
    const marker = caseMarker(review, entry, index);
    const detail = element("span", marker.text, "case-marker");
    detail.title = marker.title;
    button.append(element("strong", entry.project || "未识别项目"), element("small", review.report_id),
      detail,
      element("span", labels[review.status] || "需查看问题", "pill " + (review.status === "complete" ? "" : "amber")));
    button.addEventListener("click", () => {
      selectedCase = index;
      renderCases();
      $("cases").querySelector('[data-index="' + index + '"]')?.focus({preventScroll: true});
    });
    return button;
  }));
  renderCase(reviews[selectedCase]);
}
function appendFieldValue(field, value) {
  if (value === null || value === undefined) { field.append(element("p", "尚未提取到该字段。", "reason")); return; }
  const raw = typeof value === "string" ? value : JSON.stringify(value, null, 2);
  if (!Array.isArray(value) && typeof value === "object" && typeof value.code === "string") {
    field.append(element("p", (value.file ?? "未提供文件") + " · 行 " + (value.line ?? "未提供"), "source-location"), element("pre", value.code));
    if (typeof value.desc === "string") field.append(element("p", value.desc, "value-description"));
    const original = element("details", undefined, "raw-value");
    original.append(element("summary", "查看原始 JSON"), element("pre", raw));
    field.append(original);
  } else field.append(element("pre", raw));
}
$("back-to-field").addEventListener("click", () => {
  if (returnField) { returnField.open = true; returnField.scrollIntoView({block: "start"}); returnField.querySelector("summary").focus({preventScroll: true}); }
});
function renderCase(review) {
  const entry = entryFor(review);
  returnField = null;
  $("back-to-field").hidden = true;
  $("result-empty").hidden = true;
  $("result-content").hidden = false;
  $("review-scroll").scrollTop = 0;
  $("case-id").textContent = review.report_id;
  $("case-title").textContent = entry.vuln_title || "标题待补充";
  $("case-status").textContent = review.status === "complete"
    ? "字段已齐 · 已收录到数据集导出"
    : "信息待补充 · 详情见复核报告";
  $("case-technical").textContent = JSON.stringify({entry_id: review.entry_id, status: review.status,
    verify: entry.verify ?? 0, prompt_revision: review.prompt_revision}, null, 2);
  const fields = Object.entries(fieldNames).map(([name, label]) => {
    const assessment = review.field_reviews?.[name] || {};
    const field = element("details", undefined, "field");
    field.open = ["entry_point", "critical_operation"].includes(name);
    const heading = element("summary", label);
    heading.append(element("span", labels[assessment.status] || "未评估", "pill " + (assessment.status === "supported" ? "green" : "amber")));
    field.append(heading);
    appendFieldValue(field, entry[name] ?? review.suggested_values?.[name] ?? null);
    field.append(element("p", assessment.reason || "未提供充分依据。", "reason"));
    const refs = element("div", undefined, "evidence-links");
    for (const ref of assessment.evidence_refs || []) {
      const button = element("button", "依据 " + ref);
      button.type = "button";
      const exists = (review.evidence || []).some((item) => item.id === ref);
      button.disabled = !exists;
      button.title = exists ? "跳到对应来源，随后可以返回此字段" : "当前报告未保存该引用的内容";
      button.addEventListener("click", () => {
        const evidence = $("evidence").querySelector('[data-ref="' + CSS.escape(ref) + '"]');
        if (evidence) {
          returnField = field;
          $("back-to-field").hidden = false;
          evidence.open = true;
          evidence.scrollIntoView({block: "start"});
          evidence.querySelector("summary").focus({preventScroll: true});
        }
      });
      refs.append(button);
    }
    field.append(refs);
    return field;
  });
  const issues = [...(review.errors || []), ...(review.annotation_errors || []), ...(review.input_warnings || [])];
  if (issues.length) {
    const note = element("details", undefined, "field");
    note.append(element("summary", "问题记录（" + issues.length + "）"), element("pre", JSON.stringify(issues, null, 2)));
    fields.push(note);
  }
  $("fields").replaceChildren(...fields);
  const tools = {read_file: "源码", read_advisory: "公告", git_show: "源码版本", code_search: "搜索记录", search_code: "搜索记录"};
  $("evidence").replaceChildren(...(review.evidence || []).map((item) => {
    const node = element("details"); node.dataset.ref = item.id;
    const source = item.result || {};
    node.append(element("summary", item.id + " · " + (tools[item.tool] || "来源记录") + " · " + (source.path || item.name || item.tool || "资料")));
    if (source.commit) node.append(element("p", source.commit + " · 行 " + (source.start_line ?? "?") + "–" + (source.end_line ?? "?"), "hint path"));
    node.append(element("pre", source.text || item.text || JSON.stringify(source, null, 2)));
    return node;
  }));
}
function renderDownloads(id) {
  const hasDraftExport = id && current()?.summary?.files?.includes("drafts.jsonl");
  const signature = id ? id + ":" + Boolean(hasDraftExport) : null;
  if (downloadRun === signature) return;
  downloadRun = signature;
  if (!id) { $("downloads").replaceChildren(); return; }
  const names = [
    ["entries.jsonl", "导出数据集", "仅字段已齐的候选，未人工确认"],
    ["review.jsonl", "复核报告", "字段依据、不确定性和问题"],
    ...(hasDraftExport ? [["drafts.jsonl", "导出待补充条目", "空值表示未确定，不属于完整数据集；依据见复核报告"]] : []),
    ["reports.jsonl", "公告记录"], ["report_conflicts.jsonl", "冲突记录"],
    ["actions.jsonl", "处理记录"], ["summary.json", "批次统计"],
  ];
  const buttons = names.map(([name, title, help], index) => {
    const button = element("button", title);
    button.type = "button";
    button.title = name + (help ? " · " + help : "");
    if (index > 1) button.append(element("small", name));
    button.addEventListener("click", async () => {
      if (button.disabled) return;
      button.disabled = true;
      button.setAttribute("aria-busy", "true");
      try {
        const response = await fetch("/api/download/" + id + "/" + name, {headers: {"X-T2-Session": token}, signal: AbortSignal.timeout(60000)});
        if (!response.ok) throw new Error("该文件暂时无法下载，可查看左侧运行记录中的本地结果目录。");
        const url = URL.createObjectURL(await response.blob()), link = element("a");
        link.href = url; link.download = name;
        document.body.append(link); link.click(); link.remove();
        setTimeout(() => URL.revokeObjectURL(url), 1000);
        message("已交给浏览器下载：" + name + "。导出原文件，未修改结果。");
      } catch (error) { message(readableError(error)); }
      finally { button.disabled = false; button.removeAttribute("aria-busy"); }
    });
    return button;
  });
  const more = element("details", undefined, "export-more"), menu = element("div", undefined, "export-menu");
  more.append(element("summary", "更多文件"));
  menu.append(...buttons.slice(2)); more.append(menu);
  $("downloads").replaceChildren(...buttons.slice(0,2), more);
}
async function refresh() {
  const request = ++stateRequest;
  try {
    const next = await api("/api/state");
    if (request !== stateRequest) return;
    snapshot = next;
    connected = true;
    $("connection").textContent = "本地已连接";
    $("connection").className = "connection";
    $("connection").title = "仅连接本机服务";
    await render();
  } catch (error) {
    if (request !== stateRequest) return;
    connected = false;
    $("connection").textContent = "连接已断开";
    $("connection").className = "connection offline";
    $("connection").title = "请检查本地服务。任务不会自动重跑；恢复连接后会继续显示状态。";
    controls();
    throw error;
  }
}
async function poll() {
  try { await refresh(); } catch { /* The connection indicator owns this status. */ }
  finally { setTimeout(poll, document.hidden ? 10000 : 2000); }
}
poll();
