"use strict";

// Offline browser-logic regressions. Run with: node --test tests/web_ui_interactions.cjs
// This deliberately has no browser, third-party DOM, timers, or network dependency.
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");
const vm = require("node:vm");

const assets = path.join(__dirname, "..", "vulngym_t2", "web_assets");

class FakeElement {
  constructor(tagName, ownerDocument) {
    this.tagName = tagName.toUpperCase();
    this.ownerDocument = ownerDocument;
    this.children = [];
    this.parentElement = null;
    this.attributes = new Map();
    this.dataset = {};
    this.style = {};
    this.listeners = new Map();
    this.className = "";
    this.value = "";
    this.checked = false;
    this.hidden = false;
    this.disabled = false;
    this.files = [];
    this.open = false;
    this.scrollTop = 0;
    this.appendCount = 0;
    this.replaceCount = 0;
    this._text = "";
    this.classList = {
      contains: (name) => this.className.split(/\s+/).includes(name),
      add: (...names) => { this.className = [...new Set([...this.className.split(/\s+/).filter(Boolean), ...names])].join(" "); },
      remove: (...names) => { this.className = this.className.split(/\s+/).filter((name) => !names.includes(name)).join(" "); },
      toggle: (name, force) => {
        const add = force ?? !this.classList.contains(name);
        this.classList[add ? "add" : "remove"](name);
        return add;
      },
    };
  }

  get textContent() { return this._text + this.children.map((child) => child.textContent).join(""); }
  set textContent(value) {
    this._text = String(value ?? "");
    for (const child of this.children) child.parentElement = null;
    this.children = [];
  }
  get childElementCount() { return this.children.length; }
  get firstElementChild() { return this.children[0] || null; }
  get options() { return this.children; }
  get valueAsNumber() { return Number(this.value); }
  get disabled() { return Boolean(this._disabled); }
  set disabled(value) { this._disabled = Boolean(value); }
  get hidden() { return Boolean(this._hidden); }
  set hidden(value) { this._hidden = Boolean(value); }
  get checked() { return Boolean(this._checked); }
  set checked(value) { this._checked = Boolean(value); }
  get open() { return Boolean(this._open); }
  set open(value) { this._open = Boolean(value); }

  setAttribute(name, value) {
    value = String(value);
    this.attributes.set(name, value);
    if (name === "class") this.className = value;
    else if (name.startsWith("data-")) this.dataset[name.slice(5).replace(/-([a-z])/g, (_, char) => char.toUpperCase())] = value;
    else if (["hidden", "disabled", "checked", "required", "open"].includes(name)) this[name] = true;
    else this[name] = value;
  }
  getAttribute(name) {
    if (name.startsWith("data-")) return this.dataset[name.slice(5).replace(/-([a-z])/g, (_, char) => char.toUpperCase())] ?? null;
    return this.attributes.get(name) ?? null;
  }
  removeAttribute(name) {
    this.attributes.delete(name);
    if (["hidden", "disabled", "checked", "required", "open"].includes(name)) this[name] = false;
  }
  append(...nodes) {
    for (let node of nodes) {
      if (typeof node === "string") {
        const text = new FakeElement("span", this.ownerDocument);
        text.textContent = node;
        node = text;
      }
      if (node.parentElement) node.remove();
      node.parentElement = this;
      this.children.push(node);
      this.appendCount += 1;
    }
  }
  appendChild(node) { this.append(node); return node; }
  replaceChildren(...nodes) {
    this.replaceCount += 1;
    this.textContent = "";
    this.append(...nodes);
  }
  remove() {
    if (!this.parentElement) return;
    const siblings = this.parentElement.children;
    siblings.splice(siblings.indexOf(this), 1);
    this.parentElement = null;
  }
  matches(selector) {
    if (selector.startsWith("#")) return this.id === selector.slice(1);
    if (selector.startsWith(".")) return selector.slice(1).split(".").every((name) => this.classList.contains(name));
    const attribute = selector.match(/^([\w-]+)?\[([\w-]+)(?:=["']?([^"'\]]+)["']?)?\]$/);
    if (attribute) {
      const [, tag, name, value] = attribute;
      return (!tag || this.tagName === tag.toUpperCase()) && this.getAttribute(name) !== null
        && (value === undefined || this.getAttribute(name) === value);
    }
    return this.tagName === selector.toUpperCase();
  }
  querySelectorAll(selector) {
    const alternatives = selector.split(",").map((part) => part.trim());
    const found = [];
    const visit = (node) => {
      for (const child of node.children) {
        if (alternatives.some((part) => child.matches(part))) found.push(child);
        visit(child);
      }
    };
    visit(this);
    return found;
  }
  querySelector(selector) { return this.querySelectorAll(selector)[0] || null; }
  closest(selector) {
    for (let node = this; node; node = node.parentElement) if (node.matches(selector)) return node;
    return null;
  }
  focus() { this.ownerDocument.activeElement = this; }
  scrollIntoView() {}
  checkValidity() { return true; }
  reportValidity() { return true; }
  showModal() { this.open = true; }
  close() { this.open = false; return this.emit("close"); }
  addEventListener(name, listener) {
    const listeners = this.listeners.get(name) || [];
    listeners.push(listener);
    this.listeners.set(name, listeners);
  }
  async emit(name, values = {}) {
    const event = {
      type: name, target: this, currentTarget: this, defaultPrevented: false,
      bubbles: ["input", "change", "click", "submit"].includes(name),
      preventDefault() { this.defaultPrevented = true; }, ...values,
    };
    for (let node = this; node; node = event.bubbles ? node.parentElement : null) {
      event.currentTarget = node;
      for (const listener of node.listeners.get(name) || []) await listener(event);
    }
  }
  click() { return this.emit("click"); }
}

function fakeDocument(html) {
  const document = {hidden: false, activeElement: null};
  const root = new FakeElement("document", document);
  const stack = [root];
  const voidTags = new Set(["area", "base", "br", "col", "embed", "hr", "img", "input", "link", "meta", "param", "source", "track", "wbr"]);
  for (const token of html.matchAll(/<!--[\s\S]*?-->|<![^>]*>|<\/?[\w-]+\b[^>]*>|[^<]+/g)) {
    const raw = token[0];
    if (raw.startsWith("<!")) continue;
    if (raw.startsWith("</")) {
      const tag = raw.slice(2).match(/^[\w-]+/)[0].toUpperCase();
      while (stack.length > 1) if (stack.pop().tagName === tag) break;
      continue;
    }
    if (!raw.startsWith("<")) { stack.at(-1)._text += raw; continue; }
    const [, tag, attributes] = raw.match(/^<([\w-]+)([\s\S]*?)\/?\s*>$/);
    const node = new FakeElement(tag, document);
    for (const attribute of attributes.matchAll(/([^\s=]+)(?:\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+)))?/g)) {
      node.setAttribute(attribute[1], attribute[2] ?? attribute[3] ?? attribute[4] ?? "");
    }
    stack.at(-1).append(node);
    if (!voidTags.has(tag.toLowerCase()) && !raw.endsWith("/>")) stack.push(node);
  }
  document.documentElement = root.querySelector("html");
  document.body = root.querySelector("body");
  document.getElementById = (id) => root.querySelector(`#${id}`);
  document.querySelector = (selector) => root.querySelector(selector);
  document.querySelectorAll = (selector) => root.querySelectorAll(selector);
  document.createElement = (tag) => new FakeElement(tag, document);
  document.addEventListener = () => {};
  for (const select of root.querySelectorAll("select")) select.value = select.options[0]?.value || "";
  return document;
}

function fixtureRun(id = "prepared-run", state = "prepared") {
  return {
    id, state, created: "2026-09-13T12:00:00+00:00", inputs: [], events: [], progress: {},
    processed_count: 0, summary: null, code: null, output_path: "D:\\synthetic\\output",
    results_available: ["finished", "imported"].includes(state),
  };
}

function fixtureSnapshot(runs = [fixtureRun()]) {
  return {
    runs, budget: {available: true, used: 2, limit: 100, remaining: 98, pending: 0},
    model: "deepseek-flash", max_run_requests: 500, automatic_retries: 0,
  };
}

function managedSnapshot(runs = [], used = 0) {
  return {...fixtureSnapshot(runs),
    budget: {managed: true, available: true, used, limit: 3000, remaining: 3000 - used, pending: 0}};
}

function response(value, ok = true) { return {ok, status: ok ? 200 : 400, json: async () => value}; }
function deferred() {
  let resolve;
  let reject;
  const promise = new Promise((yes, no) => { resolve = yes; reject = no; });
  return {promise, resolve, reject};
}

function createPage() {
  const document = fakeDocument(fs.readFileSync(path.join(assets, "index.html"), "utf8"));
  const calls = [];
  const timers = new Map();
  let nextTimer = 0;
  let request = async (url) => { throw new Error(`Unexpected offline request: ${url}`); };
  const context = vm.createContext({
    document, console, TextEncoder, TextDecoder, AbortController, Blob,
    AbortSignal: {timeout: () => new AbortController().signal},
    window: {matchMedia: () => ({matches: false, addEventListener() {}}), addEventListener() {}},
    navigator: {}, CSS: {escape: (value) => String(value)},
    URL: {createObjectURL: () => "blob:synthetic", revokeObjectURL() {}},
    fetch: async (url, options) => { calls.push({url, options}); return request(url, options); },
    setTimeout: (callback, delay) => { const id = ++nextTimer; timers.set(id, {callback, delay}); return id; },
    clearTimeout: (id) => timers.delete(id),
    requestAnimationFrame: (callback) => callback(),
  });
  const source = fs.readFileSync(path.join(assets, "app.js"), "utf8");
  assert.match(source, /\bpoll\(\);\s*$/, "the harness must remove only the final automatic poll");
  vm.runInContext(source.replace(/\bpoll\(\);\s*$/, ""), context, {filename: "app.js"});
  return {
    context, document, calls, timers,
    get: (id) => {
      const node = document.getElementById(id);
      assert.ok(node, `missing page element: ${id}`);
      return node;
    },
    evaluate: (script) => vm.runInContext(script, context),
    setRequest: (handler) => { request = handler; },
    async flush() {
      // App event listeners may start an action without returning its promise.
      for (let step = 0; step < 12; step += 1) await new Promise(setImmediate);
    },
  };
}

function preparePage(page, runs = [fixtureRun()]) {
  page.context.fixtureState = fixtureSnapshot(runs);
  page.get("mode").value = "material";
  page.get("material").value = "Synthetic public advisory, no model request.";
  page.get("repo").value = "D:\\synthetic\\repo";
  page.get("key").value = "synthetic-key-for-offline-tests";
  page.get("cap").value = "12";
  page.get("confirmed").checked = true;
  page.evaluate(`snapshot = fixtureState; connected = true; selectedRun = snapshot.runs[0].id;
    preparedId = snapshot.runs[0].id; preparedFingerprint = formFingerprint(); controls();`);
}

const syntheticUrls = [
  "https://github.com/advisories/GHSA-2345-cfgh-jmpq",
  "https://github.com/advisories/GHSA-6789-rvwx-2345",
  "https://github.com/advisories/GHSA-cfgh-jmpq-6789",
];

test("startup network mode is a read-only state label and does not change consent or start work", async () => {
  const page = createPage();
  preparePage(page);
  const key = page.get("key").value;
  const cap = page.get("cap").value;
  for (const [mode, label] of [["system", "系统默认"], ["direct", "直连"]]) {
    page.context.fixtureState = {...fixtureSnapshot(), network_mode: mode};
    await page.evaluate("snapshot = fixtureState; render()");
    assert.equal(page.get("network-mode").textContent, "当前资料联网：" + label);
    assert.equal(page.get("network-mode").tagName, "SPAN");
    assert.equal(page.get("network-mode").getAttribute("tabindex"), null);
    assert.equal(page.get("network-mode").getAttribute("role"), null);
    assert.equal(page.get("network-mode").listeners.size, 0);
    assert.equal(page.get("key").value, key);
    assert.equal(page.get("cap").value, cap);
    assert.equal(page.get("confirmed").checked, true);
    assert.equal(page.get("start").disabled, false);
    assert.equal(page.get("budget").textContent, "2 / 100");
  }
  assert.match(page.get("network-mode-hint").textContent, /启动时确定.*公告和源码下载.*不改变模型请求的联网方式/);
  assert.match(page.get("network-mode-hint").textContent, /关闭本工作台自己的服务窗口.*另一启动入口.*仅关闭网页不会停止服务/);
  assert.ok(page.get("urls").getAttribute("aria-describedby").split(/\s+/).includes("network-mode-hint"));
  assert.equal(page.calls.length, 0, "rendering a network mode cannot start acquisition, model calls, or retries");
});

test("missing legacy or invalid network modes never claim direct mode", async () => {
  const page = createPage();
  assert.equal(page.get("network-mode").textContent, "当前资料联网：系统默认");
  for (const mode of [undefined, null, "", "DIRECT", " direct ", "auto", true, 1, ["direct"], {mode: "direct"}]) {
    page.context.fixtureState = {...fixtureSnapshot([]), network_mode: "direct"};
    await page.evaluate("snapshot = fixtureState; render()");
    assert.equal(page.get("network-mode").textContent, "当前资料联网：直连");
    page.context.fixtureState = fixtureSnapshot([]);
    if (mode !== undefined) page.context.fixtureState.network_mode = mode;
    await page.evaluate("snapshot = fixtureState; render()");
    assert.equal(page.get("network-mode").textContent, "当前资料联网：系统默认",
      "only the exact direct state property may display direct mode");
  }
  for (const missingState of [null, undefined]) {
    page.context.fixtureState = {...fixtureSnapshot([]), network_mode: "direct"};
    await page.evaluate("snapshot = fixtureState; render()");
    page.context.fixtureState = missingState;
    await page.evaluate("snapshot = fixtureState; render()");
    assert.equal(page.get("network-mode").textContent, "当前资料联网：系统默认");
  }
  assert.equal(page.calls.length, 0);
});

test("URL intake is the default, focuses one multiline field, and discloses public network acquisition", async () => {
  const page = createPage();
  page.context.fixtureState = fixtureSnapshot([]);
  page.evaluate("snapshot = fixtureState; connected = true; controls()");
  assert.equal(page.get("mode").value, "urls");
  assert.equal(page.get("urls").tagName, "TEXTAREA");
  assert.equal(page.get("urls-controls").hidden, false);
  for (const id of ["material-controls", "batch-controls", "local-controls"])
    assert.equal(page.get(id).hidden, true, `${id} must not demand local paths for URL intake`);
  assert.match(page.get("urls-network").textContent, /联网.*GitHub.*不运行目标程序/);
  assert.match(page.get("mode").textContent, /粘贴公告链接（GHSA \/ OSV）/);
  assert.match(page.get("urls").getAttribute("placeholder"), /https:\/\/osv\.dev\/vulnerability\//);
  assert.match(page.get("urls-network").textContent, /OSV.*源码仍从 GitHub 获取/);
  assert.match(page.get("urls-network").textContent, /不会自动切换来源或重试/);
  assert.match(page.get("urls-network").textContent, /不调用模型.*确认额度.*整批提取/);
  assert.match(page.get("urls-network").textContent, /依次处理/);
  assert.equal(page.get("prepare").textContent, "获取资料并检查");
  await page.get("new-run").emit("click");
  assert.equal(page.document.activeElement, page.get("urls"));
  assert.equal(page.calls.length, 0, "opening URL intake cannot acquire or call a model automatically");
});

test("one paste submits all Markdown and whitespace links once, without stale local paths or key", async () => {
  const page = createPage();
  let state = managedSnapshot();
  const pasted = `[first](${syntheticUrls[0]})\n${syntheticUrls[1]} ${syntheticUrls[2]}\n${syntheticUrls[0]}`;
  page.setRequest(async (url, options) => {
    if (url === "/api/state") return response(state);
    assert.equal(url, "/api/prepare", "only free preparation is authorized");
    assert.deepEqual(JSON.parse(options.body), {mode: "urls", urls: pasted});
    const run = fixtureRun();
    run.inputs = syntheticUrls.map((url, index) => ({report_id: `synthetic-${index}`, input_error: null}));
    state = managedSnapshot([run]);
    return response({run_id: run.id});
  });
  await page.evaluate("refresh()");
  for (const id of ["repo", "cache", "mapping", "source", "input-path"])
    page.get(id).value = "Stale local-form draft must not override acquired mappings";
  page.get("key").value = "synthetic-key-never-sent-during-prepare";
  page.get("urls").value = pasted;
  await page.get("urls").emit("input");
  assert.equal(page.get("cap").value, "36", "three unique URLs suggest three per-input budgets, not four");
  assert.match(page.get("urls-hint").textContent, /3 个不同链接.*36 次/);
  await page.get("prepare-form").emit("submit");
  assert.equal(page.evaluate("preparedId"), "prepared-run");
  assert.equal(page.get("start").disabled, true, "free preparation is not model consent");
  page.get("confirmed").checked = true;
  await page.get("confirmed").emit("change");
  assert.equal(page.get("start").disabled, false);
  assert.equal(page.calls.filter((call) => call.options.method === "POST").length, 1);
  assert.ok(page.calls.every((call) => call.url !== "/api/start"));
});

test("URL count suggestions never overwrite a manually edited request cap", async () => {
  const page = createPage();
  page.get("urls").value = syntheticUrls.slice(0, 2).join(" ");
  await page.get("urls").emit("input");
  assert.equal(page.get("cap").value, "24");
  page.get("cap").value = "7";
  await page.get("cap").emit("input");
  page.get("urls").value = syntheticUrls.join("\n");
  await page.get("urls").emit("input");
  assert.equal(page.get("cap").value, "7");
  assert.match(page.get("urls-hint").textContent, /建议本批上限 36/);
  for (const mode of ["material", "batch", "urls"]) {
    page.get("mode").value = mode;
    await page.get("mode").emit("change");
    assert.equal(page.get("cap").value, "7");
  }
  assert.equal(page.calls.length, 0);
});

test("mixed GHSA and OSV paste preserves payload and sources while canonicalizing OSV page/API counts", async () => {
  const page = createPage();
  let state = managedSnapshot();
  const pasted = `[github](${syntheticUrls[0]})\n${syntheticUrls[0].toUpperCase()} `
    + "https://osv.dev/vulnerability/GHSA-2345-cfgh-jmpq\n"
    + "[osv](https://api.osv.dev/v1/vulns/ghsa-2345-CFGH-JMPQ/) "
    + "https://osv.dev/vulnerability/PYSEC-2021-1\nhttps://api.osv.dev/v1/vulns/PYSEC-2021-1";
  page.setRequest(async (url, options) => {
    if (url === "/api/state") return response(state);
    assert.equal(url, "/api/prepare", "mixed intake may only prepare until explicit model consent");
    assert.deepEqual(JSON.parse(options.body), {mode: "urls", urls: pasted});
    const run = fixtureRun();
    run.inputs = ["github", "osv-ghsa", "osv-pysec"].map((id) => ({report_id: id, input_error: null}));
    state = managedSnapshot([run]);
    return response({run_id: run.id});
  });
  await page.evaluate("refresh()");
  page.get("urls").value = pasted;
  page.get("key").value = "synthetic-not-sent-to-prepare";
  await page.get("urls").emit("input");
  assert.equal(page.get("cap").value, "36");
  assert.match(page.get("urls-hint").textContent, /3 个不同链接.*36 次/);
  await page.get("prepare-form").emit("submit");
  assert.equal(page.get("start").disabled, true);
  assert.equal(page.calls.filter((call) => call.options.method === "POST").length, 1);
  assert.ok(page.calls.every((call) => call.url !== "/api/start"));
});

test("OSV count keeps case-sensitive IDs, canonicalizes CVE, and does not overwrite edited cap", async () => {
  const page = createPage();
  page.get("urls").value = [
    "https://osv.dev/vulnerability/CVE-2021-1234", "https://api.osv.dev/v1/vulns/cve-2021-1234/",
    "https://osv.dev/vulnerability/PYSEC-2021-1", "https://osv.dev/vulnerability/pysec-2021-1",
  ].join(" ");
  await page.get("urls").emit("input");
  assert.equal(page.get("cap").value, "36");
  page.get("cap").value = "9";
  await page.get("cap").emit("input");
  page.get("urls").value += " https://osv.dev/vulnerability/GHSA-6789-rvwx-2345";
  await page.get("urls").emit("input");
  assert.equal(page.get("cap").value, "9");
  assert.match(page.get("urls-hint").textContent, /4 个不同链接.*48 次/);
  assert.equal(page.calls.length, 0);
});

test("OSV count ignores unsupported hosts, queries and ambiguous unsafe paths before server validation", async () => {
  const page = createPage();
  page.get("urls").value = [
    "https://osv.dev.evil.example/vulnerability/PYSEC-2021-1",
    "https://osv.dev/vulnerability/PYSEC-2021-1?other=1",
    "https://osv.dev/vulnerability/PYSEC-2021-1#other",
    "https://osv.dev/vulnerability/../secret", "https://osv.dev/vulnerability/CON",
    "https://api.osv.dev:443/v1/vulns/PYSEC-2021-1",
  ].join(" ");
  await page.get("urls").emit("input");
  assert.equal(page.get("cap").value, "12");
  assert.doesNotMatch(page.get("urls-hint").textContent, /识别到/);
  assert.equal(page.calls.length, 0);
});

test("mixed-provider count warns at twenty without treating OSV aliases as extra inputs", async () => {
  const page = createPage();
  const urls = Array.from({length: 20}, (_, index) => `https://osv.dev/vulnerability/PYSEC-2021-${index + 1}`);
  page.get("urls").value = [...urls, "https://api.osv.dev/v1/vulns/PYSEC-2021-1", syntheticUrls[0]].join("\n");
  await page.get("urls").emit("input");
  assert.match(page.get("urls-hint").textContent, /21 个不同链接.*每批最多 20 条/);
  assert.equal(page.get("cap").value, "240", "the suggestion must not expand beyond the batch input ceiling");
  assert.equal(page.calls.length, 0);
});

test("URL and legacy mode transitions preserve drafts but invalidate prepared consent", async () => {
  const page = createPage();
  preparePage(page);
  page.get("urls").value = syntheticUrls.join("\n");
  page.get("input-path").value = "D:\\synthetic\\batch.jsonl";
  const drafts = new Map(["urls", "material", "input-path", "repo"].map((id) => [id, page.get(id).value]));
  for (const mode of ["urls", "batch", "material"]) {
    page.get("mode").value = mode;
    await page.get("mode").emit("change");
    for (const name of ["urls", "batch", "material"])
      assert.equal(page.get(`${name}-controls`).hidden, name !== mode);
    assert.equal(page.get("local-controls").hidden, mode === "urls");
    assert.equal(page.evaluate("preparedId"), null);
    assert.equal(page.get("confirmed").checked, false);
    assert.equal(page.get("start").disabled, true);
    for (const [id, value] of drafts) assert.equal(page.get(id).value, value);
  }
  assert.equal(page.calls.length, 0);
});

test("editing URL text after preparation invalidates the batch binding and Start", async () => {
  const page = createPage();
  preparePage(page);
  page.get("mode").value = "urls";
  page.get("urls").value = syntheticUrls[0];
  page.evaluate("preparedFingerprint = formFingerprint(); controls()");
  assert.equal(page.get("start").disabled, false);
  page.get("urls").value += "\n" + syntheticUrls[1];
  await page.get("urls").emit("input");
  assert.equal(page.evaluate("preparedId"), null);
  assert.equal(page.get("confirmed").checked, false);
  assert.equal(page.get("start").disabled, true);
  assert.equal(page.calls.length, 0);
});

test("partial URL acquisition preserves failure reasons, while all failed input cannot Start", () => {
  const page = createPage();
  const run = fixtureRun();
  run.inputs = [{report_id: "SYNTHETIC-READY", input_error: null},
    {report_id: "SYNTHETIC-MISSING", input_error: "public_repository_not_found"}];
  preparePage(page, [run]);
  page.get("mode").value = "urls";
  page.get("urls").value = syntheticUrls.slice(0, 2).join(" ");
  page.evaluate("preparedFingerprint = formFingerprint(); controls()");
  assert.match(page.get("prepared-summary").textContent, /1 份可提取，1 份资料获取失败.*失败项保留原因，不调用模型/);
  assert.match(page.get("prepared-summary").textContent, /SYNTHETIC-MISSING.*public_repository_not_found/);
  assert.equal(page.get("start").disabled, false, "backend-prepared valid items may share a batch with recorded failures");
  page.evaluate(`snapshot.runs[0].state = "error"; snapshot.runs[0].code = "no_ready_url_inputs";
    snapshot.runs[0].inputs[0].input_error = "public_repository_not_found"; controls()`);
  assert.equal(page.get("start").disabled, true);
  assert.match(page.get("prepared-summary").textContent, /0 份可提取，2 份资料获取失败/);
  assert.equal(page.calls.length, 0);
});

test("empty URL text never submits an acquisition or model request", async () => {
  const page = createPage();
  page.setRequest(async (url) => {
    assert.equal(url, "/api/state");
    return response(fixtureSnapshot([]));
  });
  await page.evaluate("refresh()");
  await page.get("prepare-form").emit("submit");
  assert.match(page.get("dialog-notice").textContent, /至少一个 GHSA 或 OSV 公告链接/);
  assert.ok(page.calls.every((call) => call.options.method === "GET"));
});

test("URL acquisition progress is readable and rate limiting remains a recorded failure, not a model retry", () => {
  const page = createPage();
  const run = fixtureRun("prepared-run", "preparing");
  run.events = [{event: "acquisition_repository", report_id: "SYNTHETIC", index: 2, total: 3}];
  preparePage(page, [run]);
  page.get("mode").value = "urls";
  page.evaluate("preparedFingerprint = formFingerprint(); controls()");
  assert.match(page.get("prepared-summary").textContent, /尚未调用模型/);
  assert.match(page.get("prepared-summary").textContent, /第 2\/3 份.*正在获取源码仓库/);
  assert.equal(page.get("start").disabled, true);
  const message = page.evaluate(`eventText({event: "acquisition_failed", report_id: "SYNTHETIC", index: 2,
    total: 3, code: "github_rate_limited"})`);
  assert.match(message, /第 2\/3 份.*资料获取失败.*GitHub.*不会自动重试/);
  assert.equal(page.calls.length, 0);
});

test("compound URL acquisition failures show readable individual causes in both summaries and checks", () => {
  const page = createPage();
  const run = fixtureRun("prepared-run", "error");
  run.inputs = [
    {report_id: "SYNTHETIC-RATE", input_error: "advisory_material_missing;repository_path_missing;github_rate_limited"},
    {report_id: "SYNTHETIC-TIMEOUT", input_error: "repository_path_missing;repository_download_timeout"},
  ];
  preparePage(page, [run]);
  page.get("mode").value = "urls";
  page.evaluate("preparedFingerprint = formFingerprint(); controls(); renderChecks(snapshot.runs[0])");
  for (const id of ["prepared-summary", "input-checks"]) {
    const text = page.get(id).textContent;
    assert.match(text, /尚未取得公告正文.*尚未取得可读取的源码仓库.*GitHub 暂时限制了请求/);
    assert.match(text, /SYNTHETIC-TIMEOUT.*尚未取得可读取的源码仓库.*源码仓库下载超时/);
    assert.doesNotMatch(text, /advisory_material_missing|repository_path_missing|github_rate_limited|repository_download_timeout/);
  }
  assert.match(page.evaluate('inputErrorText("advisory_access_denied;advisory_not_found")'), /拒绝访问.*404/);
  assert.doesNotMatch(page.evaluate('inputErrorText("C:\\\\private\\\\file;sk-not-a-safe-code")'), /private|sk-not/);
  page.evaluate("preparedId = preparedFingerprint = null; controls()");
  assert.match(page.get("start-reason").textContent, /第 1 步“获取资料并检查”/);
  page.get("mode").value = "material";
  page.evaluate("controls()");
  assert.match(page.get("start-reason").textContent, /第 1 步“检查输入”/);
  assert.equal(page.calls.length, 0);
});

test("OSV preparation failures explain access and schema boundaries without starting or switching sources", () => {
  const page = createPage();
  const cases = [
    ["osv_rate_limited", /OSV.*429.*不会自动重试或切换来源/],
    ["osv_access_denied", /OSV.*403.*不会轮换网络或自动重试/],
    ["osv_not_found", /OSV.*404/],
    ["osv_response_invalid", /格式或编号不匹配/],
    ["osv_ghsa_missing", /未提供对应的 GHSA.*暂不能/],
    ["osv_ghsa_ambiguous", /多个 GHSA.*明确目标/],
    ["osv_reviewed_origin_unconfirmed", /未明确确认.*reviewed.*暂不能开始/],
    ["osv_record_withdrawn", /公告已撤回/],
  ];
  for (const [code, expected] of cases) {
    page.context.testCode = code;
    assert.match(page.evaluate("inputErrorText(testCode)"), expected);
    assert.match(page.evaluate('eventText({event: "acquisition_failed", index: 1, total: 1, code: testCode})'), expected);
  }
  const run = fixtureRun("osv-failed", "error");
  run.inputs = [{report_id: "SYNTHETIC-OSV", input_error: "osv_ghsa_missing;repository_path_missing"}];
  preparePage(page, [run]);
  page.get("mode").value = "urls";
  page.evaluate("preparedFingerprint = formFingerprint(); controls(); renderChecks(snapshot.runs[0])");
  assert.match(page.get("prepared-summary").textContent, /0 份可提取，1 份资料获取失败/);
  assert.match(page.get("input-checks").textContent, /未提供对应的 GHSA/);
  assert.equal(page.get("start").disabled, true);
  assert.equal(page.calls.length, 0);
});

test("a confirmed empty workspace exposes direct input without opening a dialog or submitting", async () => {
  const page = createPage();
  assert.equal(page.get("intake-home").hidden, true, "the initial connection state does not prove there are zero runs");
  assert.equal(page.get("new-dialog").open, false);
  assert.equal(page.calls.length, 0);
  page.setRequest(async (url) => {
    assert.equal(url, "/api/state", "displaying empty-workspace inputs must only read local state");
    return response(fixtureSnapshot([]));
  });
  await page.evaluate("poll()");
  assert.equal(page.get("intake-home").hidden, false);
  assert.equal(page.get("intake-content").parentElement, page.get("home-intake-slot"));
  assert.equal(page.get("prepare-form").closest("#intake-home"), page.get("intake-home"));
  assert.equal(page.get("run-form").closest("#intake-home"), page.get("intake-home"));
  assert.equal(page.get("start").closest("#intake-home"), page.get("intake-home"));
  assert.equal(page.get("review-toolbar").hidden, true);
  assert.equal(page.get("result-empty").hidden, true);
  assert.equal(page.get("result-content").hidden, true);
  assert.equal(page.get("new-dialog").open, false, "the first state response must not open a modal");
  assert.equal(page.get("prepare").disabled, false);
  assert.equal(page.get("start").disabled, true, "direct input still requires preparation and explicit consent");
  assert.deepEqual(page.calls.map((call) => [call.url, call.options.method]), [["/api/state", "GET"]]);
  const ids = page.document.querySelectorAll("[id]").map((node) => node.id);
  assert.equal(new Set(ids).size, ids.length, "inline input must reuse the forms, not introduce duplicate IDs");
});

test("draft fields and selected files survive inline to modal to inline, but closing clears credentials", async () => {
  const page = createPage();
  page.setRequest(async (url) => {
    assert.equal(url, "/api/state");
    return response(fixtureSnapshot([]));
  });
  await page.evaluate("refresh()");
  const drafts = {
    material: "Synthetic public advisory draft.", repo: "D:\\synthetic\\repo",
    source: "https://example.invalid/advisory", cache: "D:\\synthetic\\cache",
    mapping: "D:\\synthetic\\mapping.json", "input-path": "D:\\synthetic\\batch.jsonl", cap: "11",
  };
  const nodes = new Map(["intake-content", "prepare-form", "run-form", "files", "mode", ...Object.keys(drafts)]
    .map((id) => [id, page.get(id)]));
  for (const [id, value] of Object.entries(drafts)) page.get(id).value = value;
  const files = [{name: "synthetic.md", size: 24, lastModified: 1, type: "text/markdown"}];
  page.get("files").files = files;
  await page.get("files").emit("change");
  page.get("mode").value = "batch";
  await page.get("mode").emit("change");
  const fingerprint = page.evaluate("formFingerprint()");
  page.get("key").value = "synthetic-key-for-offline-tests";
  page.get("confirmed").checked = true;
  await page.get("new-run").emit("click");
  assert.equal(page.get("new-dialog").open, true);
  assert.equal(page.get("intake-home").hidden, true);
  assert.equal(page.get("intake-content").parentElement, page.get("dialog-intake-slot"));
  assert.equal(page.document.activeElement, page.get("input-path"), "batch input should receive focus when explicitly opened");
  assert.equal(page.evaluate("formFingerprint()"), fingerprint);
  await page.evaluate("refresh()");
  assert.equal(page.get("intake-content").parentElement, page.get("dialog-intake-slot"), "polling must not pull a live form out of its open dialog");
  await page.get("close-dialog").emit("click");
  assert.equal(page.get("new-dialog").open, false);
  assert.equal(page.get("intake-home").hidden, false);
  assert.equal(page.get("intake-content").parentElement, page.get("home-intake-slot"));
  for (const [id, node] of nodes) assert.equal(page.get(id), node, `${id} must keep its original DOM identity`);
  for (const [id, value] of Object.entries(drafts)) assert.equal(page.get(id).value, value, `${id} draft must survive closing`);
  assert.equal(page.get("files").files, files);
  assert.match(page.get("file-list").textContent, /synthetic\.md/);
  assert.equal(page.get("mode").value, "batch");
  assert.equal(page.get("material-controls").hidden, true);
  assert.equal(page.get("batch-controls").hidden, false);
  assert.equal(page.evaluate("formFingerprint()"), fingerprint);
  assert.equal(page.get("key").value, "");
  assert.equal(page.get("confirmed").checked, false);
  assert.equal(page.document.activeElement, page.get("new-run"));
  page.get("confirmed").checked = true;
  await page.get("material").emit("input");
  assert.equal(page.get("confirmed").checked, false, "the moved form must retain its input invalidation handler");
  assert.ok(page.calls.every((call) => call.url === "/api/state" && call.options.method === "GET"));
});

test("unchanged empty-state polling never reparents the intake form or steals typing focus", async () => {
  const page = createPage();
  page.setRequest(async (url) => {
    assert.equal(url, "/api/state");
    return response(fixtureSnapshot([]));
  });
  await page.evaluate("poll()");
  const content = page.get("intake-content"), slot = page.get("home-intake-slot");
  const appendCount = slot.appendCount;
  const dialogAppendCount = page.get("dialog-intake-slot").appendCount;
  page.get("material").value = "An unfinished synthetic draft";
  page.get("material").focus();
  for (let iteration = 0; iteration < 3; iteration += 1) {
    const [timerId, timer] = [...page.timers.entries()][0];
    page.timers.delete(timerId);
    await timer.callback();
    assert.equal(slot.appendCount, appendCount, "unchanged polls must not append the same form again");
    assert.equal(page.get("dialog-intake-slot").appendCount, dialogAppendCount);
    assert.equal(page.get("intake-content"), content);
    assert.equal(content.parentElement, slot);
    assert.equal(page.document.activeElement, page.get("material"));
    assert.equal(page.get("material").value, "An unfinished synthetic draft");
    assert.equal(page.get("new-dialog").open, false);
  }
  assert.equal(page.calls.length, 4);
  assert.equal(page.timers.size, 1, "polling should retain only its next scheduled tick");
});

test("a workspace with existing runs retains explicitly opened modal intake", async () => {
  const page = createPage();
  page.setRequest(async (url) => {
    assert.equal(url, "/api/state");
    return response(fixtureSnapshot());
  });
  await page.evaluate("refresh()");
  assert.equal(page.get("intake-home").hidden, true);
  assert.equal(page.get("intake-content").parentElement, page.get("dialog-intake-slot"));
  assert.equal(page.get("new-dialog").open, false);
  await page.get("new-run").emit("click");
  assert.equal(page.get("new-dialog").open, true);
  assert.equal(page.document.activeElement, page.get("urls"));
  await page.get("close-dialog").emit("click");
  assert.equal(page.get("intake-home").hidden, true);
  assert.equal(page.get("intake-content").parentElement, page.get("dialog-intake-slot"));
  assert.equal(page.calls.length, 1, "opening or closing intake must not submit or refresh a task");
});

test("inline preparation keeps its second step visible until the task starts", async () => {
  const page = createPage();
  let state = fixtureSnapshot([]);
  page.setRequest(async (url, options) => {
    if (url === "/api/state") return response(state);
    assert.equal(url, "/api/prepare", "free input preparation must never start a model request");
    assert.equal(JSON.parse(options.body).text, "Synthetic public advisory, only a local test.");
    state = fixtureSnapshot();
    return response({run_id: "prepared-run"});
  });
  await page.evaluate("refresh()");
  page.get("mode").value = "material";
  await page.get("mode").emit("change");
  page.get("material").value = "Synthetic public advisory, only a local test.";
  page.get("repo").value = "D:\\synthetic\\repo";
  await page.get("prepare-form").emit("submit");
  assert.equal(page.evaluate("preparedId"), "prepared-run");
  assert.equal(page.get("intake-home").hidden, false, "a newly prepared run must not hide the form being used");
  assert.equal(page.get("run-form").closest("#intake-home"), page.get("intake-home"));
  assert.equal(page.get("prepared-summary").hidden, false);
  assert.equal(page.get("result-empty").hidden, true);
  assert.equal(page.get("start").disabled, true, "preparation alone does not grant paid-request consent");
  assert.equal(page.get("new-dialog").open, false);
  assert.equal(page.calls.filter((call) => call.options.method === "POST").length, 1);
  state = fixtureSnapshot([fixtureRun("prepared-run", "running")]);
  await page.evaluate("refresh()");
  assert.equal(page.get("intake-home").hidden, true);
  assert.equal(page.get("intake-content").parentElement, page.get("dialog-intake-slot"));
  assert.equal(page.get("review-toolbar").hidden, false);
  assert.equal(page.get("result-empty").hidden, false);
  assert.equal(page.get("new-dialog").open, false);
});

test("clear intake and source-location labels preserve the canonical entry_point field", () => {
  const page = createPage();
  assert.match(page.get("new-run").textContent, /添加资料并提取/);
  assert.match(page.get("new-heading").textContent, /添加资料并提取/);
  assert.equal(page.evaluate("fieldNames.entry_point"), "源码入口位置");
  assert.equal(page.evaluate('Object.hasOwn(fieldNames, "源码入口位置")'), false);
  page.context.fixtureResult = {
    entries: [{entry_id: "synthetic-entry", vuln_title: "Synthetic fixture", entry_point: {
      file: "synthetic.c", line: 14, code: "synthetic_read(input);", desc: "Synthetic source location.",
    }}],
    reviews: [{entry_id: "synthetic-entry", report_id: "SYNTHETIC-1", status: "draft", field_reviews: {
      entry_point: {status: "supported", reason: "Synthetic source evidence.", evidence_refs: []},
    }, evidence: []}],
  };
  const original = JSON.stringify(page.context.fixtureResult);
  page.evaluate("result = fixtureResult; renderCase(result.reviews[0])");
  const field = page.get("fields").children.find((node) => node.querySelector("summary")?.textContent.startsWith("源码入口位置"));
  assert.ok(field, "the canonical entry_point must render under the clearer source-location label");
  assert.match(field.textContent, /synthetic\.c · 行 14/);
  assert.match(field.textContent, /synthetic_read\(input\);/);
  assert.match(field.textContent, /Synthetic source evidence\./);
  assert.equal(JSON.stringify(page.context.fixtureResult), original, "display labels must not rename or mutate result schema keys");
  assert.equal(page.calls.length, 0);
});

function coverageFixture(input = "synthetic-input", plan = {proposed_count: 4, selected_count: 3, omitted_count: 1}) {
  const reviews = ["draft", "draft", "complete"].map((status, index) => ({
    entry_id: index ? input + "-" + index : input, input_id: input, slot: index + 1,
    report_id: "SYNTHETIC-1", status, process_metadata_scope: "candidate_with_shared_usage",
    input_actions: index ? [] : [{action: "candidate_plan", ...plan}], actions: [],
    field_reviews: {}, draft_fields: {}, suggested_values: {}, evidence: [],
  }));
  return {summary: {status: "completed", input_count: 1, requested_input_count: 1,
    unprocessed_input_count: 0, candidate_count: 1, draft_count: 2}, reviews,
    entries: [{entry_id: reviews[2].entry_id, project: "Synthetic", vuln_title: "Synthetic candidate", verify: 0}]};
}

test("same-report draft cards expose saved locations and stable ordinals without changing data or focus", async () => {
  const page = createPage(), data = coverageFixture();
  data.entries = [];
  for (const [index, review] of data.reviews.entries()) {
    review.status = "draft";
    review.draft_fields = {project: "Synthetic", vuln_title: "Material " + (index + 1)};
  }
  data.reviews[0].draft_fields.critical_operation = {file: "packages/nodes/Alpha/Alpha.node.ts", line: "31-34"};
  data.reviews[1].suggested_values.critical_operation = {file: "packages/nodes/Beta/Beta.node.ts", line: 52};
  data.reviews[2].draft_fields.entry_point = {file: "packages/nodes/Gamma/Gamma.node.ts", line: 73};
  page.context.fixtureResult = data;
  const original = JSON.stringify(data);
  page.evaluate("result = fixtureResult; renderCases()");
  const markers = page.get("cases").querySelectorAll(".case-marker");
  assert.deepEqual(markers.map((node) => node.textContent), [
    "第 1 条 · Alpha.node.ts:31-34", "第 2 条 · 建议位置 · Beta.node.ts:52", "第 3 条 · Gamma.node.ts:73",
  ]);
  assert.equal(markers[1].title, "第 2 条 · 建议位置 · packages/nodes/Beta/Beta.node.ts:52");
  await page.get("cases").children[1].click();
  assert.equal(page.evaluate("selectedCase"), 1);
  assert.equal(page.document.activeElement, page.get("cases").children[1], "click restores focus after card rendering");
  assert.equal(page.get("cases").children[1].getAttribute("aria-pressed"), "true");
  page.get("case-search").value = "material 3";
  await page.get("case-search").emit("input");
  assert.equal(page.get("case-count").textContent, "1 / 3 条结果");
  assert.equal(page.get("cases").querySelector(".case-marker").textContent, "第 3 条 · Gamma.node.ts:73",
    "search must not renumber the saved result order");
  page.get("case-search").value = "SYNTHETIC-1";
  await page.get("case-search").emit("input");
  assert.equal(page.get("cases").children.length, 3, "existing report search still works");
  assert.equal(JSON.stringify(data), original, "card labels must never promote suggestions or mutate output");
  assert.equal(page.calls.length, 0);
});

test("card identifiers fall back to saved IDs and keep long paths readable and literal", () => {
  const page = createPage(), data = coverageFixture();
  data.entries = [];
  const longName = "UnusuallyLongSource".repeat(12) + "<draft>.ts";
  const longPath = "packages\\" + "nested\\".repeat(30) + longName;
  data.reviews[1].entry_id = "saved-draft-id";
  delete data.reviews[2].entry_id;
  data.reviews[0].suggested_values.entry_point = {file: longPath, line: 44};
  page.context.fixtureResult = data;
  const original = JSON.stringify(data);
  page.evaluate("result = fixtureResult; renderCases()");
  const markers = page.get("cases").querySelectorAll(".case-marker");
  assert.equal(markers[0].textContent, "第 1 条 · 建议位置 · " + longName + ":44");
  assert.equal(markers[0].title, "第 1 条 · 建议位置 · " + longPath + ":44", "the full path must not be lost");
  assert.equal(markers[0].children.length, 0, "source text is textContent, not HTML");
  assert.equal(markers[1].textContent, "第 2 条 · saved-draft-id");
  assert.equal(markers[2].textContent, "第 3 条 · 位置待补充");
  const css = fs.readFileSync(path.join(assets, "app.css"), "utf8");
  const markerRule = css.match(/\.case-marker\s*\{([^}]+)\}/)?.[1];
  assert.ok(markerRule);
  assert.match(markerRule, /overflow-wrap:\s*anywhere/);
  assert.match(markerRule, /-webkit-line-clamp:\s*2/);
  assert.match(markerRule, /overflow:\s*hidden/);
  assert.equal(JSON.stringify(data), original);
  assert.equal(page.calls.length, 0);
});

test("saved omitted proposals are visible without adding results or mixing input and result counts", async () => {
  const page = createPage(), data = coverageFixture();
  const original = JSON.stringify(data), run = fixtureRun("coverage-run", "imported");
  run.summary = data.summary;
  preparePage(page, [run]);
  page.context.fixtureResult = data;
  await page.evaluate("result = fixtureResult; resultRun = selectedRun; renderCases(); render()");
  assert.equal(page.get("run-title").textContent, "已处理 1 份资料 · 字段已齐 1 条结果");
  assert.equal(page.get("run-subtitle").textContent, "2 条结果待补充 · 0 份资料未处理");
  assert.equal(page.get("case-count").textContent, "3 / 3 条结果");
  assert.equal(page.get("cases").children.length, 3, "the fourth proposal must not become a fake review");
  assert.equal(page.get("progress").value, 1);
  assert.equal(page.get("candidate-coverage").hidden, false);
  assert.equal(page.get("candidate-coverage").open, false);
  assert.match(page.get("candidate-coverage-summary").textContent, /提出 4 · 选中 3 · 未选 1（含去重）/);
  assert.match(page.get("candidate-coverage-detail").textContent, /提案不是已确认漏洞/);
  assert.match(page.get("candidate-coverage-detail").textContent, /未选提案未逐条处理/);
  assert.match(page.get("candidate-coverage-detail").textContent, /编码预留 未记录/);
  assert.equal(JSON.stringify(data), original, "display must not mutate saved counts or decisions");
  assert.equal(page.calls.length, 0);
});

test("serial coverage resolves each input's slot one once even in reversed review order", () => {
  const page = createPage(), first = coverageFixture("input-a"), second = coverageFixture("input-b");
  second.reviews[0].input_actions[0] = {action: "candidate_plan", proposed_count: 5, selected_count: 3, omitted_count: 2,
    encoding_reserve: 1, scope: "PROPOSAL_TEXT_NOT_A_FACT"};
  first.reviews[0].input_actions[0].encoding_reserve = 0;
  // A copied child packet must not be summed as an independent input plan.
  first.reviews[1].input_actions = [structuredClone(first.reviews[0].input_actions[0])];
  page.context.fixtureReviews = [...first.reviews, ...second.reviews].reverse();
  const before = JSON.stringify(page.context.fixtureReviews);
  page.evaluate("renderCandidateCoverage(fixtureReviews)");
  assert.match(page.get("candidate-coverage-summary").textContent, /提出 9 · 选中 6 · 未选 3/);
  const details = page.get("candidate-coverage-detail").textContent;
  assert.equal(details.split("input-a：").length - 1, 1);
  assert.equal(details.split("input-b：").length - 1, 1);
  assert.match(details, /编码预留 0 次（未必消费）/);
  assert.match(details, /编码预留 1 次（未必消费）/);
  assert.doesNotMatch(details, /PROPOSAL_TEXT_NOT_A_FACT/);
  assert.equal(JSON.stringify(page.context.fixtureReviews), before);
  assert.equal(page.calls.length, 0);
});

test("old shared_input and pre-serial actions retain recorded coverage without inventing a pool", () => {
  const page = createPage(), shared = coverageFixture("old-input").reviews;
  for (const row of shared) {
    row.process_metadata_scope = "shared_input";
    row.actions = row.input_actions;
    delete row.input_actions;
  }
  const legacy = {entry_id: "legacy-entry", actions: [{action: "candidate_plan",
    proposed_count: 2, selected_count: 1, omitted_count: 1}]};
  page.context.fixtureReviews = [shared[2], legacy, shared[0], shared[1]];
  page.evaluate("renderCandidateCoverage(fixtureReviews)");
  assert.match(page.get("candidate-coverage-summary").textContent, /提出 6 · 选中 4 · 未选 2/);
  assert.equal(page.get("candidate-coverage-detail").textContent.split("编码预留 未记录").length - 1, 2);
  assert.doesNotMatch(page.get("candidate-coverage-detail").textContent, /编码预留 0/);
  assert.equal(page.calls.length, 0);
});

test("missing, conflicting and duplicated plans remain unknown or inconsistent instead of zero", () => {
  const page = createPage();
  for (const mutation of [
    (rows) => { rows[0].input_actions = []; },
    (rows) => { delete rows[0].input_actions[0].omitted_count; },
    (rows) => { rows[0].input_actions[0].selected_count = true; },
    (rows) => { rows[0].input_actions[0].omitted_count = 0; },
    (rows) => { rows[0].input_actions.push(structuredClone(rows[0].input_actions[0])); },
    (rows) => { rows[1].slot = 1; },
    (rows) => { rows[1].process_metadata_scope = "shared_input"; },
  ]) {
    const rows = coverageFixture().reviews;
    mutation(rows);
    page.context.fixtureReviews = rows;
    page.evaluate("renderCandidateCoverage(fixtureReviews)");
    assert.match(page.get("candidate-coverage-summary").textContent, /未记录|不一致/);
    assert.doesNotMatch(page.get("candidate-coverage-summary").textContent, /提出 0|未选 0/);
  }
  page.evaluate("renderCandidateCoverage([])");
  assert.match(page.get("candidate-coverage-summary").textContent, /未记录/);
  assert.equal(page.calls.length, 0);
});

test("one missing input prevents a falsely complete aggregate while retaining known input details", () => {
  const page = createPage(), first = coverageFixture("known-input"), second = coverageFixture("unknown-input");
  second.reviews[0].input_actions = [];
  page.context.fixtureReviews = [...first.reviews, ...second.reviews];
  page.evaluate("renderCandidateCoverage(fixtureReviews)");
  assert.match(page.get("candidate-coverage-summary").textContent, /部分未记录/);
  assert.doesNotMatch(page.get("candidate-coverage-summary").textContent, /提出 4/);
  assert.match(page.get("candidate-coverage-detail").textContent, /known-input：提出 4/);
  assert.match(page.get("candidate-coverage-detail").textContent, /unknown-input：未记录/);
  assert.equal(page.calls.length, 0);
});

test("invalid reserve is not rewritten as zero and explicitly recorded zero counts stay zero", () => {
  const page = createPage(), data = coverageFixture();
  data.reviews[0].input_actions[0].encoding_reserve = true;
  page.context.fixtureReviews = data.reviews;
  page.evaluate("renderCandidateCoverage(fixtureReviews)");
  assert.match(page.get("candidate-coverage-detail").textContent, /编码预留 记录不一致/);
  assert.doesNotMatch(page.get("candidate-coverage-detail").textContent, /编码预留 0/);
  page.context.fixtureReviews = [{entry_id: "zero-plan", actions: [{action: "candidate_plan",
    proposed_count: 0, selected_count: 0, omitted_count: 0}]}];
  page.evaluate("renderCandidateCoverage(fixtureReviews)");
  assert.match(page.get("candidate-coverage-summary").textContent, /提出 0 · 选中 0 · 未选 0/);
  assert.equal(page.calls.length, 0);
});

test("choosing another run clears prior proposal coverage until its own saved result loads", () => {
  const page = createPage();
  preparePage(page, [fixtureRun("old", "imported"), fixtureRun("new", "prepared")]);
  page.context.fixtureReviews = coverageFixture().reviews;
  page.evaluate('renderCandidateCoverage(fixtureReviews); document.getElementById("candidate-coverage").open = true; chooseRun("new")');
  assert.equal(page.get("candidate-coverage").hidden, true);
  assert.equal(page.get("candidate-coverage").open, false);
  assert.equal(page.get("candidate-coverage-detail").children.length, 0);
  assert.match(page.get("candidate-coverage-summary").textContent, /未记录/);
  assert.equal(page.get("case-count").textContent, "0 条结果");
  assert.equal(page.calls.length, 0);
});

test("prepared form fingerprint follows material inputs, not temporary credentials", () => {
  const page = createPage();
  preparePage(page);
  const initial = page.evaluate("formFingerprint()");
  for (const id of ["urls", "material", "repo", "source", "cache", "mapping"]) {
    const before = page.get(id).value;
    page.get(id).value = `${before} changed`;
    assert.notEqual(page.evaluate("formFingerprint()"), initial, `${id} must invalidate preparation`);
    page.get(id).value = before;
  }
  page.get("files").files = [{name: "fixture.md", size: 20, lastModified: 1}];
  assert.notEqual(page.evaluate("formFingerprint()"), initial, "changing uploaded files must invalidate preparation");
  page.get("files").files = [];
  page.get("key").value = "another-synthetic-key";
  assert.equal(page.evaluate("formFingerprint()"), initial, "key changes must not require re-reading source material");
  page.get("mode").value = "batch";
  const batch = page.evaluate("formFingerprint()");
  assert.notEqual(batch, initial);
  page.get("input-path").value = "D:\\synthetic\\batch.jsonl";
  assert.notEqual(page.evaluate("formFingerprint()"), batch);
});

test("editing prepared materials blocks Start and resets explicit consent", async () => {
  const page = createPage();
  preparePage(page);
  assert.equal(page.get("start").disabled, false, "a valid prepared form should be startable");
  page.get("material").value += " Changed after preparation.";
  await page.get("material").emit("input");
  page.evaluate("controls()");
  assert.equal(page.evaluate("preparedId"), null);
  assert.equal(page.evaluate("preparedFingerprint"), null);
  assert.equal(page.get("start").disabled, true);
  assert.equal(page.get("confirmed").checked, false);
  assert.ok(page.get("start-reason").textContent.trim(), "disabled Start needs an actionable explanation");
  assert.equal(page.calls.length, 0, "invalidating preparation must remain local and free");
});

test("draft export is offered only when the selected batch actually declares it", () => {
  const page = createPage();
  const history = fixtureRun("export-run", "imported");
  history.summary = {files: ["entries.jsonl", "review.jsonl"]};
  preparePage(page, [history]);
  page.evaluate('selectedRun = "export-run"; renderDownloads(selectedRun)');
  assert.ok(!page.get("downloads").textContent.includes("导出待补充条目"));
  page.evaluate('snapshot.runs[0].summary.files.push("drafts.jsonl"); renderDownloads(selectedRun)');
  assert.ok(page.get("downloads").textContent.includes("导出待补充条目"));
  page.evaluate('snapshot.runs[0].summary.files.pop(); renderDownloads(selectedRun)');
  assert.ok(!page.get("downloads").textContent.includes("导出待补充条目"));
  assert.equal(page.calls.length, 0);
});

test("start gating checks cap, confirmation, budget, and connection before any request", async () => {
  const page = createPage();
  preparePage(page);
  assert.equal(page.get("start").disabled, false);
  for (const cap of ["", "0", "99", "3.5"]) {
    page.get("cap").value = cap;
    page.evaluate("controls()");
    assert.equal(page.get("start").disabled, true, `invalid cap ${JSON.stringify(cap)} must block Start`);
    assert.ok(page.get("start-reason").textContent.trim());
  }
  page.get("cap").value = "12";
  page.get("confirmed").checked = false;
  page.evaluate("controls()");
  assert.equal(page.get("start").disabled, true);
  page.get("confirmed").checked = true;
  page.evaluate("snapshot.budget.pending = 1; controls()");
  assert.equal(page.get("start").disabled, true);
  page.evaluate("snapshot.budget.pending = 0; connected = false; controls()");
  assert.equal(page.get("start").disabled, true);
  assert.equal(page.get("prepare").disabled, true);
  assert.ok(page.get("prepare-reason").textContent.trim());
  page.evaluate("connected = true; controls()");
  assert.equal(page.get("start").disabled, false);
  page.get("cap").value = "10";
  await page.get("cap").emit("input");
  assert.equal(page.get("confirmed").checked, false, "changing the allowed request budget requires fresh consent");
  assert.equal(page.get("start").disabled, true);
  assert.equal(page.calls.length, 0);
});

test("managed first launch shows zero usage and prepares freely before explicit per-batch consent", async () => {
  const page = createPage();
  let state = managedSnapshot();
  page.setRequest(async (url, options) => {
    if (url === "/api/state") return response(state);
    if (url === "/api/prepare") {
      const payload = JSON.parse(options.body);
      assert.ok(payload.text);
      assert.equal(payload.key, undefined, "free preparation must not send credentials");
      state = managedSnapshot([fixtureRun()]);
      return response({run_id: "prepared-run"});
    }
    if (url === "/api/start") {
      assert.deepEqual(JSON.parse(options.body), {run_id: "prepared-run",
        key: "synthetic-key-for-offline-tests", max_requests: 12, confirmed: true});
      state = managedSnapshot([fixtureRun("prepared-run", "running")]);
      return response({status: "started"});
    }
    throw new Error(`Unexpected offline request: ${url}`);
  });
  await page.evaluate("poll()");
  assert.equal(page.get("budget").textContent, "已用 0 次");
  assert.equal(page.get("budget-prefix").hidden, true);
  assert.equal(page.get("budget-hint").hidden, true);
  assert.equal(page.get("budget-detail").textContent,
    "本机累计用量自动保存。每批按你填写的请求上限执行；费用以模型平台为准。");
  assert.doesNotMatch(page.get("budget").textContent, /3000|3,000|授权|\//);
  assert.doesNotMatch(page.get("cap-hint").textContent, /总额度|账本|配置/);
  assert.match(page.get("confirmation-text").textContent, /本批最多/);
  assert.equal(page.get("cap").max, "500");
  assert.equal(page.get("prepare").disabled, false);
  assert.equal(page.get("intake-home").hidden, false);
  assert.equal(page.get("new-dialog").open, false);
  assert.equal(page.get("start").disabled, true);
  assert.deepEqual(page.calls.map((call) => call.url), ["/api/state"]);

  page.get("mode").value = "material";
  await page.get("mode").emit("change");
  page.get("material").value = "Synthetic public advisory, no model request.";
  page.get("repo").value = "D:\\synthetic\\repo";
  await page.get("prepare-form").emit("submit");
  await page.flush();
  assert.equal(page.evaluate("preparedId"), "prepared-run");
  assert.equal(page.get("intake-home").hidden, false);
  assert.equal(page.get("new-dialog").open, false, "no extra setup dialog follows free preparation");
  assert.equal(page.get("start").disabled, true, "preparation alone cannot authorize a model request");
  page.get("cap").value = "12";
  page.get("key").value = "synthetic-key-for-offline-tests";
  await page.get("key").emit("input");
  await page.get("run-form").emit("submit");
  assert.equal(page.get("start").disabled, true);
  assert.match(page.get("start-reason").textContent, /本批请求上限确认/);
  assert.equal(page.calls.filter((call) => call.url === "/api/start").length, 0);
  page.get("confirmed").checked = true;
  await page.get("confirmed").emit("change");
  assert.equal(page.get("start").disabled, false);
  assert.equal(page.calls.filter((call) => call.url === "/api/start").length, 0,
    "checking consent must not automatically start a request");
  await page.get("run-form").emit("submit");
  await page.flush();
  assert.equal(page.calls.filter((call) => call.url === "/api/start").length, 1);
  assert.equal(page.get("key").value, "");
  assert.equal(page.get("confirmed").checked, false);
});

test("managed existing usage displays cumulative counts without turning the safety ceiling into authorization", async () => {
  const page = createPage();
  preparePage(page);
  page.context.fixtureState = managedSnapshot([fixtureRun()], 1234);
  await page.evaluate("snapshot = fixtureState; render()");
  assert.equal(page.get("budget").textContent, "已用 " + (1234).toLocaleString() + " 次");
  assert.doesNotMatch(page.get("budget").textContent, /3000|3,000|授权|\//);
  assert.equal(page.get("cap").max, "500");
  assert.equal(page.get("start").disabled, false);
  page.get("cap").value = "501";
  page.evaluate("controls()");
  assert.equal(page.get("start").disabled, true, "the per-batch ceiling remains 500 requests");
  page.get("cap").value = "12";
  page.context.fixtureState = managedSnapshot([fixtureRun()], 2990);
  await page.evaluate("snapshot = fixtureState; render()");
  assert.equal(page.get("budget").textContent, "已用 " + (2990).toLocaleString() + " 次");
  assert.equal(page.get("cap").max, "10");
  assert.equal(page.get("start").disabled, true);
  assert.match(page.get("start-reason").textContent, /1–10/);
  page.get("cap").value = "10";
  await page.get("cap").emit("input");
  assert.equal(page.get("confirmed").checked, false);
  assert.equal(page.get("start").disabled, true);
  page.get("confirmed").checked = true;
  await page.get("confirmed").emit("change");
  assert.equal(page.get("start").disabled, false);
  page.context.fixtureState = managedSnapshot([fixtureRun()], 3000);
  await page.evaluate("snapshot = fixtureState; render()");
  assert.equal(page.get("start").disabled, true);
  assert.match(page.get("start-reason").textContent, /累计请求次数已达到安全上限/);
  assert.equal(page.get("prepare").disabled, false, "a reached model limit must not block free preparation");
  assert.equal(page.calls.length, 0);
});

test("managed record errors block only model starts and show local guidance without setup dialogs", async () => {
  const page = createPage();
  preparePage(page);
  for (const code of ["managed_usage_unavailable", "managed_request_total_reached", "managed_budget_account_conflict"]) {
    page.context.fixtureState = managedSnapshot([fixtureRun()], 2);
    page.context.fixtureState.budget = {...page.context.fixtureState.budget, available: false, code};
    await page.evaluate("snapshot = fixtureState; render()");
    assert.equal(page.get("start").disabled, true);
    assert.equal(page.get("prepare").disabled, false);
    assert.equal(page.get("input-fields").disabled, false);
    assert.equal(page.get("new-dialog").open, false);
    assert.equal(page.get("budget-detail").textContent, page.evaluate(`errorNames[${JSON.stringify(code)}]`));
    assert.equal(page.get("start-reason").textContent, page.get("budget-detail").textContent);
    assert.doesNotMatch(page.get("start-reason").textContent, /账本|初始化|模型账户/);
    if (code === "managed_budget_account_conflict")
      assert.match(page.get("start-reason").textContent, /保留现有记录.*不要清零/);
    await page.get("run-form").emit("submit");
  }
  page.context.fixtureState = managedSnapshot([fixtureRun()], 2);
  page.context.fixtureState.budget.pending = 1;
  await page.evaluate("snapshot = fixtureState; render()");
  assert.equal(page.get("start").disabled, true, "an unfinished request remains fail-closed");
  assert.equal(page.get("prepare").disabled, false);
  assert.equal(page.calls.length, 0);
});

test("read-only demo labels its mode and blocks intake and model requests without ledger errors", async () => {
  const page = createPage();
  preparePage(page);
  await page.evaluate(`snapshot.read_only = true;
    snapshot.budget = {managed: true, available: false, code: "read_only_mode", remaining: 0}; render();`);
  assert.equal(page.get("budget").textContent, "演示模式 · 不调用模型");
  assert.match(page.get("budget-detail").textContent, /不需要 API key/);
  assert.equal(page.get("budget-prefix").hidden, true);
  assert.equal(page.get("budget-hint").hidden, true);
  for (const id of ["new-run", "prepare", "start", "input-fields", "key", "cap", "confirmed"])
    assert.equal(page.get(id).disabled, true, `${id} must not accept a demo write`);
  assert.match(page.get("start-reason").textContent, /演示模式/);
  assert.doesNotMatch(page.get("prepare-reason").textContent, /未就绪|暂不可用|额度已用完/);
  await page.get("new-run").emit("click");
  await page.get("prepare-form").emit("submit");
  await page.get("run-form").emit("submit");
  await page.get("stop").emit("click");
  assert.equal(page.get("new-dialog").open, false);
  assert.equal(page.calls.length, 0, "even dispatched form events must not submit a demo operation");

  // Ordinary mode retains the existing preparation/consent and request limits.
  await page.evaluate(`snapshot.read_only = false;
    snapshot.budget = {available: true, used: 2, limit: 100, remaining: 98, pending: 0}; render();`);
  for (const id of ["new-run", "prepare", "start", "input-fields", "key", "cap", "confirmed"])
    assert.equal(page.get(id).disabled, false, `${id} should recover its ordinary-mode behavior`);
  assert.equal(page.get("budget").textContent, "2 / 100");
  assert.equal(page.get("budget-prefix").hidden, false);
  assert.equal(page.get("budget-hint").hidden, false);
  assert.equal(page.get("cap-hint").textContent, "这是停止上限，不是要用满的次数。与右上角总额度共同生效。");
  assert.equal(page.get("confirmation-text").textContent, "我确认将已检查的资料和相关源码发送给模型，并允许使用上述额度。");
});

test("read-only demo preserves batch switching, search, preview, and original-file export", async () => {
  const page = createPage(), data = coverageFixture();
  const original = JSON.stringify(data);
  preparePage(page, [fixtureRun("demo-a", "imported"), fixtureRun("demo-b", "imported")]);
  page.evaluate(`snapshot.read_only = true;
    snapshot.budget = {available: false, code: "read_only_mode", remaining: 0};`);
  page.setRequest(async (url, options) => {
    assert.notEqual(options?.method, "POST", "demo interaction cannot write or start a task");
    if (url === "/api/result/demo-a" || url === "/api/result/demo-b") return response(data);
    if (url === "/api/download/demo-b/entries.jsonl")
      return {ok: true, blob: async () => new Blob(["synthetic original dataset"])};
    throw new Error(`Unexpected offline request: ${url}`);
  });
  await page.evaluate("render()");
  assert.equal(page.get("run-select").disabled, false);
  assert.equal(page.get("case-search").disabled, false);
  assert.equal(page.get("case-filter").disabled, false);
  page.get("case-search").value = "SYNTHETIC-1";
  await page.get("case-search").emit("input");
  assert.equal(page.get("cases").querySelectorAll("button").length, 3);
  page.get("run-select").value = "demo-b";
  await page.get("run-select").emit("change");
  await page.flush();
  assert.equal(page.evaluate("resultRun"), "demo-b");
  assert.equal(page.get("result-content").hidden, false);
  const download = page.get("downloads").querySelector("button");
  assert.equal(download.disabled, false);
  await download.emit("click");
  assert.deepEqual(page.calls.map((call) => call.url), [
    "/api/result/demo-a", "/api/result/demo-b", "/api/download/demo-b/entries.jsonl",
  ]);
  assert.equal(JSON.stringify(data), original, "demo viewing must not modify saved result data");
});

test("an empty demo workspace explains the missing results instead of offering unusable input", async () => {
  const page = createPage();
  page.context.fixtureState = {...fixtureSnapshot([]), read_only: true,
    budget: {available: false, code: "read_only_mode", remaining: 0}};
  await page.evaluate("snapshot = fixtureState; connected = true; render()");
  assert.equal(page.get("intake-home").hidden, true);
  assert.equal(page.get("new-dialog").open, false);
  assert.match(page.get("empty-title").textContent, /演示模式/);
  assert.match(page.get("empty-description").textContent, /暂无可查看/);
  assert.equal(page.get("new-run").disabled, true);
  assert.equal(page.calls.length, 0);
});

test("Start targets the prepared form, not whichever historical run is being inspected", async () => {
  const page = createPage();
  const history = fixtureRun("historical-run", "imported");
  preparePage(page, [fixtureRun(), history]);
  page.evaluate('selectedRun = "historical-run"; controls()');
  assert.equal(page.get("start").disabled, false);
  page.setRequest(async (url, options) => {
    if (url === "/api/start") {
      assert.equal(JSON.parse(options.body).run_id, "prepared-run");
      return response({status: "started"});
    }
    if (url === "/api/state") return response(fixtureSnapshot([fixtureRun("prepared-run", "running"), history]));
    if (url === "/api/result/historical-run") return response({summary: {}, entries: [], reviews: []});
    throw new Error(`Unexpected offline request: ${url}`);
  });
  await page.get("run-form").emit("submit");
  await page.flush();
  assert.equal(page.calls.filter((call) => call.url === "/api/start").length, 1);
  assert.equal(page.get("key").value, "");
  assert.equal(page.get("confirmed").checked, false);
});

test("unchanged state preserves batch option nodes and selector focus", () => {
  const page = createPage();
  preparePage(page, [fixtureRun(), fixtureRun("old-run", "imported")]);
  page.evaluate("renderRunChoices()");
  const select = page.get("run-select");
  const options = [...select.children];
  const replacements = select.replaceCount;
  assert.equal(options.length, 2);
  select.focus();
  page.evaluate("renderRunChoices(); renderRunChoices()");
  assert.deepEqual(select.children, options, "polling must keep existing option identities");
  assert.equal(select.replaceCount, replacements, "unchanged polling must not rebuild the dropdown");
  assert.equal(page.document.activeElement, select);
});

test("batch tooltip follows selection even with unchanged options or a focused dropdown", async () => {
  const page = createPage();
  preparePage(page, [fixtureRun("batch-a"), fixtureRun("batch-b")]);
  page.evaluate('resultNames.set("batch-a", "v84 · 1 条结果 · Alpha"); resultNames.set("batch-b", "v83 · 3 条结果 · Beta"); renderRunChoices()');
  const select = page.get("run-select");
  const options = [...select.children], replacements = select.replaceCount;
  assert.equal(select.title, "v84 · 1 条结果 · Alpha");
  select.focus();
  select.value = "batch-b";
  await select.emit("change");
  await page.flush();
  assert.equal(page.evaluate("selectedRun"), "batch-b");
  assert.equal(select.title, "v83 · 3 条结果 · Beta", "focused selection must update its tooltip/help immediately");
  assert.equal(page.document.activeElement, select);
  assert.deepEqual(select.children, options);
  assert.equal(select.replaceCount, replacements);
  page.document.activeElement = null;
  page.evaluate('chooseRun("batch-a"); renderRunChoices()');
  assert.equal(select.title, "v84 · 1 条结果 · Alpha", "the unchanged-signature path must update help too");
  assert.equal(select.value, "batch-a");
  assert.deepEqual(select.children, options);
  assert.equal(select.replaceCount, replacements);
  assert.equal(page.calls.length, 0);
});

test("an older state response cannot overwrite a newer snapshot", async () => {
  const page = createPage();
  preparePage(page);
  const first = deferred();
  const second = deferred();
  page.setRequest((url) => {
    assert.equal(url, "/api/state");
    return page.calls.length === 1 ? first.promise : second.promise;
  });
  const olderRequest = page.evaluate("refresh()");
  const newerRequest = page.evaluate("refresh()");
  second.resolve(response({...fixtureSnapshot(), marker: "newer"}));
  await newerRequest;
  first.resolve(response({...fixtureSnapshot(), marker: "older"}));
  await olderRequest;
  assert.equal(page.evaluate("snapshot.marker"), "newer");
  assert.equal(page.evaluate("connected"), true);
  assert.equal(page.calls.length, 2);
});

test("a successful state refresh restores connected controls after an outage", async () => {
  const page = createPage();
  preparePage(page);
  page.setRequest(async () => { throw new Error("synthetic offline failure"); });
  await Promise.resolve(page.evaluate("refresh()")).catch(() => {});
  assert.equal(page.evaluate("connected"), false);
  assert.equal(page.get("prepare").disabled, true);
  page.setRequest(async (url) => {
    assert.equal(url, "/api/state");
    return response(fixtureSnapshot());
  });
  await page.evaluate("refresh()");
  assert.equal(page.evaluate("connected"), true);
  assert.equal(page.get("prepare").disabled, false);
  assert.equal(page.get("start").disabled, false);
});

test("failed preview keeps exports available and explicit Retry can load it successfully", async () => {
  const page = createPage();
  const run = fixtureRun("finished-run", "finished");
  preparePage(page, [run]);
  page.setRequest(async (url) => {
    assert.equal(url, "/api/result/finished-run");
    return response({code: "result_unavailable_or_too_large"}, false);
  });
  await page.evaluate("render()");
  await page.flush();
  assert.equal(page.calls.length, 1);
  assert.notEqual(page.evaluate("resultRun"), run.id, "failed preview must not be cached as loaded");
  assert.equal(page.get("retry-preview").hidden, false);
  assert.ok(page.get("downloads").querySelectorAll("button").length > 0,
    "registered exports must remain available when a preview is oversized or temporarily unreadable");
  page.setRequest(async (url) => {
    assert.equal(url, "/api/result/finished-run");
    return response({summary: {status: "completed"}, entries: [], reviews: []});
  });
  await page.get("retry-preview").emit("click");
  await page.flush();
  assert.equal(page.calls.length, 2, "one click should make exactly one new preview request");
  assert.equal(page.evaluate("resultRun"), run.id);
  assert.equal(page.evaluate("Boolean(previewError)"), false);
  assert.equal(page.get("retry-preview").hidden, true);
});

test("late preview success or failure from an old selection cannot replace the new request", async () => {
  for (const outcome of ["success", "failure"]) {
    const page = createPage();
    preparePage(page, [fixtureRun("run-a", "finished"), fixtureRun("run-b", "finished")]);
    const oldPreview = deferred();
    const newPreview = deferred();
    page.setRequest((url) => {
      assert.equal(url, "/api/result/run-a");
      return page.calls.length === 1 ? oldPreview.promise : newPreview.promise;
    });
    const oldRequest = page.evaluate("loadResult(snapshot.runs[0])");
    page.evaluate('chooseRun("run-b"); chooseRun("run-a")');
    const newRequest = page.evaluate("loadResult(snapshot.runs[0])");
    if (outcome === "success") oldPreview.resolve(response({marker: "obsolete", entries: [], reviews: []}));
    else oldPreview.reject(new Error("obsolete synthetic preview failure"));
    await oldRequest;
    assert.equal(page.evaluate("loadingResult"), "run-a", `${outcome}: old completion must not clear a newer pending preview`);
    assert.equal(page.evaluate("result"), null, `${outcome}: old completion must not publish results`);
    assert.equal(page.evaluate("Boolean(previewError)"), false, `${outcome}: old error must not poison the new selection`);
    newPreview.resolve(response({marker: "current", entries: [], reviews: []}));
    await newRequest;
    assert.equal(page.evaluate("result.marker"), "current");
    assert.equal(page.evaluate("resultRun"), "run-a");
    assert.equal(page.evaluate("loadingResult"), null);
    assert.equal(page.calls.length, 2);
  }
});

test("a pending historical download does not block Stop or follow the current selection", async () => {
  const page = createPage();
  preparePage(page, [fixtureRun("history", "finished"), fixtureRun("active", "running")]);
  page.evaluate('renderDownloads("history"); controls()');
  const button = page.get("downloads").querySelector("button");
  assert.ok(button);
  const pendingDownload = deferred();
  page.setRequest(async (url) => {
    if (url === "/api/download/history/entries.jsonl") return pendingDownload.promise;
    if (url === "/api/stop") return response({status: "stopping_after_current"});
    if (url === "/api/state") return response(fixtureSnapshot([fixtureRun("history", "finished"), fixtureRun("active", "stopping")]));
    throw new Error(`Unexpected offline request: ${url}`);
  });
  const download = button.emit("click");
  assert.equal(button.disabled, true);
  assert.equal(page.evaluate("busy"), false, "a read-only download must not take the global operation lock");
  page.evaluate('chooseRun("active"); controls()');
  assert.equal(page.get("stop").hidden, false);
  assert.equal(page.get("stop").disabled, false);
  await page.get("stop").emit("click");
  const stop = page.calls.find((call) => call.url === "/api/stop");
  assert.ok(stop, "Stop must be sent while the separate download is still pending");
  assert.equal(JSON.parse(stop.options.body).run_id, "active");
  assert.equal(button.disabled, true, "the download should still be pending during Stop");
  pendingDownload.resolve({ok: true, blob: async () => new Blob(["synthetic exported data"])});
  await download;
  assert.equal(button.disabled, false);
  assert.equal(page.evaluate("busy"), false);
  assert.deepEqual(page.calls.filter((call) => call.url.startsWith("/api/download/")).map((call) => call.url),
    ["/api/download/history/entries.jsonl"], "changing selection must not change a queued download's origin");
});
