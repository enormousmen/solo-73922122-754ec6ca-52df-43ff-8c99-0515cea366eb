"use strict";

const byId = (id) => document.getElementById(id);

const form = byId("scan-form");
const input = byId("archive-input");
const dropZone = byId("drop-zone");
const dropTitle = byId("drop-title");
const dropHint = byId("drop-hint");
const filePill = byId("file-pill");
const scanButton = byId("scan-button");
const demoButton = byId("demo-button");
const statusBox = byId("status-box");
const errorBox = byId("error-box");
const errorCode = byId("error-code");
const errorMessage = byId("error-message");
const errorMeta = byId("error-meta");
const results = byId("results");
const resultSubtitle = byId("result-subtitle");
const metricLayers = byId("metric-layers");
const metricFiles = byId("metric-files");
const metricSuid = byId("metric-suid");
const metricSgid = byId("metric-sgid");
const safetyNote = byId("safety-note");
const layerStrip = byId("layer-strip");
const findingsBody = byId("findings-body");
const tableWrap = document.querySelector(".table-wrap");
const emptyState = byId("empty-state");
const selectAll = byId("select-all");
const repairPanel = byId("repair-panel");
const repairButton = byId("repair-button");
const repairSelectedCount = byId("repair-selected-count");
const repairTotalCount = byId("repair-total-count");
const repairStatus = byId("repair-status");
const repairError = byId("repair-error");
const repairErrorCode = byId("repair-error-code");
const repairErrorMessage = byId("repair-error-message");
const repairErrorMeta = byId("repair-error-meta");
const repairResult = byId("repair-result");
const repairResultDetail = byId("repair-result-detail");
const repairDownload = byId("repair-download");
const repairRescan = byId("repair-rescan");
const repairDiff = byId("repair-diff");

let selectedFile = null;
let busy = false;
let repairBusy = false;
let currentScan = null;
const checkedPaths = new Set();

function el(tag, className, text) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined && text !== null) node.textContent = String(text);
  return node;
}

function formatBytes(bytes) {
  if (!Number.isFinite(bytes) || bytes <= 0) return "0 B";
  const units = ["B", "KB", "MB", "GB", "TB"];
  const index = Math.min(
    Math.floor(Math.log(bytes) / Math.log(1024)),
    units.length - 1
  );
  const value = bytes / 1024 ** index;
  return `${value >= 10 || index === 0 ? value.toFixed(0) : value.toFixed(1)} ${units[index]}`;
}

function setStatus(message) {
  if (!message) {
    statusBox.hidden = true;
    statusBox.textContent = "";
    return;
  }
  statusBox.hidden = false;
  statusBox.textContent = message;
}

function setError(error) {
  errorBox.hidden = true;
  if (!error) return;

  errorCode.textContent = error.code || "扫描失败";
  errorMessage.textContent = error.message || "无法完成扫描。";
  const metaParts = [];
  if (error.path) metaParts.push(`路径 ${error.path}`);
  if (error.layer_number !== undefined && error.layer_number !== null) {
    metaParts.push(`层 ${error.layer_number}`);
  }
  if (error.layer_path) metaParts.push(error.layer_path);
  if (metaParts.length) {
    errorMeta.hidden = false;
    errorMeta.textContent = metaParts.join(" · ");
  } else {
    errorMeta.hidden = true;
    errorMeta.textContent = "";
  }
  errorBox.hidden = false;
  errorBox.scrollIntoView({ behavior: "smooth", block: "nearest" });
}

function describeHttpDetail(payload) {
  const detail = payload && payload.detail;
  if (!detail) {
    return { code: "request_failed", message: "服务返回了无法识别的响应。" };
  }
  if (typeof detail === "string") {
    return { code: "request_failed", message: detail };
  }
  if (Array.isArray(detail)) {
    const messages = detail.map((item) => item && (item.msg || item.message)).filter(Boolean);
    return {
      code: "validation_error",
      message: messages.join("；") || "请求参数无效。",
    };
  }
  return {
    code: detail.code || "request_failed",
    message: detail.message || "请求失败。",
    path: detail.path,
    layer_number: detail.layer_number,
    layer_path: detail.layer_path,
  };
}

function setBusy(nextBusy, label) {
  busy = nextBusy;
  scanButton.classList.toggle("is-busy", nextBusy);
  scanButton.disabled = nextBusy || !selectedFile;
  demoButton.disabled = nextBusy || repairBusy;
  if (repairButton) repairButton.disabled = nextBusy || repairBusy || checkedPaths.size === 0;
  if (nextBusy) {
    const text = el("span", "button-label", label || "扫描中");
    const spinner = el("span", "spinner");
    spinner.setAttribute("aria-hidden", "true");
    scanButton.replaceChildren(text, spinner);
    scanButton.classList.add("is-busy");
  } else {
    const text = el("span", "button-label", "开始扫描");
    const spinner = el("span", "spinner");
    spinner.setAttribute("aria-hidden", "true");
    scanButton.replaceChildren(text, spinner);
    scanButton.classList.remove("is-busy");
  }
}

function chooseFile(file) {
  if (busy || repairBusy) return;
  selectedFile = file || null;
  setError(null);
  results.hidden = true;
  checkedPaths.clear();
  currentScan = null;
  if (repairPanel) repairPanel.hidden = true;

  if (!selectedFile) {
    input.value = "";
    dropZone.classList.remove("is-selected");
    filePill.hidden = true;
    dropTitle.textContent = "拖拽 tar 到这里，或点击选择文件";
    dropHint.textContent = "单镜像 docker save tar · 内容仅在内存中解析";
    scanButton.disabled = true;
    return;
  }

  dropZone.classList.add("is-selected");
  dropTitle.textContent = "已选择镜像归档";
  dropHint.textContent = "点击可重新选择；扫描过程不会解包到宿主文件系统";
  filePill.hidden = false;
  filePill.replaceChildren(
    el("strong", null, selectedFile.name),
    document.createTextNode(` · ${formatBytes(selectedFile.size)}`)
  );
  scanButton.disabled = false;
}

async function parseResponse(response) {
  let payload = null;
  try {
    payload = await response.json();
  } catch (_error) {
    payload = null;
  }
  if (!response.ok) {
    throw describeHttpDetail(payload);
  }
  if (!payload) {
    throw { code: "invalid_response", message: "服务没有返回有效 JSON。" };
  }
  return payload;
}

function makeLayerChip(layer) {
  const chip = el("li", "layer-chip");
  const heading = el("strong");
  heading.append(el("span", "layer-badge", `L${layer.number}`));
  heading.append(document.createTextNode(layer.number === 1 ? "基础层" : `第 ${layer.number} 层`));
  chip.append(heading);
  chip.append(el("span", "layer-name", layer.name || layer.path));
  chip.append(
    el("span", "layer-order", `manifest index ${layer.manifest_index} · 第 ${layer.manifest_index + 1} 项`)
  );
  chip.title = layer.path;
  return chip;
}

function makeBadge(bit) {
  const isSuid = bit === "SUID";
  return el("span", `badge ${isSuid ? "badge-suid" : "badge-sgid"}`, bit);
}

function makeFindingRow(item) {
  const tr = el("tr");

  const checkCell = el("td", "check-cell");
  const checkbox = document.createElement("input");
  checkbox.type = "checkbox";
  checkbox.className = "row-check";
  checkbox.value = item.relative_path;
  checkbox.setAttribute("aria-label", `选择 ${item.path}`);
  checkbox.checked = checkedPaths.has(item.relative_path);
  checkbox.addEventListener("change", () => {
    if (checkbox.checked) checkedPaths.add(item.relative_path);
    else checkedPaths.delete(item.relative_path);
    syncRepairSelection();
  });
  checkCell.append(checkbox);
  tr.append(checkCell);

  const pathCell = el("td", "path-cell");
  pathCell.append(el("span", "path-text", item.path));
  tr.append(pathCell);

  const modeCell = el("td");
  modeCell.append(el("code", "mode-code", item.mode_octal));
  tr.append(modeCell);

  const bitsCell = el("td");
  const bits = el("div", "badge-list");
  for (const bit of item.special_bits || []) bits.append(makeBadge(bit));
  bitsCell.append(bits);
  tr.append(bitsCell);

  const idCell = el("td", "id-cell");
  const uid = el("strong", null, String(item.uid));
  const gid = el("strong", null, String(item.gid));
  idCell.append(uid, document.createTextNode(" : "), gid);
  tr.append(idCell);

  const layerCell = el("td", "layer-cell");
  const lastLayer = item.last_layer || {
    number: item.layer_number,
    manifest_index: item.layer_manifest_index,
    path: item.layer_path,
    name: item.layer_name,
  };
  const main = el("div", "layer-main");
  main.append(el("span", "layer-badge", `L${lastLayer.number}`));
  main.append(document.createTextNode(`Layer ${lastLayer.number}`));
  layerCell.append(main);
  layerCell.append(el("span", "layer-detail", lastLayer.name || lastLayer.path));
  layerCell.title = `${lastLayer.path || ""} · manifest index ${lastLayer.manifest_index}`;
  tr.append(layerCell);

  return tr;
}

function renderResult(payload) {
  currentScan = payload;
  const files = payload.files || [];
  const summary = payload.summary || {};
  const layers = payload.layers || [];
  const tags = (payload.image && payload.image.tags) || [];

  metricLayers.textContent = String(summary.layers_scanned ?? layers.length);
  metricFiles.textContent = String(summary.privileged_files ?? files.length);
  metricSuid.textContent = String(summary.suid_files ?? 0);
  metricSgid.textContent = String(summary.sgid_files ?? 0);

  const tagText = tags.length ? tags.join(", ") : "未命名镜像";
  resultSubtitle.textContent = `${tagText} · ${payload.source === "built-in-demo" ? "内置多层示例" : "上传归档"}`;

  safetyNote.hidden = true;
  safetyNote.textContent = "";

  layerStrip.replaceChildren();
  for (const layer of layers) layerStrip.append(makeLayerChip(layer));

  // Drop stale selections that no longer exist in this scan.
  const currentPaths = new Set(files.map((item) => item.relative_path));
  for (const path of Array.from(checkedPaths)) {
    if (!currentPaths.has(path)) checkedPaths.delete(path);
  }

  findingsBody.replaceChildren();
  for (const item of files) findingsBody.append(makeFindingRow(item));

  const hasFiles = files.length > 0;
  tableWrap.hidden = !hasFiles;
  emptyState.hidden = hasFiles;
  repairPanel.hidden = !hasFiles;
  resetRepairResult();
  syncRepairSelection();

  results.hidden = false;
  results.scrollIntoView({ behavior: "smooth", block: "start" });
}

function setRepairStatus(message) {
  if (!message) {
    repairStatus.hidden = true;
    repairStatus.textContent = "";
    return;
  }
  repairStatus.hidden = false;
  repairStatus.textContent = message;
}

function setRepairError(error) {
  repairError.hidden = true;
  if (!error) return;
  repairErrorCode.textContent = error.code || "修复失败";
  repairErrorMessage.textContent = error.message || "无法完成修复。";
  const metaParts = [];
  if (error.path) metaParts.push(`路径 ${error.path}`);
  if (error.layer_number !== undefined && error.layer_number !== null) {
    metaParts.push(`层 ${error.layer_number}`);
  }
  if (error.layer_path) metaParts.push(error.layer_path);
  if (metaParts.length) {
    repairErrorMeta.hidden = false;
    repairErrorMeta.textContent = metaParts.join(" · ");
  } else {
    repairErrorMeta.hidden = true;
    repairErrorMeta.textContent = "";
  }
  repairError.hidden = false;
  repairError.scrollIntoView({ behavior: "smooth", block: "nearest" });
}

function syncRepairSelection() {
  const files = (currentScan && currentScan.files) || [];
  const total = files.length;
  const selected = files.filter((item) => checkedPaths.has(item.relative_path)).length;

  repairSelectedCount.textContent = String(selected);
  repairTotalCount.textContent = String(total);
  selectAll.disabled = total === 0;
  selectAll.checked = total > 0 && selected === total;
  selectAll.indeterminate = selected > 0 && selected < total;
  repairButton.disabled = repairBusy || selected === 0;
}

function resetRepairResult() {
  repairResult.hidden = true;
  repairDownload.removeAttribute("href");
  repairDiff.replaceChildren();
  setRepairError(null);
  setRepairStatus("");
}

selectAll.addEventListener("change", () => {
  const files = (currentScan && currentScan.files) || [];
  checkedPaths.clear();
  if (selectAll.checked) {
    for (const item of files) checkedPaths.add(item.relative_path);
  }
  for (const box of findingsBody.querySelectorAll(".row-check")) {
    box.checked = selectAll.checked;
  }
  syncRepairSelection();
});

function setRepairBusy(nextBusy, label) {
  repairBusy = nextBusy;
  repairButton.classList.toggle("is-busy", nextBusy);
  repairButton.disabled = nextBusy || checkedPaths.size === 0;
  demoButton.disabled = busy || nextBusy;
  selectAll.disabled = nextBusy;
  for (const box of findingsBody.querySelectorAll(".row-check")) box.disabled = nextBusy;
  if (nextBusy) {
    repairButton.replaceChildren(
      el("span", "button-label", label || "生成中"),
      (() => {
        const spinner = el("span", "spinner");
        spinner.setAttribute("aria-hidden", "true");
        return spinner;
      })()
    );
  } else {
    repairButton.replaceChildren(
      el("span", "button-label", "生成降权镜像"),
      (() => {
        const spinner = el("span", "spinner");
        spinner.setAttribute("aria-hidden", "true");
        return spinner;
      })()
    );
  }
}

function renderRepairDiff(job) {
  const report = (job && job.report) || {};
  const items = report.selected_files || [];
  repairDiff.replaceChildren();
  if (!items.length) return;

  const heading = el("h4", null, "补丁层变更明细");
  repairDiff.append(heading);
  const list = el("ul", "repair-diff-list");
  for (const item of items) {
    const li = el("li");
    li.append(el("code", "repair-path", item.path));
    const change = el(
      "span",
      "repair-mode-change",
      `${item.old_mode_octal} → ${item.new_mode_octal}`
    );
    li.append(change);
    li.append(
      el(
        "span",
        "repair-meta",
        `UID/GID ${item.uid}:${item.gid} · 正文 ${item.body_digest.slice(0, 19)}…`
      )
    );
    list.append(li);
  }
  repairDiff.append(list);
}

async function runRepair() {
  if (repairBusy || !currentScan) return;
  const paths = Array.from(checkedPaths).sort();
  if (!paths.length) {
    setRepairError({ code: "selection_empty", message: "请至少勾选一个高权限文件。" });
    return;

  }
  const isDemo = currentScan.source === "built-in-demo";
  if (!isDemo && !selectedFile) {
    setRepairError({
      code: "file_missing",
      message: "请重新选择原始归档后再发起修复（修复请求需要携带原 tar）。",
    });
    return;
  }

  setRepairError(null);
  resetRepairResult();
  setRepairBusy(true, "重新合并核对并生成归档");
  setRepairStatus("服务端正在重新合并 whiteout、核对所选路径，并分块复制正文生成补丁层…");

  try {
    const formData = new FormData();
    if (isDemo) {
      formData.append("paths_json", JSON.stringify(paths));
    } else {
      formData.append("archive", selectedFile, selectedFile.name);
      for (const path of paths) formData.append("paths", path);
    }
    const endpoint = isDemo ? "/api/demo/repair" : "/api/repair";
    const response = await fetch(endpoint, {
      method: "POST",
      body: formData,
      headers: { Accept: "application/json" },
    });
    const payload = await parseResponse(response);
    const job = payload.job;
    repairDownload.href = job.download_url;
    repairDownload.setAttribute("download", job.download_name);
    repairResultDetail.textContent =
      `补丁层 ${job.report.patch_layer.path} · 输出 ${formatBytes(job.report.output_size)} · 任务 ${job.job_id.slice(0, 8)}`;
    renderRepairDiff(job);
    repairResult.hidden = false;
    setRepairStatus("");
    repairResult.scrollIntoView({ behavior: "smooth", block: "nearest" });
  } catch (error) {
    setRepairStatus("");
    if (error && typeof error === "object" && "message" in error) {
      setRepairError(error);
    } else {
      setRepairError({ code: "network_error", message: "网络请求失败，请确认服务正在运行。" });
    }
  } finally {
    setRepairBusy(false);
    syncRepairSelection();
  }
}

repairButton.addEventListener("click", runRepair);

repairRescan.addEventListener("click", async () => {
  const href = repairDownload.getAttribute("href");
  if (!href || repairBusy) return;
  const jobId = href.split("/").slice(-2, -1)[0];
  setRepairError(null);
  setRepairStatus("正在扫描刚生成的降权镜像…");
  try {
    const response = await fetch(`/api/repair/jobs/${encodeURIComponent(jobId)}/scan`, {
      method: "POST",
      headers: { Accept: "application/json" },
    });
    const payload = await parseResponse(response);
    setRepairStatus("");
    renderResult(payload);
  } catch (error) {
    setRepairStatus("");
    setRepairError(error && error.message ? error : {
      code: "network_error",
      message: "扫描修复结果失败。",
    });
  }
});

async function runScan({ file, demo }) {
  if (busy) return;
  setError(null);
  setBusy(true, demo ? "构建并扫描示例" : "扫描并合并层");
  setStatus(demo ? "正在内存中构建四层示例归档并合并…" : "正在读取 tar 头并合并 whiteout 规则…");

  try {
    let response;
    if (demo) {
      response = await fetch("/api/demo", { method: "GET", headers: { Accept: "application/json" } });
    } else {
      const formData = new FormData();
      formData.append("archive", file, file.name);
      response = await fetch("/api/scan", { method: "POST", body: formData, headers: { Accept: "application/json" } });
    }
    const payload = await parseResponse(response);
    renderResult(payload);
    setStatus("");
  } catch (error) {
    setStatus("");
    if (error && typeof error === "object" && "message" in error) {
      setError(error);
    } else {
      setError({ code: "network_error", message: "网络请求失败，请确认服务正在运行。" });
    }
  } finally {
    setBusy(false);
  }
}

form.addEventListener("submit", (event) => {
  event.preventDefault();
  if (!selectedFile) {
    setError({ code: "file_missing", message: "请先选择一个 docker save 导出的 tar 文件。" });
    return;
  }
  runScan({ file: selectedFile, demo: false });
});

demoButton.addEventListener("click", () => runScan({ file: null, demo: true }));

input.addEventListener("change", () => {
  chooseFile(input.files && input.files[0]);
});

for (const eventName of ["dragenter", "dragover"]) {
  dropZone.addEventListener(eventName, (event) => {
    event.preventDefault();
    event.stopPropagation();
    if (!busy) dropZone.classList.add("is-dragging");
  });
}

for (const eventName of ["dragleave", "drop"]) {
  dropZone.addEventListener(eventName, (event) => {
    event.preventDefault();
    event.stopPropagation();
    dropZone.classList.remove("is-dragging");
  });
}

dropZone.addEventListener("drop", (event) => {
  const dropped = event.dataTransfer && event.dataTransfer.files;
  if (dropped && dropped.length) chooseFile(dropped[0]);
});

window.addEventListener("dragover", (event) => event.preventDefault());
window.addEventListener("drop", (event) => event.preventDefault());

chooseFile(null);
