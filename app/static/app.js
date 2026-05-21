async function parseCert() {
  const pem = document.getElementById("pem-input").value.trim();
  const errorMsg = document.getElementById("error-msg");
  errorMsg.classList.add("hidden");

  if (!pem) {
    showError("Please paste a PEM-encoded certificate");
    return;
  }

  const btn = document.getElementById("parse-btn");
  btn.disabled = true;
  btn.textContent = "Parsing...";

  try {
    const res = await fetch("/api/parse", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ pem }),
    });

    if (!res.ok) {
      const err = await res.json();
      throw new Error(err.detail || "Failed to parse certificate");
    }

    const data = await res.json();
    renderResult(data);
  } catch (e) {
    showError(e.message);
  } finally {
    btn.disabled = false;
    btn.textContent = "Parse Certificate";
  }
}

function showError(msg) {
  const el = document.getElementById("error-msg");
  el.textContent = msg;
  el.classList.remove("hidden");
}

function renderResult(data) {
  document.getElementById("input-section").classList.add("hidden");
  const resultSection = document.getElementById("result-section");
  resultSection.classList.remove("hidden");

  const badge = document.getElementById("status-badge");
  if (data.is_expired) {
    badge.textContent = "Expired";
    badge.className = "badge-expired px-3 py-1 rounded-full text-xs font-medium";
  } else if (data.days_remaining < 30) {
    badge.textContent = `Expires in ${data.days_remaining} days`;
    badge.className = "badge-warning px-3 py-1 rounded-full text-xs font-medium";
  } else {
    badge.textContent = `Valid (${data.days_remaining} days)`;
    badge.className = "badge-ok px-3 py-1 rounded-full text-xs font-medium";
  }

  const rows = [
    ["Common Name", data.subject.commonName || "N/A"],
    ["Organization", data.subject.organizationName || "N/A"],
    ["Issuer", data.issuer.commonName || data.issuer.organizationName || "N/A"],
    ["Issuer Org", data.issuer.organizationName || "N/A"],
    ["Serial Number", data.serial_number],
    ["Valid From", formatDate(data.not_before)],
    ["Valid Until", formatDate(data.not_after)],
    ["Signature Algorithm", data.signature_algorithm],
    ["Public Key", formatKey(data.public_key)],
    ["Version", data.version],
    ["Self-Signed", data.is_self_signed ? "Yes" : "No"],
    ["SHA-256 Fingerprint", data.fingerprints.sha256],
    ["SHA-1 Fingerprint", data.fingerprints.sha1],
  ];

  const details = document.getElementById("cert-details");
  details.innerHTML = rows.map(([label, value]) =>
    `<div class="info-row flex justify-between py-2.5">
      <span class="text-xs text-slate-500">${label}</span>
      <span class="text-xs text-slate-300 font-mono text-right max-w-[60%] break-all">${value}</span>
    </div>`
  ).join("");

  const sanExt = data.extensions.find(e => e.san);
  if (sanExt && sanExt.san.length > 0) {
    const sanSection = document.getElementById("san-section");
    sanSection.classList.remove("hidden");
    document.getElementById("san-list").innerHTML = sanExt.san.map(name =>
      `<div class="text-xs font-mono text-slate-300 py-1">${name}</div>`
    ).join("");
  }

  const extList = document.getElementById("extensions-list");
  extList.innerHTML = data.extensions.map(ext =>
    `<div class="flex justify-between py-1.5">
      <span class="text-xs text-slate-400">${ext.name}</span>
      <span class="text-xs ${ext.critical ? 'text-yellow-400' : 'text-slate-600'}">${ext.critical ? 'Critical' : 'Non-critical'}</span>
    </div>`
  ).join("");
}

function formatDate(iso) {
  return new Date(iso).toLocaleDateString("en-US", {
    year: "numeric", month: "short", day: "numeric", hour: "2-digit", minute: "2-digit"
  });
}

function formatKey(key) {
  if (key.bits) return `${key.type} ${key.bits}-bit${key.curve ? ' (' + key.curve + ')' : ''}`;
  return key.type;
}

function reset() {
  document.getElementById("input-section").classList.remove("hidden");
  document.getElementById("result-section").classList.add("hidden");
  document.getElementById("san-section").classList.add("hidden");
  document.getElementById("pem-input").value = "";
  document.getElementById("error-msg").classList.add("hidden");
}
