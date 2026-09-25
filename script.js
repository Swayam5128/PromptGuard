const input = document.getElementById("promptInput");
const charCount = document.getElementById("charCount");
const scanBtn = document.getElementById("scanBtn");
const clearBtn = document.getElementById("clearBtn");
const sampleBtn = document.getElementById("sampleBtn");
const redactBtn = document.getElementById("redactBtn");
const findingCount = document.getElementById("findingCount");
const summaryText = document.getElementById("summaryText");
const findingList = document.getElementById("findingList");
const riskBadge = document.getElementById("riskBadge");
const riskFill = document.getElementById("riskFill");
const outputBox = document.getElementById("outputBox");

let lastScan = null;

function updateCount() {
  charCount.textContent = `${input.value.length} characters`;
}

function escapeRegExp(text) {
  return text.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

function addFinding(findings, type, label, value, score, placeholder) {
  findings.push({ type, label, value, score, placeholder });
}

function detect(text) {
  const findings = [];

  // Email
  const emailRe = /\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b/gi;
  for (const m of text.matchAll(emailRe)) {
    addFinding(findings, "PII", "Email", m[0], 25, "[EMAIL]");
  }

  // Phone numbers (India-oriented + general 10-digit patterns)
  const phoneRe = /(?<!\d)(?:\+?91[\s-]?)?[6-9]\d{9}(?!\d)/g;
  for (const m of text.matchAll(phoneRe)) {
    const cleaned = m[0].replace(/\s|-/g, "");
    if (cleaned.length >= 10) {
      addFinding(findings, "PII", "Phone Number", m[0], 25, "[PHONE]");
    }
  }

  // Credit/debit card-like numbers with optional spaces/dashes.
  const cardRe = /(?<!\d)(?:\d[ -]?){13,19}(?!\d)/g;
  for (const m of text.matchAll(cardRe)) {
    const digits = m[0].replace(/\D/g, "");
    if (digits.length >= 13 && digits.length <= 19) {
      addFinding(findings, "Financial", "Card Number", m[0], 35, "[CARD_NUMBER]");
    }
  }

  // Credential / secret patterns.
  const credentialPatterns = [
    { re: /\b(?:api[_ -]?key|secret[_ -]?key|password|passwd|token)\s*[:=]\s*["']?([^\s"',;]+)/gi, label: "Credential", score: 45 },
    { re: /\bAKIA[0-9A-Z]{16}\b/g, label: "Cloud Access Key", score: 45 }
  ];
  for (const p of credentialPatterns) {
    for (const m of text.matchAll(p.re)) {
      addFinding(findings, "Credential", p.label, m[0], p.score, "[REDACTED_SECRET]");
    }
  }

  // Simple name heuristic for demo purposes:
  // catches "my name is <two words>" without claiming full NER coverage.
  const nameRe = /\bmy\s+name\s+is\s+([A-Z][a-z]+(?:\s+[A-Z][a-z]+){0,2})/gi;
  for (const m of text.matchAll(nameRe)) {
    const value = m[1];
    addFinding(findings, "PII", "Name", value, 15, "[PERSON]");
  }

  // Government-ID-like patterns: require an explicit label so a
  // 16-digit card number is not misclassified as a 12-digit ID.
  const aadhaarLabelRe = /\b(?:aadhaar|aadhar|government\s*id|govt\s*id|id\s*number)\s*[:#-]?\s*(\d{4}[\s-]\d{4}[\s-]\d{4})\b/gi;
  for (const m of text.matchAll(aadhaarLabelRe)) {
    addFinding(findings, "PII", "Government ID", m[1], 35, "[GOV_ID]");
  }

  // Deduplicate overlapping findings. If the same sensitive value is
  // detected by multiple credential rules, keep only one finding.
  const unique = [];
  const seen = new Set();
  for (const f of findings) {
    const normalizedValue = f.value.replace(/\s+/g, " ").trim().toLowerCase();
    const key = f.type === "Credential"
      ? `credential|${normalizedValue}`
      : `${f.type}|${f.label}|${normalizedValue}`;
    if (!seen.has(key)) {
      seen.add(key);
      unique.push(f);
    }
  }
  // Final overlap cleanup for credential rules:
  // "API key: sk-..." can be reported both as a Credential and as an API Key.
  // Keep the labeled Credential finding and remove the duplicate API Key finding.
  const credentialValues = new Set(
    unique
      .filter(f => f.type === "Credential")
      .map(f => {
        const m = f.value.match(/\b(?:api[_ -]?key|secret[_ -]?key|password|passwd|token)\s*[:=]\s*["']?([^\s"',;]+)/i);
        return m ? m[1].toLowerCase() : f.value.toLowerCase();
      })
  );

  const cleaned = unique.filter(f => {
    if (f.label !== "API Key") return true;
    return !credentialValues.has(f.value.toLowerCase());
  });

  return cleaned;
}

function getRisk(findings) {
  const score = Math.min(100, findings.reduce((sum, f) => sum + f.score, 0));
  if (score >= 60) return { label: "HIGH", level: "high", score };
  if (score >= 30) return { label: "MEDIUM", level: "medium", score };
  if (score > 0) return { label: "LOW", level: "low", score };
  return { label: "LOW", level: "low", score: 0 };
}

function renderFindings(findings) {
  findingCount.textContent = findings.length;
  findingList.innerHTML = "";

  if (!findings.length) {
    findingList.innerHTML = `<div class="empty-state">No sensitive pattern detected in this scan.</div>`;
    return;
  }

  for (const f of findings) {
    const chip = document.createElement("div");
    chip.className = "finding-chip";
    chip.textContent = `${f.label}: ${f.value.length > 28 ? f.value.slice(0, 25) + "..." : f.value}`;
    findingList.appendChild(chip);
  }
}

function scan() {
  const text = input.value.trim();

  if (!text) {
    lastScan = null;
    riskBadge.textContent = "Not scanned";
    riskBadge.className = "risk-badge neutral";
    riskFill.style.width = "0%";
    findingCount.textContent = "0";
    summaryText.textContent = "Enter a prompt and run a scan.";
    findingList.innerHTML = `<div class="empty-state">No scan results yet.</div>`;
    redactBtn.disabled = true;
    outputBox.className = "output-box empty";
    outputBox.textContent = "Scan a prompt first. Redacted text will appear here.";
    return;
  }

  const findings = detect(text);
  const risk = getRisk(findings);

  lastScan = { text, findings, risk };
  riskBadge.textContent = risk.label;
  riskBadge.className = `risk-badge ${risk.level}`;
  riskFill.style.width = `${Math.max(risk.score, findings.length ? 8 : 0)}%`;
  summaryText.textContent = findings.length
    ? `${risk.label} risk based on the detected categories.`
    : "No common sensitive-data patterns detected.";
  renderFindings(findings);
  redactBtn.disabled = findings.length === 0;

  if (!findings.length) {
    outputBox.className = "output-box";
    outputBox.textContent = text;
  } else {
    outputBox.className = "output-box empty";
    outputBox.textContent = "Click “Redact sensitive data” to generate a safe-to-send version.";
  }
}

function redact() {
  if (!lastScan || !lastScan.findings.length) return;

  let safeText = lastScan.text;
  const sorted = [...lastScan.findings].sort((a, b) => b.value.length - a.value.length);

  for (const f of sorted) {
    const escaped = escapeRegExp(f.value);
    safeText = safeText.replace(new RegExp(escaped, "g"), f.placeholder);
  }

  outputBox.className = "output-box";
  outputBox.textContent = safeText;
}

sampleBtn.addEventListener("click", () => {
  input.value = `My name is Rahul Patel.
Please summarize this customer issue.

Email: rahul.patel@gmail.com
Phone: 9876543210
API key: sk-example1234567890
Card: 4111 1111 1111 1111`;
  updateCount();
  scan();
});

scanBtn.addEventListener("click", scan);
redactBtn.addEventListener("click", redact);

clearBtn.addEventListener("click", () => {
  input.value = "";
  updateCount();
  scan();
});

input.addEventListener("input", updateCount);
input.addEventListener("input", () => {
  // Keep the demo feeling real-time without overwhelming the UI.
  clearTimeout(window.__scanTimer);
  window.__scanTimer = setTimeout(scan, 250);
});

updateCount();
