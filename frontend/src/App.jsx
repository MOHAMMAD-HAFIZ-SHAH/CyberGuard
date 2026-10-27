import { useRef, useState } from "react";
import "./App.css";

const API_BASE_URL = "http://127.0.0.1:8000/api";
const MAX_IMAGE_SIZE = 500 * 1024 * 1024;
const ALLOWED_EXTENSIONS = [".dd", ".img", ".raw", ".e01"];

function displayValue(value, fallback = "Not available") {
  if (value === null || value === undefined || value === "") {
    return fallback;
  }

  if (
    typeof value === "string" ||
    typeof value === "number" ||
    typeof value === "boolean"
  ) {
    return String(value);
  }

  return JSON.stringify(value, null, 2);
}

function formatArtifactSource(source, index) {
  if (typeof source === "string" && source.trim()) {
    return source;
  }

  if (source && typeof source === "object") {
    const parts = [
      source.image_name,
      source.path,
      source.metadata_address != null
        ? `Metadata address: ${source.metadata_address}`
        : null,
    ].filter(
      (part) =>
        part !== null &&
        part !== undefined &&
        typeof part !== "object" &&
        String(part).trim() !== ""
    );

    return parts.length
      ? parts.join(" · ")
      : JSON.stringify(source);
  }

  return `Artifact ${index + 1}`;
}

function SeverityBadge({ severity }) {
  const level =
    typeof severity === "string"
      ? severity.toLowerCase()
      : "unknown";

  return (
    <span className={`severity severity-${level}`}>
      {level}
    </span>
  );
}

function EvidenceCard({ item }) {
  return (
    <article className="evidence-card">
      <div className="evidence-top">
        <span className="evidence-id">
          {displayValue(item.evidence_id, "Evidence")}
        </span>
        <SeverityBadge severity={item.severity} />
      </div>

      <h4>
        {displayValue(item.event_type, "Unknown event").replaceAll(
          "_",
          " "
        )}
      </h4>

      <p>
        {displayValue(item.description, "No description provided.")}
      </p>

      <div className="evidence-meta">
        <span>
          ◷ {displayValue(item.timestamp, "Time unavailable")}
        </span>
        <span>
          Source: {displayValue(item.source, "Unknown")}
        </span>
      </div>
    </article>
  );
}

function Timeline({ events }) {
  if (!Array.isArray(events) || events.length === 0) {
    return (
      <p className="empty-state">
        No timeline events available.
      </p>
    );
  }

  return (
    <div className="timeline">
      {events.map((event, index) => (
        <div
          className="timeline-item"
          key={event.evidence_id || index}
        >
          <div className="timeline-marker" />

          <div className="timeline-content">
            <span className="timeline-time">
              {displayValue(event.timestamp, "Time unavailable")}
            </span>

            <h4>
              {displayValue(event.event_type, "Event").replaceAll(
                "_",
                " "
              )}
            </h4>

            <p>
              {displayValue(event.description, "No description")}
            </p>

            <SeverityBadge severity={event.severity} />
          </div>
        </div>
      ))}
    </div>
  );
}

function HypothesisCard({ hypothesis }) {
  const confidence = Number(hypothesis.confidence);

  const percent = Number.isFinite(confidence)
    ? Math.max(
        0,
        Math.min(
          100,
          Math.round(
            confidence <= 1
              ? confidence * 100
              : confidence
          )
        )
      )
    : null;

  return (
    <article className="hypothesis-card">
      <div className="hypothesis-heading">
        <span className="evidence-id">
          {displayValue(
            hypothesis.hypothesis_id,
            "Hypothesis"
          )}
        </span>

        <span className="review-label">
          Human review required
        </span>
      </div>

      <p>
        {displayValue(
          hypothesis.description,
          "No hypothesis description provided."
        )}
      </p>

      {percent !== null && (
        <div className="confidence-section">
          <div className="confidence-label">
            <span>Heuristic score</span>
            <strong>{percent}%</strong>
          </div>

          <div
            className="confidence-track"
            role="progressbar"
            aria-label="Heuristic score"
            aria-valuenow={percent}
            aria-valuemin={0}
            aria-valuemax={100}
          >
            <div
              className="confidence-fill"
              style={{ width: `${percent}%` }}
            />
          </div>
        </div>
      )}

      <div className="hypothesis-evidence">
        <strong>Supporting evidence:</strong>{" "}
        {Array.isArray(hypothesis.supporting_evidence) &&
        hypothesis.supporting_evidence.length
          ? hypothesis.supporting_evidence
              .map((item) => displayValue(item))
              .join(", ")
          : "None listed"}
      </div>

      <div className="hypothesis-evidence">
        <strong>Contradicting evidence:</strong>{" "}
        {Array.isArray(hypothesis.contradicting_evidence) &&
        hypothesis.contradicting_evidence.length
          ? hypothesis.contradicting_evidence
              .map((item) => displayValue(item))
              .join(", ")
          : "None listed"}
      </div>
    </article>
  );
}

function CrewAIReview({ review }) {
  if (!review || typeof review !== "object") {
    return (
      <p className="empty-state">
        No CrewAI investigation review was returned by the backend.
      </p>
    );
  }

  const status = String(review.status || "unknown").toLowerCase();
  const analysis = review.analysis || review.review || "";
  const warnings = Array.isArray(review.validation_warnings)
    ? review.validation_warnings
    : [];
  const missingSections = Array.isArray(review.missing_sections)
    ? review.missing_sections
    : [];

  return (
    <div className="crewai-review">
      <div className="review-status-row">
        <span className={`severity severity-${status}`}>
          {status.replaceAll("_", " ")}
        </span>
        <span className="muted">
          Evidence reviewed: {displayValue(review.evidence_reviewed, "Unknown")}
        </span>
        <span className="muted">
          Runtime: {Number.isFinite(Number(review.duration_seconds))
            ? `${Number(review.duration_seconds).toFixed(2)} s`
            : "Not available"}
        </span>
      </div>

      {review.warning && (
        <p className="warning-message" role="status">{review.warning}</p>
      )}

      {missingSections.length > 0 && (
        <p className="warning-message">
          Missing sections: {missingSections.join(", ")}
        </p>
      )}

      {warnings.length > 0 && (
        <ul className="review-warnings">
          {warnings.map((warning, index) => (
            <li key={index}>{displayValue(warning)}</li>
          ))}
        </ul>
      )}

      {analysis ? (
        <pre className="crewai-analysis">{analysis}</pre>
      ) : (
        <p className="empty-state">CrewAI did not return analysis text.</p>
      )}

      <p className="muted">
        AI-generated interpretations are not verified forensic facts. Validate
        conclusions against original evidence.
      </p>
    </div>
  );
}

function MonitoringPanel({ monitoring }) {
  if (!monitoring || typeof monitoring !== "object") {
    return <p className="empty-state">No monitoring metrics were returned.</p>;
  }

  const stages = Array.isArray(monitoring.stages) ? monitoring.stages : [];
  return (
    <div className="monitoring-panel">
      <div className="stats-grid monitoring-stats">
        <article className="stat-card">
          <span>Total runtime</span>
          <strong>{Number.isFinite(Number(monitoring.total_runtime_seconds))
            ? `${Number(monitoring.total_runtime_seconds).toFixed(2)} s`
            : "N/A"}</strong>
        </article>
        <article className="stat-card">
          <span>Stages</span>
          <strong>{displayValue(monitoring.stage_count, stages.length)}</strong>
        </article>
        <article className="stat-card">
          <span>Incomplete stages</span>
          <strong>{displayValue(monitoring.incomplete_stage_count, 0)}</strong>
        </article>
        <article className="stat-card">
          <span>Failed stages</span>
          <strong>{displayValue(monitoring.failed_stage_count, 0)}</strong>
        </article>
      </div>

      <p className="muted">
        Model: {displayValue(monitoring.model)} · Base URL: {displayValue(monitoring.base_url)}
      </p>
      {monitoring.cost_estimate == null && (
        <p className="muted">Cost estimate: unavailable/not configured for this local run.</p>
      )}
      {stages.length > 0 && (
        <div className="table-scroll">
          <table className="monitoring-table">
            <thead>
              <tr><th>Stage</th><th>Status</th><th>Duration</th></tr>
            </thead>
            <tbody>
              {stages.map((stage, index) => (
                <tr key={stage.name || stage.stage || index}>
                  <td>{displayValue(stage.name || stage.stage, `Stage ${index + 1}`)}</td>
                  <td>{displayValue(stage.status, "unknown")}</td>
                  <td>{Number.isFinite(Number(stage.duration_seconds))
                    ? `${Number(stage.duration_seconds).toFixed(2)} s`
                    : "N/A"}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}

function App() {
  const [title, setTitle] = useState("");
  const [description, setDescription] = useState("");
  const [logText, setLogText] = useState("");

  const [imagePath, setImagePath] = useState("");
  const [imageFile, setImageFile] = useState(null);
  const [isDragging, setIsDragging] = useState(false);
  const [uploadProgress, setUploadProgress] = useState("");

  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");

  const [evidenceSearch, setEvidenceSearch] = useState("");
  const [severityFilter, setSeverityFilter] = useState("all");

  const fileInputRef = useRef(null);

  function validateImageFile(file) {
    if (!file) {
      return "Please select a file.";
    }

    const dotIndex = file.name.lastIndexOf(".");
    const extension =
      dotIndex >= 0
        ? file.name.slice(dotIndex).toLowerCase()
        : "";

    if (!ALLOWED_EXTENSIONS.includes(extension)) {
      return (
        "Unsupported file type. Choose a .dd, .img, .raw, " +
        "or .e01 image."
      );
    }

    if (file.size === 0) {
      return "The selected file is empty.";
    }

    if (file.size > MAX_IMAGE_SIZE) {
      return "The image exceeds the 500 MB upload limit.";
    }

    return "";
  }

  function handleFileSelection(file) {
    if (!file) return;

    const validationError = validateImageFile(file);

    if (validationError) {
      setError(validationError);
      setImageFile(null);
      return;
    }

    setError("");
    setImageFile(file);
    setImagePath("");
    setUploadProgress("");
  }

  function handleDrop(event) {
    event.preventDefault();
    setIsDragging(false);

    const file = event.dataTransfer.files?.[0];

    if (file) {
      handleFileSelection(file);
    }
  }

  async function uploadForensicImage(file) {
    const formData = new FormData();
    formData.append("file", file);

    setUploadProgress("Uploading forensic image...");

    const response = await fetch(
      `${API_BASE_URL}/forensics/upload`,
      {
        method: "POST",
        body: formData,
      }
    );

    const data = await response.json().catch(() => ({}));

    if (!response.ok) {
      throw new Error(
        typeof data.detail === "string"
          ? data.detail
          : "The forensic image upload failed."
      );
    }

    if (!data.image_path) {
      throw new Error(
        "The upload response did not include an image path."
      );
    }

    setImagePath(data.image_path);

    setUploadProgress(
      `Upload complete: ${data.filename || file.name} (${(
        (data.size_bytes || file.size) /
        (1024 * 1024)
      ).toFixed(2)} MB)`
    );

    return data.image_path;
  }

  async function handleInvestigation(event) {
    event.preventDefault();

    setLoading(true);
    setError("");
    setResult(null);
    setEvidenceSearch("");
    setSeverityFilter("all");
    setUploadProgress("");

    try {
      let selectedImagePath = imagePath.trim();

      if (imageFile) {
        selectedImagePath = await uploadForensicImage(imageFile);
      }

      setUploadProgress(
        selectedImagePath
          ? "Starting investigation with the selected forensic image..."
          : "Starting investigation..."
      );

      const payload = {
        title,
        description,
        log_text: logText,
      };

      if (selectedImagePath) {
        payload.image_path = selectedImagePath;
      }

      const response = await fetch(
        `${API_BASE_URL}/investigations`,
        {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
          },
          body: JSON.stringify(payload),
        }
      );

      const data = await response.json().catch(() => ({}));

      if (!response.ok) {
        throw new Error(
          typeof data.detail === "string"
            ? data.detail
            : JSON.stringify(data.detail) ||
                "Investigation failed. Check the submitted details."
        );
      }

      setResult(data);
      setUploadProgress("");
    } catch (err) {
      setError(
        err.message ||
          "Could not connect to CyberGuard. Check that the backend is running."
      );
      setUploadProgress("");
    } finally {
      setLoading(false);
    }
  }

  // Download a professionally formatted, standalone HTML report.
  function downloadProfessionalReport() {
    if (!result) return;

    // Escape dynamic content before inserting it into HTML.
    const escapeHtml = (value) =>
      String(value ?? "")
        .replaceAll("&", "&amp;")
        .replaceAll("<", "&lt;")
        .replaceAll(">", "&gt;")
        .replaceAll('"', "&quot;")
        .replaceAll("'", "&#39;");

    const safe = (value, fallback = "Not available") =>
      escapeHtml(displayValue(value, fallback));

    const reportDate = new Date().toLocaleString();

    const reportEvidence = Array.isArray(result.evidence)
      ? result.evidence
      : [];

    const reportTimeline = Array.isArray(result.timeline)
      ? result.timeline
      : [];

    const reportHypotheses = Array.isArray(result.hypotheses)
      ? result.hypotheses
      : [];

    const reportAnalyses = Array.isArray(
      result.forensic_artifact_analyses
    )
      ? result.forensic_artifact_analyses
      : [];

    const reportWarnings = Array.isArray(result.collection_errors)
      ? result.collection_errors
      : [];

    const reportPlan = Array.isArray(result.investigation_plan)
      ? result.investigation_plan
      : [];

    const section = (heading, content) => `
      <section class="report-section">
        <h2>${escapeHtml(heading)}</h2>
        ${content || "<p>None recorded.</p>"}
      </section>
    `;

    const evidenceHtml = reportEvidence.length
      ? reportEvidence
          .map(
            (item, index) => `
              <article class="item">
                <h3>${index + 1}. ${safe(
                  item.event_type,
                  "Evidence item"
                )}</h3>
                <p><b>Evidence ID:</b> ${safe(item.evidence_id)}</p>
                <p><b>Severity:</b> ${safe(
                  item.severity,
                  "Unclassified"
                )}</p>
                <p><b>Timestamp:</b> ${safe(item.timestamp)}</p>
                <p><b>Source:</b> ${safe(item.source)}</p>
                <p><b>Description:</b> ${safe(item.description)}</p>
              </article>
            `
          )
          .join("")
      : "<p>No evidence items were returned by the investigation.</p>";

    const timelineHtml = reportTimeline.length
      ? `<ol>${reportTimeline
          .map(
            (item) => `
              <li>
                <b>${safe(
                  item.timestamp,
                  "Time unavailable"
                )}</b> —
                ${safe(item.event_type, "Event")}:
                ${safe(item.description)}
              </li>
            `
          )
          .join("")}</ol>`
      : "<p>No timeline events were returned.</p>";

    const hypothesesHtml = reportHypotheses.length
      ? reportHypotheses
          .map((item, index) => {
            const rawConfidence = Number(item.confidence);
            const hasConfidence =
              item.confidence !== null &&
              item.confidence !== undefined &&
              Number.isFinite(rawConfidence);

            const confidence = hasConfidence
              ? Math.max(
                  0,
                  Math.min(
                    100,
                    Math.round(
                      rawConfidence <= 1
                        ? rawConfidence * 100
                        : rawConfidence
                    )
                  )
                )
              : null;

            return `
              <article class="item">
                <h3>Hypothesis ${index + 1}</h3>
                <p>${safe(item.description)}</p>
                <p><b>Heuristic score:</b> ${
                  confidence === null
                    ? "Not provided"
                    : `${confidence}%`
                }</p>
                <p><b>Supporting evidence:</b> ${safe(
                  item.supporting_evidence,
                  "None listed"
                )}</p>
                <p><b>Contradicting evidence:</b> ${safe(
                  item.contradicting_evidence,
                  "None listed"
                )}</p>
              </article>
            `;
          })
          .join("")
      : "<p>No hypotheses were generated from the available data.</p>";

    const analysesHtml = reportAnalyses.length
      ? reportAnalyses
          .map(
            (item, index) => `
              <article class="item">
                <h3>Artifact Analysis ${index + 1}</h3>
                <p><b>Source:</b> ${safe(item.source)}</p>
                <pre>${safe(item.ai_analysis ?? item)}</pre>
              </article>
            `
          )
          .join("")
      : "<p>No forensic artifact AI analyses were returned.</p>";

    const planHtml = reportPlan.length
      ? `<ol>${reportPlan
          .map((step) => `<li>${safe(step)}</li>`)
          .join("")}</ol>`
      : "<p>No investigation plan was returned.</p>";

    const warningsHtml = reportWarnings.length
      ? `<ul>${reportWarnings
          .map((warning) => `<li>${safe(warning)}</li>`)
          .join("")}</ul>`
      : "<p>No collection warnings were reported by the backend.</p>";

    const originalReport = safe(
      result.report,
      "No narrative report was returned."
    );

    const evidenceSummary = result.evidence_summary || {};
    const severityCounts = evidenceSummary.by_severity || {};

    const html = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>CyberGuard Forensic Report</title>
<style>
  * { box-sizing: border-box; }
  body {
    font-family: Arial, Helvetica, sans-serif;
    max-width: 900px;
    margin: 40px auto;
    padding: 0 28px;
    color: #202b3c;
    line-height: 1.65;
    background: #fff;
  }
  header {
    border-bottom: 4px solid #163a63;
    padding-bottom: 22px;
    margin-bottom: 28px;
  }
  .brand {
    color: #163a63;
    font-size: 13px;
    font-weight: bold;
    letter-spacing: 2px;
  }
  h1 { font-size: 30px; margin-bottom: 6px; }
  h2 {
    color: #163a63;
    border-bottom: 1px solid #ccd5df;
    padding-bottom: 8px;
    margin-top: 32px;
    font-size: 20px;
  }
  h3 { font-size: 16px; }
  .metadata {
    background: #f3f6fa;
    padding: 16px 20px;
    border-radius: 6px;
    overflow-wrap: anywhere;
  }
  .item {
    border: 1px solid #d9e0e8;
    padding: 14px 18px;
    margin: 14px 0;
    border-radius: 5px;
    break-inside: avoid;
    overflow-wrap: anywhere;
  }
  pre {
    white-space: pre-wrap;
    overflow-wrap: anywhere;
    background: #f5f7fa;
    padding: 14px;
    font: 12px/1.6 Consolas, monospace;
  }
  .disclaimer {
    background: #fff8e7;
    border-left: 4px solid #b78120;
    padding: 14px;
  }
  .badge {
    display: inline-block;
    padding: 3px 9px;
    background: #e7edf5;
    border-radius: 4px;
    font-size: 12px;
  }
  footer {
    margin-top: 40px;
    padding-top: 14px;
    border-top: 1px solid #ccd5df;
    color: #596579;
    font-size: 12px;
  }
  @media print {
    body { margin: 0; padding: 0; max-width: none; }
    .report-section { break-inside: auto; }
    .item { break-inside: avoid; }
    h2 { break-after: avoid; }
    header { break-after: avoid; }
  }
</style>
</head>
<body>
<header>
  <div class="brand">CYBERGUARD | DIGITAL FORENSICS</div>
  <h1>Incident Investigation Report</h1>
  <p>Evidence review and investigative findings</p>
  <span class="badge">Preliminary — Requires analyst review</span>
</header>

<div class="metadata">
  <p><b>Incident:</b> ${safe(result.title)}</p>
  <p><b>Case ID:</b> ${safe(result.incident_id)}</p>
  <p><b>Status:</b> ${safe(result.status)}</p>
  <p><b>Report generated:</b> ${escapeHtml(reportDate)}</p>
  <p><b>Evidence items:</b> ${reportEvidence.length}</p>
  <p><b>Hypotheses:</b> ${reportHypotheses.length}</p>
  <p><b>Critical findings:</b> ${safe(
    severityCounts.critical ?? 0
  )}</p>
  <p><b>High-severity findings:</b> ${safe(
    severityCounts.high ?? 0
  )}</p>
</div>

${section(
  "1. Executive Summary",
  `<p>This report documents the investigation results returned by CyberGuard for the incident <b>${safe(
    result.title
  )}</b>.</p>
   <p>The system returned ${reportEvidence.length} evidence item(s),
   ${reportTimeline.length} timeline event(s), and
   ${reportHypotheses.length} hypothesis/hypotheses.
   These counts describe the returned data and do not independently
   establish whether malicious activity occurred.</p>`
)}

${section(
  "2. Incident Description",
  `<p>${safe(description, "No incident description provided.")}</p>`
)}

${section("3. Investigation Plan", planHtml)}

${section("4. Evidence Findings", evidenceHtml)}

${section("5. Event Timeline", timelineHtml)}

${section("6. Investigative Hypotheses", hypothesesHtml)}

${section("7. Forensic Artifact Analysis", analysesHtml)}

${section(
  "8. CrewAI Investigation Review",
  `<p><b>Status:</b> ${safe(result.crewai_review?.status ?? result.crewai_analysis?.status, "Not available")}</p>
   <p><b>Evidence reviewed:</b> ${safe(result.crewai_review?.evidence_reviewed ?? result.crewai_analysis?.evidence_reviewed, "Not available")}</p>
   <pre>${safe(result.crewai_review?.analysis ?? result.crewai_review?.review ?? result.crewai_analysis?.analysis ?? "No CrewAI analysis was returned.")}</pre>
   <p><b>Warning:</b> ${safe(result.crewai_review?.warning ?? result.crewai_analysis?.warning, "None reported")}</p>`
)}

${section(
  "9. Monitoring and Evaluation",
  `<p><b>Total runtime:</b> ${safe(result.monitoring?.total_runtime_seconds, "Not available")} seconds</p>
   <p><b>Stage count:</b> ${safe(result.monitoring?.stage_count, "Not available")}</p>
   <p><b>Failed stages:</b> ${safe(result.monitoring?.failed_stage_count, "Not available")}</p>
   <p><b>Incomplete stages:</b> ${safe(result.monitoring?.incomplete_stage_count, "Not available")}</p>
   <pre>${safe(result.monitoring?.stages ?? "No stage metrics returned.")}</pre>`
)}

${section(
  "10. Unified Investigation Report",
  `<pre>${originalReport}</pre>`
)}

${section("11. Collection Warnings", warningsHtml)}

${section(
  "12. Limitations and Professional Review",
  `<div class="disclaimer">
    <p>This report reflects the data returned by CyberGuard at the time
    of generation. It does not independently certify the authenticity,
    completeness, or integrity of the original evidence.</p>
    <p>AI-generated interpretations and heuristic scores are not
    independently verified forensic facts. Missing evidence does not
    establish that an event did not occur.</p>
    <p>A qualified investigator should validate findings against the
    original evidence, document examination methods, preserve relevant
    hashes and chain-of-custody records, and review conclusions before
    relying on this report for legal, disciplinary, or operational
    decisions.</p>
  </div>
  <p>${safe(
    result.note,
    "Human validation is required before relying on these findings."
  )}</p>`
)}

<footer>
  CyberGuard · Digital Forensics Investigation Report<br>
  Generated ${escapeHtml(reportDate)}<br>
  Handle and distribute according to your evidence-handling policy.
</footer>
</body>
</html>`;

    const blob = new Blob([html], {
      type: "text/html;charset=utf-8",
    });

    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");

    const safeName = String(result.title || "investigation")
      .replace(/[^a-z0-9_-]+/gi, "_")
      .slice(0, 70);

    link.href = url;
    link.download =
      `CyberGuard_Report_${safeName || "investigation"}.html`;

    document.body.appendChild(link);
    link.click();
    link.remove();

    // Delay revocation so the browser has time to start the download.
    window.setTimeout(() => URL.revokeObjectURL(url), 1000);
  }

  const evidence = Array.isArray(result?.evidence)
    ? result.evidence
    : [];

  const hypotheses = Array.isArray(result?.hypotheses)
    ? result.hypotheses
    : [];

  const timeline = Array.isArray(result?.timeline)
    ? result.timeline
    : [];

  const investigationPlan = Array.isArray(
    result?.investigation_plan
  )
    ? result.investigation_plan
    : [];

  const artifactAnalyses = Array.isArray(
    result?.forensic_artifact_analyses
  )
    ? result.forensic_artifact_analyses
    : [];

  const collectionErrors = Array.isArray(
    result?.collection_errors
  )
    ? result.collection_errors
    : [];

  const summary = result?.evidence_summary || {};
  const severityCounts = summary.by_severity || {};
  const crewaiReview = result?.crewai_review || result?.crewai_analysis || null;
  const monitoring = result?.monitoring || null;

  const filteredEvidence = evidence.filter((item) => {
    const query = evidenceSearch.trim().toLowerCase();

    const matchesSearch = [
      item.description,
      item.event_type,
      item.evidence_id,
      item.source,
    ].some((value) =>
      String(
        value && typeof value === "object"
          ? JSON.stringify(value)
          : value || ""
      )
        .toLowerCase()
        .includes(query)
    );

    const matchesSeverity =
      severityFilter === "all" ||
      String(item.severity || "").toLowerCase() ===
        severityFilter;

    return matchesSearch && matchesSeverity;
  });

  return (
    <main className="app">
      <header className="header">
        <div className="brand">
          <span className="brand-icon">🛡️</span>

          <div>
            <h1>CyberGuard</h1>
            <p>AI-Powered Cyber Incident Investigation</p>
          </div>
        </div>

        <span className="status">● Investigation System</span>
      </header>

      <section className="hero">
        <p className="eyebrow">CYBERSECURITY COMMAND CENTER</p>

        <h2>Investigate threats. Connect evidence.</h2>

        <p>
          Analyze security logs and forensic disk images, organize
          evidence, and review potential incident hypotheses in one
          workspace.
        </p>
      </section>

      <section className="panel">
        <h2>New Investigation</h2>

        <p className="muted">
          Enter incident details, security logs, and optionally a
          forensic disk image.
        </p>

        <form onSubmit={handleInvestigation}>
          <label htmlFor="title">Incident title</label>

          <input
            id="title"
            value={title}
            onChange={(event) => setTitle(event.target.value)}
            placeholder="e.g. Suspicious login activity"
            minLength={3}
            maxLength={200}
            required
          />

          <label htmlFor="description">
            Incident description
          </label>

          <textarea
            id="description"
            value={description}
            onChange={(event) =>
              setDescription(event.target.value)
            }
            placeholder="Describe what happened and which systems may be affected."
            minLength={5}
            maxLength={5000}
            rows={3}
            required
          />

          <label htmlFor="logs">Security logs</label>

          <textarea
            id="logs"
            value={logText}
            onChange={(event) => setLogText(event.target.value)}
            placeholder={
              "Paste log entries here...\nExample: Failed login for user admin"
            }
            rows={6}
          />

          <div className="forensic-image-section">
            <h3>Forensic Disk Image (Optional)</h3>

            <p className="muted">
              Upload an image from your computer, drag and drop it
              below, or enter an absolute path to an image already
              accessible to the backend.
            </p>

            <div
              className={`image-drop-zone ${
                isDragging ? "dragging" : ""
              }`}
              onDragOver={(event) => {
                event.preventDefault();
                setIsDragging(true);
              }}
              onDragLeave={(event) => {
                event.preventDefault();
                setIsDragging(false);
              }}
              onDrop={handleDrop}
              role="group"
              aria-label="Forensic image upload area"
            >
              <div className="upload-icon" aria-hidden="true">
                ⇧
              </div>

              <strong>
                Drag and drop your forensic image here
              </strong>

              <p className="muted">
                Supported formats: .E01, .DD, .IMG, .RAW · Maximum 500 MB
              </p>

              <button
                type="button"
                className="secondary-button"
                onClick={() => fileInputRef.current?.click()}
                disabled={loading}
              >
                Choose Forensic Image
              </button>

              <input
                ref={fileInputRef}
                id="forensic-image"
                type="file"
                accept=".dd,.img,.raw,.e01"
                hidden
                onChange={(event) => {
                  handleFileSelection(event.target.files?.[0]);
                  event.target.value = "";
                }}
              />

              {imageFile && (
                <div className="selected-file">
                  <strong>Selected file:</strong>{" "}
                  {imageFile.name}

                  <span>
                    {" "}
                    ({(
                      imageFile.size /
                      (1024 * 1024)
                    ).toFixed(2)} MB)
                  </span>

                  <button
                    type="button"
                    className="remove-file-button"
                    onClick={() => {
                      setImageFile(null);
                      setUploadProgress("");
                    }}
                    disabled={loading}
                    aria-label="Remove selected image"
                  >
                    Remove
                  </button>
                </div>
              )}
            </div>

            <div className="image-path-divider">
              <span>OR ENTER AN EXISTING IMAGE PATH</span>
            </div>

            <label htmlFor="image-path">
              Forensic image path
            </label>

            <input
              id="image-path"
              type="text"
              value={imagePath}
              onChange={(event) => {
                setImagePath(event.target.value);
                setImageFile(null);
                setUploadProgress("");
              }}
              placeholder="e.g. G:\C1Prj01.E01"
              disabled={loading}
            />

            <p className="muted help-text">
              The path must be accessible from the backend computer,
              not just your browser. If you upload a file above,
              CyberGuard will use the uploaded copy instead.
            </p>

            {uploadProgress && (
              <p className="upload-status" role="status">
                {uploadProgress}
              </p>
            )}
          </div>

          <button type="submit" disabled={loading}>
            {loading
              ? "Processing Investigation..."
              : "Start Investigation →"}
          </button>
        </form>

        {error && (
          <p className="error" role="alert">
            {error}
          </p>
        )}
      </section>

      {result && (
        <section className="results-dashboard">
          <div className="results-heading">
            <div>
              <p className="eyebrow">INVESTIGATION WORKSPACE</p>

              <h2>{displayValue(result.title, title)}</h2>

              <p className="muted incident-id">
                Case ID: {displayValue(result.incident_id)}
              </p>
            </div>

            <div className="results-actions">
              <span className="completed-label">
                ● {displayValue(result.status, "completed")}
              </span>

              <button
                type="button"
                className="download-report-button"
                onClick={downloadProfessionalReport}
              >
                ↓ Download Professional Report
              </button>
            </div>
          </div>

          <div className="stats-grid">
            <article className="stat-card">
              <span>Total evidence</span>
              <strong>
                {summary.total ?? evidence.length}
              </strong>
            </article>

            <article className="stat-card">
              <span>Hypotheses</span>
              <strong>{hypotheses.length}</strong>
            </article>

            <article className="stat-card">
              <span>High severity</span>
              <strong>{severityCounts.high || 0}</strong>
            </article>

            <article className="stat-card">
              <span>Critical severity</span>
              <strong>{severityCounts.critical || 0}</strong>
            </article>
          </div>

          <section className="dashboard-section">
            <h3>CrewAI Investigation Review</h3>
            <p className="muted">
              Evidence-led interpretation with explicit validation status.
            </p>
            <CrewAIReview review={crewaiReview} />
          </section>

          <section className="dashboard-section">
            <h3>Monitoring and Evaluation</h3>
            <p className="muted">
              Runtime and stage status for this investigation. These metrics
              describe execution and do not establish forensic conclusions.
            </p>
            <MonitoringPanel monitoring={monitoring} />
          </section>

          {investigationPlan.length > 0 && (
            <section className="dashboard-section">
              <h3>Investigation Plan</h3>

              <ol>
                {investigationPlan.map((step, index) => (
                  <li key={index}>{displayValue(step)}</li>
                ))}
              </ol>
            </section>
          )}

          <section className="dashboard-section">
            <div className="section-heading">
              <div>
                <h3>Evidence Overview</h3>

                <p className="muted">
                  Events recognized in the supplied logs and image
                </p>
              </div>

              <span className="section-count">
                {filteredEvidence.length} of {evidence.length} events
              </span>
            </div>

            <div className="evidence-filters">
              <input
                type="search"
                aria-label="Search evidence"
                placeholder="Search evidence, event type, or ID..."
                value={evidenceSearch}
                onChange={(event) =>
                  setEvidenceSearch(event.target.value)
                }
              />

              <select
                aria-label="Filter by severity"
                value={severityFilter}
                onChange={(event) =>
                  setSeverityFilter(event.target.value)
                }
              >
                <option value="all">All severities</option>
                <option value="critical">Critical</option>
                <option value="high">High</option>
                <option value="medium">Medium</option>
                <option value="low">Low</option>
              </select>
            </div>

            <p className="muted filter-count">
              Showing {filteredEvidence.length} of {evidence.length} events
            </p>

            {filteredEvidence.length > 0 ? (
              <div className="evidence-grid">
                {filteredEvidence.map((item, index) => (
                  <EvidenceCard
                    key={item.evidence_id || index}
                    item={item}
                  />
                ))}
              </div>
            ) : (
              <p className="empty-state">
                No evidence matches your search and severity filter.
              </p>
            )}
          </section>

          <section className="dashboard-section">
            <div className="section-heading">
              <div>
                <h3>Investigation Timeline</h3>

                <p className="muted">
                  Events ordered by the returned timeline
                </p>
              </div>

              <span className="section-count">
                {timeline.length} events
              </span>
            </div>

            <Timeline events={timeline} />
          </section>

          <section className="dashboard-section">
            <div className="section-heading">
              <div>
                <h3>Investigation Hypotheses</h3>

                <p className="muted">
                  Potential explanations linked to evidence
                </p>
              </div>

              <span className="section-count">
                {hypotheses.length} hypotheses
              </span>
            </div>

            {hypotheses.length > 0 ? (
              <div className="hypothesis-grid">
                {hypotheses.map((hypothesis, index) => (
                  <HypothesisCard
                    key={hypothesis.hypothesis_id || index}
                    hypothesis={hypothesis}
                  />
                ))}
              </div>
            ) : (
              <p className="empty-state">
                No hypotheses were generated from the recognized evidence.
              </p>
            )}
          </section>

          {artifactAnalyses.length > 0 && (
            <section className="dashboard-section">
              <h3>Forensic Artifact AI Analysis</h3>

              {artifactAnalyses.map((analysis, index) => (
                <article className="evidence-card" key={index}>
                  <h4>
                    {formatArtifactSource(analysis.source, index)}
                  </h4>

                  <pre>
                    {typeof analysis.ai_analysis === "string"
                      ? analysis.ai_analysis
                      : JSON.stringify(
                          analysis.ai_analysis ?? analysis,
                          null,
                          2
                        )}
                  </pre>
                </article>
              ))}
            </section>
          )}

          {collectionErrors.length > 0 && (
            <section className="dashboard-section">
              <h3>Forensic Collection Warnings</h3>

              {collectionErrors.map((item, index) => (
                <p className="muted" key={index}>
                  {displayValue(item)}
                </p>
              ))}
            </section>
          )}

          <section className="dashboard-section report-section">
            <h3>Unified Investigation Report</h3>

            <pre>
              {typeof result.report === "string"
                ? result.report
                : JSON.stringify(
                    result.report ?? "No report available.",
                    null,
                    2
                  )}
            </pre>
          </section>

          <p className="disclaimer">
            {displayValue(
              result.note,
              "Findings are preliminary and require human validation."
            )}{" "}
            Heuristic scores are not calibrated probabilities.
          </p>
        </section>
      )}

      <footer>
        CyberGuard · Evidence-driven digital forensics
      </footer>
    </main>
  );
}

export default App;