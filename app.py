import sys
import json
import uuid
import queue
import tempfile
import threading
from pathlib import Path
from datetime import datetime

from flask import Flask, request, jsonify, send_file, Response

sys.path.insert(0, str(Path(__file__).parent))

BASE_DIR = Path(__file__).parent
app = Flask(__name__, static_folder=str(BASE_DIR / "website"), static_url_path="/static")

_jobs: dict = {}


# ── Background analysis worker ─────────────────────────────────────────────────
def _run_job(job_id: str, pcap_path: Path) -> None:
    q = _jobs[job_id]["queue"]

    def emit(event: str, data: dict) -> None:
        q.put({"event": event, "data": data})

    try:
        from core.validator import validate_pcap_file, ValidationError
        from core.parser import parse_pcap, PcapParseError
        from core.models import AnalysisReport
        from detection.engine import DetectionEngine
        from enrichment.enricher import Enricher
        from ai.explainer import LLMExplainer, Guardrails
        from output.report import generate_pdf

        # 1 — validate
        emit("step", {"step": 1, "label": "Validating file…", "status": "running"})
        try:
            safe_name, file_hash = validate_pcap_file(pcap_path)
        except ValidationError as e:
            emit("error", {"message": str(e)})
            return
        emit("step", {"step": 1, "label": "File validated",
                      "status": "done", "detail": f"SHA-256: {file_hash[:16]}…"})

        # 2 — parse
        emit("step", {"step": 2, "label": "Parsing PCAP…", "status": "running"})
        analysis_start = datetime.now()
        try:
            flows, stats = parse_pcap(pcap_path)
        except PcapParseError as e:
            emit("error", {"message": str(e)})
            return
        emit("step", {"step": 2, "label": "PCAP parsed", "status": "done",
                      "detail": f"{stats['flow_count']:,} flows · {stats['packet_count']:,} packets"})

        # 3 — detect
        emit("step", {"step": 3, "label": "Running detection rules…", "status": "running"})
        engine = DetectionEngine()
        findings = engine.run(flows)
        analysis_end = datetime.now()
        emit("step", {"step": 3, "label": "Detection complete", "status": "done",
                      "detail": f"{len(findings)} finding(s)"})

        # 4 — enrich
        emit("step", {"step": 4, "label": "Enriching IOCs…", "status": "running"})
        enricher = Enricher()
        findings = enricher.enrich_all(findings)
        emit("step", {"step": 4, "label": "Enrichment done", "status": "done"})

        # 5 — AI
        emit("step", {"step": 5, "label": "Generating AI explanations…", "status": "running"})
        explainer = LLMExplainer()
        for f in findings:
            expl = explainer.explain(f)
            if expl and Guardrails.validate_explanation(expl):
                f.explanation = expl
        emit("step", {"step": 5, "label": "AI explanations ready", "status": "done"})

        # 6 — report
        emit("step", {"step": 6, "label": "Building PDF report…", "status": "running"})
        report = AnalysisReport(
            pcap_filename=safe_name,
            pcap_hash=file_hash,
            analysis_start=analysis_start,
            analysis_end=analysis_end,
            total_flows=stats["flow_count"],
            total_packets=stats["packet_count"],
            total_bytes=stats["bytes_total"],
            findings=findings,
        )
        pdf_path  = Path(tempfile.mktemp(suffix=".pdf"))
        json_path = Path(tempfile.mktemp(suffix=".json"))
        generate_pdf(report, pdf_path)
        json_path.write_text(report.to_json())

        _jobs[job_id]["pdf_path"]  = pdf_path
        _jobs[job_id]["json_path"] = json_path
        _jobs[job_id]["result"]    = report
        emit("step", {"step": 6, "label": "Report ready", "status": "done"})

        # Serialize findings for the browser
        findings_out = []
        for f in findings:
            findings_out.append({
                "rule_name":       f.rule_name,
                "severity":        f.severity.value,
                "title":           f.title,
                "description":     f.description,
                "src_ip":          f.src_ip,
                "dst_ip":          f.dst_ip,
                "timestamp":       str(f.timestamp)[:19] if f.timestamp else "—",
                "mitre_technique": f.mitre_technique,
                "mitre_tactic":    f.mitre_tactic,
                "evidence":        f.evidence,
                "explanation":     getattr(f, "explanation", None),
                "iocs": [
                    {
                        "value":     ioc.value,
                        "type":      ioc.ioc_type.value,
                        "vt_score":  ioc.vt_score or "—",
                        "malicious": ioc.malicious,
                    }
                    for ioc in f.iocs
                ],
            })

        sev = report.finding_count_by_severity
        emit("complete", {
            "job_id":         job_id,
            "filename":       safe_name,
            "hash":           file_hash,
            "duration":       round(report.duration_seconds, 1),
            "flows":          report.total_flows,
            "packets":        report.total_packets,
            "bytes":          report.total_bytes,
            "findings_count": len(findings),
            "severity":       {k: sev.get(k, 0) for k in ("CRITICAL", "HIGH", "MEDIUM", "LOW")},
            "findings":       findings_out,
        })

    except Exception as e:
        emit("error", {"message": f"Unexpected error: {e}"})
    finally:
        q.put(None)


# ── Routes ──────────────────────────────────────────────────────────────────────
@app.route("/")
def index():
    return send_file(str(BASE_DIR / "website" / "index.html"))


@app.route("/docs")
def docs():
    return send_file(str(BASE_DIR / "website" / "docs.html"))


@app.route("/analyze", methods=["POST"])
def analyze():
    if "file" not in request.files:
        return jsonify({"error": "No file provided"}), 400
    f = request.files["file"]
    if not f.filename:
        return jsonify({"error": "No filename"}), 400
    ext = Path(f.filename).suffix.lower()
    if ext not in (".pcap", ".pcapng"):
        return jsonify({"error": "Only .pcap and .pcapng files accepted"}), 400

    tmp = tempfile.NamedTemporaryFile(delete=False, suffix=ext)
    f.save(tmp.name)
    tmp.close()

    job_id = str(uuid.uuid4())
    _jobs[job_id] = {"queue": queue.Queue(), "pdf_path": None, "json_path": None, "result": None}

    threading.Thread(target=_run_job, args=(job_id, Path(tmp.name)), daemon=True).start()
    return jsonify({"job_id": job_id})


@app.route("/stream/<job_id>")
def stream(job_id):
    if job_id not in _jobs:
        return jsonify({"error": "Job not found"}), 404

    def generate():
        q = _jobs[job_id]["queue"]
        while True:
            msg = q.get()
            if msg is None:
                break
            yield f"data: {json.dumps(msg)}\n\n"

    return Response(
        generate(),
        mimetype="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


@app.route("/download/<job_id>/pdf")
def download_pdf(job_id):
    job = _jobs.get(job_id)
    if not job or not job["pdf_path"]:
        return jsonify({"error": "Not found"}), 404
    stem = job["result"].pcap_filename.rsplit(".", 1)[0]
    return send_file(job["pdf_path"], as_attachment=True,
                     download_name=f"{stem}_forensiq.pdf", mimetype="application/pdf")


@app.route("/download/<job_id>/json")
def download_json(job_id):
    job = _jobs.get(job_id)
    if not job or not job["json_path"]:
        return jsonify({"error": "Not found"}), 404
    stem = job["result"].pcap_filename.rsplit(".", 1)[0]
    return send_file(job["json_path"], as_attachment=True,
                     download_name=f"{stem}_forensiq.json", mimetype="application/json")


if __name__ == "__main__":
    app.run(debug=False, port=5001, threaded=True)
