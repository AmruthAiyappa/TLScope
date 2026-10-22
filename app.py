"""
TLScope — Flask Web Application Entrypoint.

Provides web routes, REST endpoints for TLS analysis, PDF generation,
and database persistence with strict SSRF defense and secure HTTP headers.
"""

import os
import uuid
import datetime
from flask import (
    Flask, render_template, request, jsonify, redirect, url_for,
    send_file, abort, make_response
)

from config import Config
from database.db import (
    init_db, save_scan_record, get_recent_scans, get_scan_by_id,
    delete_scan_by_id, clear_scan_history, get_history_statistics
)
from services.target_validator import (
    normalize_and_parse_target, resolve_and_validate_target, TargetValidationError
)
from services.tls_inspector import inspect_tls_endpoint
from services.certificate_analyzer import analyze_peer_certificate
from services.security_assessor import assess_security_posture
from services.report_generator import generate_pdf_report


def create_app(config_class=Config) -> Flask:
    """Application factory for TLScope."""
    app = Flask(__name__)
    app.config.from_object(config_class)

    # Initialize SQLite database schema
    init_db(app.config["DATABASE_PATH"])

    @app.after_request
    def set_security_headers(response):
        """Enforces safe HTTP response headers."""
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        # Content Security Policy allowing Bootstrap and Google Fonts / CDN icons / Chart.js
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
            "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://fonts.googleapis.com; "
            "font-src 'self' https://cdn.jsdelivr.net https://fonts.gstatic.com; "
            "img-src 'self' data:; "
            "connect-src 'self';"
        )
        return response

    @app.route("/")
    def index():
        """Home dashboard with scanner and recent scans."""
        recent = get_recent_scans(app.config["DATABASE_PATH"], limit=6)
        return render_template("index.html", recent_scans=recent)

    @app.route("/history")
    def history():
        """Audit history workspace with search, filtering, and sorting."""
        search_query = request.args.get("q", "").strip()
        outcome_filter = request.args.get("status", "ALL").strip()
        sort_by = request.args.get("sort", "newest").strip()

        all_scans = get_recent_scans(
            app.config["DATABASE_PATH"],
            limit=app.config.get("MAX_HISTORY_ENTRIES", 100),
            search_query=search_query if search_query else None,
            outcome_filter=outcome_filter,
            sort_by=sort_by
        )
        stats = get_history_statistics(app.config["DATABASE_PATH"])

        return render_template(
            "history.html",
            scans=all_scans,
            stats=stats,
            current_search=search_query,
            current_status=outcome_filter,
            current_sort=sort_by
        )

    @app.route("/pki-guide")
    def pki_guide():
        """Dedicated PKI and TLS Cryptographic Architecture Guide."""
        return render_template("pki_guide.html")

    @app.route("/scan/<scan_id>")
    def view_scan(scan_id: str):
        """Displays the detailed results dashboard for a specific scan."""
        record = get_scan_by_id(app.config["DATABASE_PATH"], scan_id)
        if not record:
            return render_template(
                "error.html",
                error_title="Scan Not Found",
                error_message=f"No scan with ID '{scan_id}' exists in the audit database."
            ), 404
        
        details = record.get("details", {})
        return render_template("results.html", scan=details, record=record)

    @app.route("/api/scan", methods=["POST"])
    def api_scan():
        """
        Executes a real TLS scan against the requested target.
        Validates hostname, resolves DNS, checks SSRF, performs TLS handshake,
        probes HSTS, analyzes X.509 certificate, executes security assessment, and persists results.
        """
        # Accept JSON or form-encoded submission
        if request.is_json:
            data = request.get_json() or {}
            target_raw = data.get("target", "")
            port_input = data.get("port", None)
        else:
            target_raw = request.form.get("target", "")
            port_input = request.form.get("port", None)

        if not target_raw:
            return jsonify({"success": False, "error": "Target domain or URL is required."}), 400

        # Step 1: Input Normalization & Syntax Validation
        try:
            default_port = int(port_input) if port_input and str(port_input).isdigit() else app.config["DEFAULT_PORT"]
            hostname, port = normalize_and_parse_target(target_raw, default_port=default_port)
        except TargetValidationError as e:
            return jsonify({"success": False, "error": str(e), "category": "VALIDATION_ERROR"}), 400
        except Exception as e:
            return jsonify({"success": False, "error": f"Invalid input format: {str(e)}", "category": "VALIDATION_ERROR"}), 400

        # Step 2: DNS Resolution and SSRF Defense
        try:
            pinned_ip, resolved_ips = resolve_and_validate_target(
                hostname, 
                port, 
                allow_private_ips=app.config.get("ALLOW_PRIVATE_IPS", False)
            )
        except TargetValidationError as e:
            return jsonify({"success": False, "error": str(e), "category": "SSRF_VIOLATION"}), 400
        except Exception as e:
            return jsonify({"success": False, "error": f"DNS resolution error: {str(e)}", "category": "DNS_ERROR"}), 400

        # Step 3: Real TLS Inspection & Safe HSTS Probe
        tls_result = inspect_tls_endpoint(
            hostname=hostname,
            pinned_ip=pinned_ip,
            port=port,
            connect_timeout=app.config.get("SOCKET_CONNECT_TIMEOUT", 6.0),
            read_timeout=app.config.get("SOCKET_READ_TIMEOUT", 6.0),
            check_hsts=True
        )

        # Step 4: X.509 Certificate Parsing & Field Analysis
        cert_result = analyze_peer_certificate(tls_result.peer_cert_der, hostname)

        # Step 5: Deterministic Security Rule Assessment
        assessment = assess_security_posture(
            tls_result=tls_result,
            cert_result=cert_result,
            warn_days=app.config.get("CERT_EXPIRY_WARN_DAYS", 30),
            critical_days=app.config.get("CERT_EXPIRY_CRITICAL_DAYS", 7)
        )

        scan_id = str(uuid.uuid4())
        scan_timestamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

        # Determine explicit overall scan state
        if assessment.overall_outcome == "FAILED":
            scan_state = "FAILED"
        elif assessment.warning_count > 0:
            scan_state = "COMPLETED_WITH_WARNINGS"
        else:
            scan_state = "COMPLETED"

        # Compile comprehensive structured response
        scan_payload = {
            "scan_id": scan_id,
            "scan_state": scan_state,
            "hostname": hostname,
            "port": port,
            "ip_address": pinned_ip,
            "resolved_ips": resolved_ips,
            "scan_timestamp": scan_timestamp,
            "pipeline_stages": tls_result.pipeline_stages,
            "connection_established": tls_result.connection_established,
            "handshake_completed": tls_result.handshake_completed,
            "verification_passed": tls_result.verification_passed,
            "chain_verified_by_ca": tls_result.chain_verified_by_ca,
            "is_diagnostic_leaf": tls_result.is_diagnostic_leaf,
            "tls_version": tls_result.tls_version,
            "cipher_suite": tls_result.cipher_name,
            "cipher_protocol": tls_result.cipher_protocol,
            "cipher_bits": tls_result.cipher_bits,
            "alpn_negotiated": tls_result.alpn_negotiated,
            "hsts_present": tls_result.hsts_present,
            "hsts_raw_header": tls_result.hsts_raw_header,
            "hsts_max_age": tls_result.hsts_max_age,
            "overall_outcome": assessment.overall_outcome,
            "educational_score": assessment.educational_score,
            "score_label": assessment.score_label,
            "score_breakdown": assessment.score_breakdown,
            "passed_count": assessment.passed_count,
            "warning_count": assessment.warning_count,
            "failure_count": assessment.failure_count,
            "not_assessed_count": assessment.not_assessed_count,
            "assessment_notes": assessment.assessment_notes,
            "findings": [f.to_dict() for f in assessment.findings],
            "certificate_details": cert_result.to_dict(),
            "error_message": tls_result.verification_error
        }

        # Step 6: Persist in SQLite Scan History
        try:
            save_scan_record(app.config["DATABASE_PATH"], {
                "scan_id": scan_id,
                "hostname": hostname,
                "ip_address": pinned_ip,
                "port": port,
                "scan_timestamp": scan_timestamp,
                "overall_outcome": assessment.overall_outcome,
                "tls_version": tls_result.tls_version,
                "cipher_suite": tls_result.cipher_name,
                "educational_score": assessment.educational_score,
                "findings_count": len(assessment.findings),
                "passed_count": assessment.passed_count,
                "warning_count": assessment.warning_count,
                "failure_count": assessment.failure_count,
                "is_completed": assessment.overall_outcome != "FAILED",
                "error_message": tls_result.verification_error,
                "details": scan_payload
            })
        except Exception:
            # Failure to record history should not crash user response
            pass

        return jsonify({
            "success": True,
            "scan_id": scan_id,
            "redirect_url": url_for("view_scan", scan_id=scan_id),
            "data": scan_payload
        })

    @app.route("/api/scan/<scan_id>/pdf")
    def download_pdf(scan_id: str):
        """Generates and downloads the ReportLab PDF security report."""
        record = get_scan_by_id(app.config["DATABASE_PATH"], scan_id)
        if not record:
            abort(404, description="Scan record not found.")

        scan_data = record.get("details", {})
        try:
            pdf_buffer = generate_pdf_report(scan_data)
            hostname_clean = scan_data.get("hostname", "target").replace(".", "_")
            filename = f"TLScope_{hostname_clean}_{scan_id[:8]}.pdf"
            
            return send_file(
                pdf_buffer,
                mimetype="application/pdf",
                as_attachment=True,
                download_name=filename
            )
        except Exception as e:
            return jsonify({"error": f"Failed to generate PDF report: {str(e)}"}), 500

    @app.route("/api/scan/<scan_id>/delete", methods=["POST"])
    def api_delete_scan(scan_id: str):
        """Deletes an individual scan record from history."""
        success = delete_scan_by_id(app.config["DATABASE_PATH"], scan_id)
        if success:
            return jsonify({"success": True, "message": "Scan record deleted."})
        return jsonify({"success": False, "error": "Scan record not found or deletion failed."}), 404

    @app.route("/api/history/clear", methods=["POST"])
    def api_clear_history():
        """Clears local SQLite scan history."""
        try:
            clear_scan_history(app.config["DATABASE_PATH"])
            return jsonify({"success": True, "message": "Scan history cleared."})
        except Exception as e:
            return jsonify({"success": False, "error": str(e)}), 500

    @app.route("/api/history/stats")
    def api_history_stats():
        """Returns aggregate historical statistics."""
        stats = get_history_statistics(app.config["DATABASE_PATH"])
        return jsonify(stats)

    @app.route("/health")
    def health():
        """Health check endpoint."""
        return jsonify({"status": "healthy", "service": "TLScope", "version": "1.1.0"})

    @app.errorhandler(404)
    def handle_404(e):
        if request.path.startswith("/api/"):
            return jsonify({"error": "Resource not found"}), 404
        return render_template(
            "error.html",
            error_title="404 — Page Not Found",
            error_message="The requested page or scan resource does not exist."
        ), 404

    @app.errorhandler(500)
    def handle_500(e):
        if request.path.startswith("/api/"):
            return jsonify({"error": "An internal server error occurred"}), 500
        return render_template(
            "error.html",
            error_title="500 — Internal Server Error",
            error_message="An unexpected server error occurred. No sensitive details are exposed."
        ), 500

    return app


if __name__ == "__main__":
    app = create_app()
    port = int(os.environ.get("PORT", 5000))
    print(f"[*] Starting TLScope server on http://127.0.0.1:{port}")
    app.run(host="127.0.0.1", port=port, debug=False)
