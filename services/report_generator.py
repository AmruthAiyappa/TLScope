"""
PDF Report Generator Service for TLScope.

Generates professional, presentation-ready academic security assessment reports
using ReportLab with two-pass page numbering, structured evidence matrices,
certificate chain summaries, and standards references.
"""

import io
import datetime
from typing import Dict, Any, List

from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, KeepTogether, HRFlowable
)
from reportlab.pdfgen import canvas


class NumberedCanvas(canvas.Canvas):
    """
    Two-pass canvas for dynamic 'Page X of Y' numbering and running header/footer.
    """
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._saved_page_states = []

    def showPage(self):
        self._saved_page_states.append(dict(self.__dict__))
        self._startPage()

    def save(self):
        num_pages = len(self._saved_page_states)
        for state in self._saved_page_states:
            self.__dict__.update(state)
            self.draw_page_decorations(num_pages)
            super().showPage()
        super().save()

    def draw_page_decorations(self, total_pages: int):
        self.saveState()
        self.setFont("Helvetica", 8)
        self.setFillColor(colors.HexColor("#64748b"))

        # Running Header (pages > 1)
        if self._pageNumber > 1:
            self.drawString(36, 760, "TLScope — TLS Certificate & HTTPS Security Audit Report")
            self.setStrokeColor(colors.HexColor("#e2e8f0"))
            self.setLineWidth(0.5)
            self.line(36, 755, 576, 755)

        # Running Footer (all pages)
        self.setStrokeColor(colors.HexColor("#e2e8f0"))
        self.setLineWidth(0.5)
        self.line(36, 45, 576, 45)
        self.drawString(36, 32, "Confidential Academic Security Audit • Standards: RFC 8446 / RFC 5280 / RFC 6125 / NIST SP 800-52r2")
        self.drawRightString(576, 32, f"Page {self._pageNumber} of {total_pages}")
        self.restoreState()


def generate_pdf_report(scan_data: Dict[str, Any]) -> io.BytesIO:
    """
    Builds a structured, high-contrast, multi-section PDF audit report in memory.
    Returns a BytesIO stream containing the PDF document.
    """
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=letter,
        leftMargin=36,
        rightMargin=36,
        topMargin=45,
        bottomMargin=55
    )

    styles = getSampleStyleSheet()
    
    # Custom Palette
    c_primary = colors.HexColor("#0f172a")     # Slate 900
    c_brand = colors.HexColor("#0284c7")       # Sky 600
    c_brand_dark = colors.HexColor("#0369a1")  # Sky 700
    c_text = colors.HexColor("#1e293b")        # Slate 800
    c_muted = colors.HexColor("#64748b")       # Slate 500
    c_bg_light = colors.HexColor("#f8fafc")    # Slate 50
    c_border = colors.HexColor("#e2e8f0")      # Slate 200

    # Typography styles
    title_style = ParagraphStyle(
        "ReportTitle",
        parent=styles["Heading1"],
        fontName="Helvetica-Bold",
        fontSize=18,
        leading=22,
        textColor=c_primary,
        spaceAfter=3
    )
    
    subtitle_style = ParagraphStyle(
        "ReportSubtitle",
        parent=styles["Normal"],
        fontName="Helvetica",
        fontSize=9.5,
        leading=13,
        textColor=c_muted,
        spaceAfter=12
    )

    h2_style = ParagraphStyle(
        "SectionHeader",
        parent=styles["Heading2"],
        fontName="Helvetica-Bold",
        fontSize=11.5,
        leading=15,
        textColor=c_brand_dark,
        spaceBefore=10,
        spaceAfter=5
    )

    cell_bold = ParagraphStyle(
        "CellBold",
        parent=styles["Normal"],
        fontName="Helvetica-Bold",
        fontSize=8,
        leading=10.5,
        textColor=c_primary
    )

    cell_normal = ParagraphStyle(
        "CellNormal",
        parent=styles["Normal"],
        fontName="Helvetica",
        fontSize=7.5,
        leading=10,
        textColor=c_text
    )

    cell_mono = ParagraphStyle(
        "CellMono",
        parent=styles["Normal"],
        fontName="Courier",
        fontSize=7.5,
        leading=9.5,
        textColor=c_text
    )

    disclaimer_style = ParagraphStyle(
        "Disclaimer",
        parent=styles["Normal"],
        fontName="Helvetica-Oblique",
        fontSize=7.2,
        leading=9.5,
        textColor=c_muted,
        alignment=1  # Centered
    )

    elements = []

    # 1. Header Banner
    elements.append(Paragraph("TLScope — TLS Certificate & HTTPS Security Audit Report", title_style))
    elements.append(Paragraph(
        f"Automated Academic Security Assessment | Generated: {scan_data.get('scan_timestamp', datetime.datetime.now().isoformat())} | Scan ID: {scan_data.get('scan_id', 'N/A')[:8]}",
        subtitle_style
    ))
    elements.append(HRFlowable(width="100%", thickness=1.5, color=c_brand, spaceAfter=10))

    # 2. Executive Summary Table
    elements.append(Paragraph("1. Executive Summary & Assessment Posture", h2_style))
    
    outcome = scan_data.get("overall_outcome", "UNKNOWN")
    score = scan_data.get("educational_score")
    score_text = f"{score}/100" if score is not None else "Inconclusive / N/A"

    summary_data = [
        [
            Paragraph("Target Hostname:", cell_bold),
            Paragraph(str(scan_data.get("hostname", "N/A")), cell_normal),
            Paragraph("Overall Security Posture:", cell_bold),
            Paragraph(f"<b>{outcome}</b> ({score_text})", cell_bold)
        ],
        [
            Paragraph("Target Port / Pinned IP:", cell_bold),
            Paragraph(f"{scan_data.get('port', 443)} / {scan_data.get('ip_address', 'N/A')}", cell_normal),
            Paragraph("Certificate Trust:", cell_bold),
            Paragraph(
                "<font color='#16a34a'><b>VERIFIED TRUSTED</b></font>" 
                if scan_data.get("verification_passed") 
                else "<font color='#dc2626'><b>VERIFICATION FAILED</b></font>",
                cell_normal
            )
        ],
        [
            Paragraph("Negotiated TLS:", cell_bold),
            Paragraph(str(scan_data.get("tls_version", "N/A")), cell_normal),
            Paragraph("Negotiated Cipher:", cell_bold),
            Paragraph(str(scan_data.get("cipher_suite", "N/A")), cell_mono)
        ],
        [
            Paragraph("Finding Breakdown:", cell_bold),
            Paragraph(
                f"<font color='#16a34a'><b>{scan_data.get('passed_count', 0)} Pass</b></font> | "
                f"<font color='#d97706'><b>{scan_data.get('warning_count', 0)} Warning</b></font> | "
                f"<font color='#dc2626'><b>{scan_data.get('failure_count', 0)} Fail</b></font>",
                cell_normal
            ),
            Paragraph("ALPN Negotiation:", cell_bold),
            Paragraph(str(scan_data.get("alpn_negotiated") or "None / Default"), cell_normal)
        ]
    ]

    t_summary = Table(summary_data, colWidths=[110, 160, 130, 140])
    t_summary.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), c_bg_light),
        ("GRID", (0, 0), (-1, -1), 0.5, c_border),
        ("TOPPADDING", (0, 0), (-1, -1), 3),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
        ("LEFTPADDING", (0, 0), (-1, -1), 6),
        ("RIGHTPADDING", (0, 0), (-1, -1), 6),
    ]))
    elements.append(t_summary)
    elements.append(Spacer(1, 8))

    # 3. Certificate Identity & Chain of Trust
    cert = scan_data.get("certificate_details") or {}
    elements.append(Paragraph("2. X.509 Leaf Certificate & Chain Hierarchy", h2_style))

    if cert.get("parsed_successfully"):
        sans_str = ", ".join(cert.get("subject_alternative_names", []))
        if len(sans_str) > 130:
            sans_str = sans_str[:127] + "..."

        cert_data = [
            [Paragraph("Subject (CN):", cell_bold), Paragraph(str(cert.get("subject_common_name") or cert.get("subject_dn")), cell_normal)],
            [Paragraph("Issuer (CA):", cell_bold), Paragraph(str(cert.get("issuer_common_name") or cert.get("issuer_dn")), cell_normal)],
            [Paragraph("Subject Alt Names (SANs):", cell_bold), Paragraph(sans_str or "None specified (RFC 6125 non-compliant)", cell_mono)],
            [Paragraph("Hostname Match Status:", cell_bold), Paragraph(f"<b>{cert.get('hostname_match_details', 'N/A')}</b>", cell_normal)],
            [Paragraph("Validity Window (UTC):", cell_bold), Paragraph(f"{cert.get('valid_from_iso', '')} to {cert.get('valid_to_iso', '')} ({cert.get('days_remaining', 0)} days remaining)", cell_normal)],
            [Paragraph("Public Key Specification:", cell_bold), Paragraph(str(cert.get("public_key_details", "N/A")), cell_normal)],
            [Paragraph("Signature Algorithm:", cell_bold), Paragraph(str(cert.get("signature_algorithm", "N/A")), cell_normal)],
            [Paragraph("Serial Number (Hex):", cell_bold), Paragraph(str(cert.get("serial_number_hex", "N/A")), cell_mono)],
            [Paragraph("SHA-256 Fingerprint:", cell_bold), Paragraph(str(cert.get("fingerprint_sha256", "N/A")), cell_mono)],
            [Paragraph("Key Usages:", cell_bold), Paragraph(", ".join(cert.get("key_usages", []) or ["Standard Web Server"]), cell_normal)]
        ]

        t_cert = Table(cert_data, colWidths=[120, 420])
        t_cert.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (0, -1), c_bg_light),
            ("GRID", (0, 0), (-1, -1), 0.5, c_border),
            ("TOPPADDING", (0, 0), (-1, -1), 3),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
            ("LEFTPADDING", (0, 0), (-1, -1), 6),
            ("RIGHTPADDING", (0, 0), (-1, -1), 6),
        ]))
        elements.append(t_cert)

        # Visual Chain of Trust
        chain = cert.get("chain_hierarchy") or []
        if chain:
            elements.append(Spacer(1, 4))
            chain_rows = [
                [
                    Paragraph("<b>Trust Level</b>", cell_bold),
                    Paragraph("<b>Identity / Common Name</b>", cell_bold),
                    Paragraph("<b>Organization</b>", cell_bold),
                    Paragraph("<b>System Trust Status</b>", cell_bold)
                ]
            ]
            for node in chain:
                trusted_label = "<font color='#16a34a'><b>TRUSTED</b></font>" if node.get("trusted_by_system") else "<font color='#dc2626'><b>UNTRUSTED</b></font>"
                chain_rows.append([
                    Paragraph(node.get("level_name", ""), cell_normal),
                    Paragraph(node.get("common_name", ""), cell_mono),
                    Paragraph(node.get("organization", "—"), cell_normal),
                    Paragraph(trusted_label, cell_normal)
                ])
            t_chain = Table(chain_rows, colWidths=[130, 160, 150, 100])
            t_chain.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), c_bg_light),
                ("GRID", (0, 0), (-1, -1), 0.5, c_border),
                ("TOPPADDING", (0, 0), (-1, -1), 2.5),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 2.5),
                ("LEFTPADDING", (0, 0), (-1, -1), 5),
                ("RIGHTPADDING", (0, 0), (-1, -1), 5),
            ]))
            elements.append(t_chain)
    else:
        elements.append(Paragraph(
            f"<i>Certificate details unavailable or parsing failed: {scan_data.get('error_message') or cert.get('error', 'No peer certificate presented')}</i>",
            cell_normal
        ))

    elements.append(Spacer(1, 8))

    # 4. Detailed Security Findings Table
    elements.append(Paragraph("3. Deterministic Findings & Remediation Advisory", h2_style))
    
    findings: List[Dict[str, Any]] = scan_data.get("findings") or []
    if findings:
        findings_table_data = [
            [
                Paragraph("<b>Check / ID</b>", cell_bold),
                Paragraph("<b>Severity</b>", cell_bold),
                Paragraph("<b>Status</b>", cell_bold),
                Paragraph("<b>Evidence, Security Implication & Remediation</b>", cell_bold)
            ]
        ]

        for f in findings:
            sev = f.get("severity", "Info")
            status = f.get("status", "Pass")
            ref = f.get("reference_standard", "NIST SP 800-52r2")

            if status in ("Pass", "PASS"):
                status_color = "#16a34a"
                status_disp = "PASS"
            elif status in ("Warning", "WARN"):
                status_color = "#d97706"
                status_disp = "WARN"
            elif status in ("Fail", "FAIL"):
                status_color = "#dc2626"
                status_disp = "FAIL"
            else:
                status_color = "#64748b"
                status_disp = "NOT EVALUATED"

            evidence_text = (
                f"<b>Evidence:</b> {f.get('evidence', '')}<br/>"
                f"<b>Implication:</b> {f.get('implication', '')}<br/>"
                f"<b>Remediation:</b> <font color='#0369a1'>{f.get('recommendation', '')}</font><br/>"
                f"<b>Standard Reference:</b> <font color='#64748b'>{ref}</font>"
            )

            findings_table_data.append([
                Paragraph(f"<b>{f.get('title', '')}</b><br/><font color='#64748b'>{f.get('finding_id', '')}</font>", cell_normal),
                Paragraph(f"<b>{sev}</b>", cell_bold),
                Paragraph(f"<font color='{status_color}'><b>{status_disp}</b></font>", cell_bold),
                Paragraph(evidence_text, cell_normal)
            ])

        t_findings = Table(findings_table_data, colWidths=[110, 50, 60, 320])
        t_findings.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), c_bg_light),
            ("GRID", (0, 0), (-1, -1), 0.5, c_border),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("TOPPADDING", (0, 0), (-1, -1), 3),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
            ("LEFTPADDING", (0, 0), (-1, -1), 4),
            ("RIGHTPADDING", (0, 0), (-1, -1), 4),
        ]))
        elements.append(t_findings)
    else:
        elements.append(Paragraph("<i>No security findings generated for this scan target.</i>", cell_normal))

    elements.append(Spacer(1, 10))

    # 5. Academic Disclaimer Footer
    elements.append(KeepTogether([
        HRFlowable(width="100%", thickness=0.8, color=c_border, spaceAfter=6),
        Paragraph(
            "<b>Academic Coursework & Educational Disclaimer:</b> This audit was generated deterministically by TLScope "
            "for academic research and coursework demonstration (Cryptography and Network Security). The evaluation checks "
            "transport layer security against NIST SP 800-52r2, RFC 8446, RFC 5280, RFC 6125, and RFC 6797 standards. "
            "A successful TLS handshake or high score does not imply that the complete application, host operating system, "
            "or organization is secure from all vulnerabilities.",
            disclaimer_style
        )
    ]))

    doc.build(elements, canvasmaker=NumberedCanvas)
    buffer.seek(0)
    return buffer
