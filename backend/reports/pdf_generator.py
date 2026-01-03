"""PDF report generator using ReportLab."""

import io
from datetime import datetime
from io import BytesIO
from typing import Any, Dict, List, Optional

import matplotlib.pyplot as plt
import numpy as np
from loguru import logger
from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_JUSTIFY, TA_LEFT
from reportlab.lib.pagesizes import A4, letter
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.platypus import (
    Image,
    KeepTogether,
    PageBreak,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)


class PDFReportGenerator:
    """
    Generates PDF reports for security scans.
    
    Supports:
    - Technical reports with detailed findings
    - Executive summaries for management
    - Individual target reports
    """

    def __init__(self):
        """Initialize PDF generator with custom styles."""
        self.styles = getSampleStyleSheet()
        self._setup_custom_styles()

    def _setup_custom_styles(self):
        """Setup custom paragraph styles for reports."""
        # Custom title style
        self.styles.add(
            ParagraphStyle(
                name="CustomTitle",
                parent=self.styles["Heading1"],
                fontSize=24,
                textColor=colors.HexColor("#1a1a1a"),
                spaceAfter=30,
                alignment=TA_CENTER,
                fontName="Helvetica-Bold",
            )
        )

        # Section header style
        self.styles.add(
            ParagraphStyle(
                name="SectionHeader",
                parent=self.styles["Heading2"],
                fontSize=16,
                textColor=colors.HexColor("#2c3e50"),
                spaceAfter=12,
                spaceBefore=12,
                borderWidth=1,
                borderColor=colors.HexColor("#3498db"),
                borderPadding=5,
                backColor=colors.HexColor("#ecf0f1"),
                fontName="Helvetica-Bold",
            )
        )

        # Finding title styles (color coded by severity)
        severity_colors = {
            "critical": "#c0392b",
            "high": "#e74c3c",
            "medium": "#f39c12",
            "low": "#f1c40f",
            "info": "#3498db",
        }

        for severity, color in severity_colors.items():
            self.styles.add(
                ParagraphStyle(
                    name=f"Finding{severity.capitalize()}",
                    parent=self.styles["Heading4"],
                    fontSize=12,
                    textColor=colors.HexColor(color),
                    spaceAfter=6,
                    fontName="Helvetica-Bold",
                )
            )

        # Code block style
        self.styles.add(
            ParagraphStyle(
                name="Code",
                parent=self.styles["Code"],
                fontSize=8,
                fontName="Courier",
                textColor=colors.HexColor("#2c3e50"),
                backColor=colors.HexColor("#f8f9fa"),
                borderWidth=1,
                borderColor=colors.HexColor("#dee2e6"),
                borderPadding=8,
                leftIndent=10,
                rightIndent=10,
            )
        )

        # Remediation style
        self.styles.add(
            ParagraphStyle(
                name="Remediation",
                parent=self.styles["BodyText"],
                fontSize=10,
                textColor=colors.HexColor("#27ae60"),
                leftIndent=15,
                bulletIndent=10,
            )
        )

    def generate_cover_page(self, scan_data: Dict[str, Any]) -> List:
        """
        Generate cover page for report.

        Args:
            scan_data: Scan metadata

        Returns:
            List of reportlab flowables
        """
        elements = []

        # Logo placeholder (can be added if logo file exists)
        # elements.append(Image('logo.png', width=2*inch, height=1*inch))

        # Title
        title = Paragraph(
            f"Security Assessment Report<br/>{scan_data.get('name', 'Unnamed Scan')}",
            self.styles["CustomTitle"],
        )
        elements.append(Spacer(1, 2 * inch))
        elements.append(title)
        elements.append(Spacer(1, 0.5 * inch))

        # Metadata table
        metadata = [
            ["Scan ID:", str(scan_data.get("id", "N/A"))],
            ["Date:", scan_data.get("date", datetime.utcnow()).strftime("%Y-%m-%d %H:%M")],
            ["Duration:", f"{scan_data.get('duration', 0):.1f} minutes"],
            ["Total Targets:", str(scan_data.get("total_targets", 0))],
            ["Total Findings:", str(scan_data.get("total_findings", 0))],
            ["Risk Score:", f"{scan_data.get('risk_score', 0):.1f}/10"],
        ]

        table = Table(metadata, colWidths=[2 * inch, 4 * inch])
        table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#ecf0f1")),
                    ("TEXTCOLOR", (0, 0), (-1, -1), colors.black),
                    ("ALIGN", (0, 0), (-1, -1), "LEFT"),
                    ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
                    ("FONTSIZE", (0, 0), (-1, -1), 10),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 12),
                    ("TOPPADDING", (0, 0), (-1, -1), 12),
                    ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
                ]
            )
        )

        elements.append(table)
        elements.append(Spacer(1, 0.5 * inch))

        # Confidentiality notice
        notice = Paragraph(
            "<b>CONFIDENTIAL</b><br/>This document contains sensitive security information.",
            self.styles["Normal"],
        )
        elements.append(notice)
        elements.append(PageBreak())

        return elements

    def generate_executive_summary(self, data: Dict[str, Any]) -> List:
        """
        Generate executive summary section.

        Args:
            data: Summary statistics

        Returns:
            List of reportlab flowables
        """
        elements = []

        # Section header
        elements.append(Paragraph("Executive Summary", self.styles["SectionHeader"]))
        elements.append(Spacer(1, 0.2 * inch))

        # Overview text
        total_targets = data.get("total_targets", 0)
        total_findings = data.get("total_findings", 0)
        critical_count = data.get("critical_count", 0)

        overview = f"""
        This report presents the results of a comprehensive security assessment 
        conducted on {total_targets} target{'s' if total_targets != 1 else ''}. 
        The assessment identified {total_findings} security finding{'s' if total_findings != 1 else ''}, 
        including {critical_count} critical vulnerabilit{'ies' if critical_count != 1 else 'y'} 
        that require immediate attention.
        """

        elements.append(Paragraph(overview, self.styles["BodyText"]))
        elements.append(Spacer(1, 0.3 * inch))

        # Risk Score Gauge
        try:
            risk_chart = self._generate_risk_gauge(data.get("risk_score", 0))
            elements.append(Image(risk_chart, width=4 * inch, height=2 * inch))
            elements.append(Spacer(1, 0.3 * inch))
        except Exception as e:
            logger.error(f"Failed to generate risk gauge: {e}")

        # Key Findings Summary Table
        elements.append(Paragraph("Key Findings", self.styles["Heading3"]))

        findings_data = [
            ["Severity", "Count", "Percentage"],
            ["Critical", str(data.get("critical_count", 0)), f"{data.get('critical_pct', 0):.1f}%"],
            ["High", str(data.get("high_count", 0)), f"{data.get('high_pct', 0):.1f}%"],
            ["Medium", str(data.get("medium_count", 0)), f"{data.get('medium_pct', 0):.1f}%"],
            ["Low", str(data.get("low_count", 0)), f"{data.get('low_pct', 0):.1f}%"],
            ["Info", str(data.get("info_count", 0)), f"{data.get('info_pct', 0):.1f}%"],
        ]

        findings_table = Table(findings_data, colWidths=[2 * inch, 1.5 * inch, 1.5 * inch])
        findings_table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#34495e")),
                    ("TEXTCOLOR", (0, 0), (-1, 0), colors.whitesmoke),
                    ("ALIGN", (0, 0), (-1, -1), "CENTER"),
                    ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                    ("FONTSIZE", (0, 0), (-1, 0), 12),
                    ("BOTTOMPADDING", (0, 0), (-1, 0), 12),
                    ("TOPPADDING", (0, 0), (-1, 0), 12),
                    ("BACKGROUND", (0, 1), (-1, -1), colors.beige),
                    ("GRID", (0, 0), (-1, -1), 1, colors.black),
                    (
                        "ROWBACKGROUNDS",
                        (0, 1),
                        (-1, -1),
                        [colors.white, colors.HexColor("#f8f9fa")],
                    ),
                ]
            )
        )

        elements.append(findings_table)
        elements.append(Spacer(1, 0.3 * inch))

        # Severity distribution chart
        try:
            severity_chart = self._generate_severity_distribution_chart(data)
            if severity_chart:
                elements.append(Image(severity_chart, width=4 * inch, height=4 * inch))
        except Exception as e:
            logger.error(f"Failed to generate severity chart: {e}")

        elements.append(PageBreak())

        return elements

    def generate_findings_section(
        self, findings: List[Dict], target_info: Optional[Dict] = None
    ) -> List:
        """
        Generate detailed findings section.

        Args:
            findings: List of findings
            target_info: Optional target information

        Returns:
            List of reportlab flowables
        """
        elements = []

        elements.append(Paragraph("Detailed Findings", self.styles["SectionHeader"]))
        elements.append(Spacer(1, 0.2 * inch))

        if not findings:
            elements.append(Paragraph("No findings to report.", self.styles["BodyText"]))
            return elements

        # Group findings by severity
        grouped = self._group_findings_by_severity(findings)

        for severity in ["critical", "high", "medium", "low", "info"]:
            if severity not in grouped or not grouped[severity]:
                continue

            # Severity header
            severity_color = self._get_severity_color(severity)
            elements.append(
                Paragraph(
                    f'{severity.upper()} Severity Findings ({len(grouped[severity])})',
                    self.styles["Heading3"],
                )
            )
            elements.append(Spacer(1, 0.1 * inch))

            # Each finding
            for idx, finding in enumerate(grouped[severity], 1):
                finding_elements = self._generate_finding_block(finding, idx, severity_color)
                elements.extend(finding_elements)
                elements.append(Spacer(1, 0.3 * inch))

        return elements

    def _generate_finding_block(
        self, finding: Dict[str, Any], index: int, color: str
    ) -> List:
        """
        Generate block for a single finding.

        Args:
            finding: Finding data
            index: Finding index
            color: Severity color

        Returns:
            List of reportlab flowables
        """
        elements = []

        # Finding title with severity badge
        title_text = f"<b>{index}. {finding.get('title', 'Untitled Finding')}</b>"
        elements.append(Paragraph(title_text, self.styles["Heading4"]))
        elements.append(Spacer(1, 0.1 * inch))

        # Info table
        info_data = [
            ["Type:", finding.get("finding_type", "Unknown")],
            ["Affected:", finding.get("affected_component", "N/A")],
            ["Confidence:", f"{finding.get('confidence', 0)*100:.0f}%"],
        ]

        if finding.get("cve_id"):
            info_data.append(["CVE:", finding["cve_id"]])
        if finding.get("cwe_id"):
            info_data.append(["CWE:", finding["cwe_id"]])
        if finding.get("cvss_score"):
            info_data.append(["CVSS Score:", str(finding["cvss_score"])])

        info_table = Table(info_data, colWidths=[1.5 * inch, 4.5 * inch])
        info_table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#ecf0f1")),
                    ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
                    ("FONTSIZE", (0, 0), (-1, -1), 9),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
                    ("TOPPADDING", (0, 0), (-1, -1), 6),
                    ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
                ]
            )
        )
        elements.append(info_table)
        elements.append(Spacer(1, 0.1 * inch))

        # Description
        elements.append(Paragraph("<b>Description:</b>", self.styles["Heading5"]))
        description = finding.get("description", "No description available.")
        elements.append(Paragraph(description, self.styles["BodyText"]))
        elements.append(Spacer(1, 0.1 * inch))

        # Evidence (if available)
        if finding.get("evidence"):
            elements.append(Paragraph("<b>Evidence:</b>", self.styles["Heading5"]))
            evidence_text = self._format_evidence(finding["evidence"])
            elements.append(Paragraph(evidence_text, self.styles["Code"]))
            elements.append(Spacer(1, 0.1 * inch))

        # Remediation
        if finding.get("remediation"):
            elements.append(Paragraph("<b>Remediation:</b>", self.styles["Heading5"]))
            elements.append(Paragraph(finding["remediation"], self.styles["Remediation"]))
            elements.append(Spacer(1, 0.1 * inch))

        # References
        if finding.get("references"):
            elements.append(Paragraph("<b>References:</b>", self.styles["Heading5"]))
            refs = ", ".join(finding["references"][:5])  # Limit to 5 references
            elements.append(Paragraph(refs, self.styles["BodyText"]))

        # Wrap in bordered box
        try:
            box_elements = KeepTogether(elements)
            return [box_elements]
        except:
            # If KeepTogether fails, return elements as-is
            return elements

    def _generate_risk_gauge(self, risk_score: float) -> BytesIO:
        """
        Generate gauge chart for risk score.

        Args:
            risk_score: Risk score (0-10)

        Returns:
            BytesIO buffer with PNG image
        """
        fig, ax = plt.subplots(figsize=(6, 3))

        # Create gauge
        categories = ["Low", "Medium", "High", "Critical"]
        colors_list = ["#2ecc71", "#f39c12", "#e74c3c", "#c0392b"]

        # Draw gauge segments
        theta = np.linspace(0, np.pi, 100)
        for i, (cat, color) in enumerate(zip(categories, colors_list)):
            start = i * 2.5
            end = (i + 1) * 2.5
            segment_theta = theta[(theta >= start / 10 * np.pi) & (theta <= end / 10 * np.pi)]
            r = 1
            ax.plot(
                r * np.cos(segment_theta),
                r * np.sin(segment_theta),
                color=color,
                linewidth=20,
            )

        # Draw needle
        angle = (risk_score / 10) * np.pi
        ax.arrow(
            0,
            0,
            0.8 * np.cos(angle),
            0.8 * np.sin(angle),
            head_width=0.1,
            head_length=0.1,
            fc="black",
            ec="black",
        )

        # Score text
        ax.text(
            0,
            -0.3,
            f"{risk_score:.1f}/10",
            ha="center",
            va="center",
            fontsize=20,
            fontweight="bold",
        )

        ax.set_xlim(-1.2, 1.2)
        ax.set_ylim(-0.5, 1.2)
        ax.axis("off")

        # Save to BytesIO
        buf = BytesIO()
        plt.savefig(buf, format="png", dpi=150, bbox_inches="tight")
        buf.seek(0)
        plt.close()

        return buf

    def _generate_severity_distribution_chart(self, data: Dict[str, Any]) -> Optional[BytesIO]:
        """
        Generate pie chart for findings distribution.

        Args:
            data: Summary data with counts

        Returns:
            BytesIO buffer with PNG image or None
        """
        labels = ["Critical", "High", "Medium", "Low", "Info"]
        sizes = [
            data.get("critical_count", 0),
            data.get("high_count", 0),
            data.get("medium_count", 0),
            data.get("low_count", 0),
            data.get("info_count", 0),
        ]
        colors_list = ["#c0392b", "#e74c3c", "#f39c12", "#f1c40f", "#3498db"]

        # Filter out zero values
        filtered_data = [(l, s, c) for l, s, c in zip(labels, sizes, colors_list) if s > 0]
        if not filtered_data:
            return None

        labels, sizes, colors_list = zip(*filtered_data)

        fig, ax = plt.subplots(figsize=(6, 6))
        ax.pie(
            sizes,
            labels=labels,
            colors=colors_list,
            autopct="%1.1f%%",
            startangle=90,
            textprops={"fontsize": 12},
        )
        ax.axis("equal")

        plt.title("Findings Distribution by Severity", fontsize=14, fontweight="bold")

        buf = BytesIO()
        plt.savefig(buf, format="png", dpi=150, bbox_inches="tight")
        buf.seek(0)
        plt.close()

        return buf

    def generate_technical_report(self, scan_id: str, data: Dict[str, Any]) -> str:
        """
        Generate complete technical report.

        Args:
            scan_id: Scan UUID
            data: Complete scan data

        Returns:
            Path to generated PDF file
        """
        import os
        os.makedirs("/tmp/reports/technical", exist_ok=True)
        output_path = f"/tmp/reports/technical/{scan_id}_technical.pdf"

        doc = SimpleDocTemplate(
            output_path,
            pagesize=letter,
            rightMargin=0.75 * inch,
            leftMargin=0.75 * inch,
            topMargin=1 * inch,
            bottomMargin=0.75 * inch,
        )

        elements = []

        # Cover page
        elements.extend(self.generate_cover_page(data.get("scan_info", {})))

        # Executive Summary
        elements.extend(self.generate_executive_summary(data.get("summary", {})))

        # Findings
        elements.extend(
            self.generate_findings_section(
                data.get("findings", []), data.get("target_info")
            )
        )

        # Appendices
        elements.append(PageBreak())
        elements.append(Paragraph("Appendices", self.styles["SectionHeader"]))
        elements.append(Paragraph("A. Scan Configuration", self.styles["Heading3"]))
        
        # Add scan configuration details
        config_data = data.get("scan_info", {}).get("pipeline_config", {})
        if config_data:
            config_text = f"<font name='Courier' size='8'>{str(config_data)[:500]}</font>"
            elements.append(Paragraph(config_text, self.styles["Code"]))

        # Build PDF
        try:
            doc.build(elements)
            logger.info(f"Generated technical report: {output_path}")
            return output_path
        except Exception as e:
            logger.error(f"Failed to build technical report: {e}", exc_info=True)
            raise

    def generate_executive_report(self, scan_id: str, data: Dict[str, Any]) -> str:
        """
        Generate executive summary report for management.

        Args:
            scan_id: Scan UUID
            data: Complete scan data

        Returns:
            Path to generated PDF file
        """
        import os
        os.makedirs("/tmp/reports/executive", exist_ok=True)
        output_path = f"/tmp/reports/executive/{scan_id}_executive.pdf"

        doc = SimpleDocTemplate(output_path, pagesize=letter)
        elements = []

        # Cover
        elements.extend(self.generate_cover_page(data.get("scan_info", {})))

        # Executive Summary (more detailed)
        elements.extend(self.generate_executive_summary(data.get("summary", {})))

        # Risk Assessment
        elements.append(Paragraph("Risk Assessment", self.styles["SectionHeader"]))
        elements.append(Spacer(1, 0.2 * inch))

        # Severity distribution chart
        try:
            severity_chart = self._generate_severity_distribution_chart(data.get("summary", {}))
            if severity_chart:
                elements.append(Image(severity_chart, width=4 * inch, height=4 * inch))
        except Exception as e:
            logger.error(f"Failed to generate chart: {e}")

        elements.append(Spacer(1, 0.3 * inch))

        # Top Critical Findings (only top 5)
        elements.append(Paragraph("Top Critical Issues", self.styles["Heading3"]))
        critical_findings = [f for f in data.get("findings", []) if f.get("severity") == "critical"][:5]

        for idx, finding in enumerate(critical_findings, 1):
            elements.append(
                Paragraph(f"<b>{idx}. {finding.get('title', 'Untitled')}</b>", self.styles["Heading4"])
            )
            desc = finding.get("description", "No description")[:200] + "..."
            elements.append(Paragraph(desc, self.styles["BodyText"]))
            elements.append(Spacer(1, 0.1 * inch))

        # Recommendations
        elements.append(PageBreak())
        elements.append(Paragraph("Recommendations", self.styles["SectionHeader"]))
        
        recommendations = [
            "1. Address all critical vulnerabilities within 24-48 hours",
            "2. Implement security patches for high severity findings within 1 week",
            "3. Conduct regular security assessments (quarterly recommended)",
            "4. Implement security awareness training for development team",
            "5. Review and update security policies based on findings",
        ]
        
        for rec in recommendations:
            elements.append(Paragraph(rec, self.styles["BodyText"]))
            elements.append(Spacer(1, 0.05 * inch))

        # Build PDF
        try:
            doc.build(elements)
            logger.info(f"Generated executive report: {output_path}")
            return output_path
        except Exception as e:
            logger.error(f"Failed to build executive report: {e}", exc_info=True)
            raise

    def generate_individual_target_report(
        self, scan_id: str, target_id: str, data: Dict[str, Any]
    ) -> str:
        """
        Generate report for a single target.

        Args:
            scan_id: Scan UUID
            target_id: Target UUID
            data: Target data with findings

        Returns:
            Path to generated PDF file
        """
        import os
        os.makedirs(f"/tmp/reports/individual/{scan_id}", exist_ok=True)
        output_path = f"/tmp/reports/individual/{scan_id}/{target_id}.pdf"

        doc = SimpleDocTemplate(output_path, pagesize=letter)
        elements = []

        # Target info header
        target_value = data.get("target", {}).get("normalized_value", "Unknown Target")
        elements.append(
            Paragraph(
                f"Target Assessment Report: {target_value}", self.styles["CustomTitle"]
            )
        )
        elements.append(Spacer(1, 0.3 * inch))

        # Target metadata
        metadata = [
            ["Target Type:", data.get("target", {}).get("target_type", "Unknown")],
            ["Scan Date:", data.get("scan_date", datetime.utcnow().strftime("%Y-%m-%d"))],
            ["Total Findings:", str(len(data.get("findings", [])))],
            ["Risk Score:", f"{data.get('risk_score', 0):.1f}/10"],
        ]

        # Add technologies if available
        technologies = data.get("target", {}).get("classification", {}).get("technologies", [])
        if technologies:
            metadata.append(["Technologies:", ", ".join(technologies[:5])])

        table = Table(metadata, colWidths=[2 * inch, 4 * inch])
        table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#ecf0f1")),
                    ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
                    ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
                    ("TOPPADDING", (0, 0), (-1, -1), 8),
                ]
            )
        )
        elements.append(table)
        elements.append(Spacer(1, 0.3 * inch))

        # Findings for this target
        elements.extend(
            self.generate_findings_section(data.get("findings", []), data.get("target"))
        )

        # Build PDF
        try:
            doc.build(elements)
            logger.info(f"Generated individual target report: {output_path}")
            return output_path
        except Exception as e:
            logger.error(f"Failed to build individual report: {e}", exc_info=True)
            raise

    def _get_severity_color(self, severity: str) -> str:
        """Get hex color for severity level."""
        colors_map = {
            "critical": "#c0392b",
            "high": "#e74c3c",
            "medium": "#f39c12",
            "low": "#f1c40f",
            "info": "#3498db",
        }
        return colors_map.get(severity.lower(), "#95a5a6")

    def _group_findings_by_severity(self, findings: List[Dict]) -> Dict[str, List]:
        """Group findings by severity level."""
        grouped = {}
        for finding in findings:
            severity = finding.get("severity", "info").lower()
            if severity not in grouped:
                grouped[severity] = []
            grouped[severity].append(finding)
        return grouped

    def _format_evidence(self, evidence: Dict[str, Any]) -> str:
        """Format evidence for display in report."""
        formatted = []

        if evidence.get("request"):
            request_str = str(evidence["request"])[:500]
            formatted.append(
                f"<b>Request:</b><br/><font name='Courier' size='8'>{request_str}</font>"
            )

        if evidence.get("response"):
            response_str = str(evidence["response"])[:500]
            formatted.append(
                f"<b>Response:</b><br/><font name='Courier' size='8'>{response_str}</font>"
            )

        if evidence.get("proof"):
            proof_str = str(evidence["proof"])
            formatted.append(
                f"<b>Proof:</b><br/><font name='Courier' size='8'>{proof_str}</font>"
            )

        return "<br/><br/>".join(formatted) if formatted else "No evidence available"
