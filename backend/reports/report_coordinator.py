"""Report coordination and data fetching."""

from datetime import datetime
from typing import Any, Dict, List
from uuid import UUID

from loguru import logger
from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession

from backend.models.finding import Finding, Severity
from backend.models.scan import Scan
from backend.models.target import Target
from backend.reports.pdf_generator import PDFReportGenerator


class ReportCoordinator:
    """
    Coordinates generation of all report types.
    
    Fetches data from database and delegates to PDF generator.
    """

    def __init__(self, db_session: AsyncSession):
        """
        Initialize report coordinator.

        Args:
            db_session: Database session
        """
        self.db = db_session
        self.pdf_generator = PDFReportGenerator()

    async def generate_all_reports(self, scan_id: str) -> Dict[str, Any]:
        """
        Generate all report types for a scan.

        Args:
            scan_id: Scan UUID

        Returns:
            Dictionary with paths to all generated reports
        """
        logger.info(f"Generating all reports for scan {scan_id}")

        try:
            # Fetch complete scan data
            scan_data = await self._fetch_scan_data(scan_id)

            # Technical report
            technical_path = self.pdf_generator.generate_technical_report(
                scan_id, scan_data
            )

            # Executive report
            executive_path = self.pdf_generator.generate_executive_report(
                scan_id, scan_data
            )

            # Individual reports for each target
            individual_paths = []
            for target in scan_data.get("targets", []):
                target_data = await self._fetch_target_data(scan_id, str(target["id"]))
                path = self.pdf_generator.generate_individual_target_report(
                    scan_id, str(target["id"]), target_data
                )
                individual_paths.append(path)

            result = {
                "technical": technical_path,
                "executive": executive_path,
                "individual": individual_paths,
                "generated_at": datetime.utcnow().isoformat(),
            }

            logger.info(f"Successfully generated all reports for scan {scan_id}")
            return result

        except Exception as e:
            logger.error(f"Error generating reports for scan {scan_id}: {e}", exc_info=True)
            raise

    async def _fetch_scan_data(self, scan_id: str) -> Dict[str, Any]:
        """
        Fetch complete scan data for report generation.

        Args:
            scan_id: Scan UUID

        Returns:
            Dictionary with scan info, summary, findings, and targets
        """
        logger.info(f"Fetching scan data for {scan_id}")

        # Get scan
        scan = await self.db.get(Scan, UUID(scan_id))
        if not scan:
            raise ValueError(f"Scan {scan_id} not found")

        # Get all targets
        targets_result = await self.db.execute(
            select(Target).where(Target.scan_id == UUID(scan_id))
        )
        targets = targets_result.scalars().all()

        # Get all findings
        findings_result = await self.db.execute(
            select(Finding).where(Finding.scan_id == UUID(scan_id))
        )
        findings = findings_result.scalars().all()

        # Calculate statistics
        total_findings = len(findings)
        severity_counts = {
            "critical": sum(1 for f in findings if f.severity == Severity.CRITICAL),
            "high": sum(1 for f in findings if f.severity == Severity.HIGH),
            "medium": sum(1 for f in findings if f.severity == Severity.MEDIUM),
            "low": sum(1 for f in findings if f.severity == Severity.LOW),
            "info": sum(1 for f in findings if f.severity == Severity.INFO),
        }

        # Calculate percentages
        severity_pcts = {}
        for severity, count in severity_counts.items():
            pct = (count / total_findings * 100) if total_findings > 0 else 0
            severity_pcts[f"{severity}_pct"] = pct

        # Calculate risk score (weighted by severity)
        weights = {"critical": 10, "high": 7, "medium": 4, "low": 2, "info": 1}
        total_weight = sum(severity_counts[sev] * weights[sev] for sev in weights)
        max_weight = total_findings * 10 if total_findings > 0 else 1
        risk_score = (total_weight / max_weight * 10) if total_findings > 0 else 0

        # Calculate duration
        duration = 0
        if scan.started_at and scan.completed_at:
            duration = (scan.completed_at - scan.started_at).total_seconds() / 60  # minutes

        # Build scan data structure
        scan_data = {
            "scan_info": {
                "id": str(scan.id),
                "name": scan.name,
                "description": scan.description,
                "date": scan.created_at,
                "duration": duration,
                "total_targets": len(targets),
                "total_findings": total_findings,
                "risk_score": risk_score,
                "pipeline_config": scan.pipeline_config,
            },
            "summary": {
                "total_targets": len(targets),
                "total_findings": total_findings,
                "critical_count": severity_counts["critical"],
                "high_count": severity_counts["high"],
                "medium_count": severity_counts["medium"],
                "low_count": severity_counts["low"],
                "info_count": severity_counts["info"],
                **severity_pcts,
                "risk_score": risk_score,
            },
            "findings": [
                {
                    "id": str(f.id),
                    "title": f.title,
                    "description": f.description,
                    "severity": f.severity.value,
                    "finding_type": f.finding_type,
                    "cve_id": f.cve_id,
                    "cwe_id": f.cwe_id,
                    "cvss_score": f.cvss_score,
                    "evidence": f.evidence,
                    "remediation": f.remediation,
                    "remediation_effort": f.remediation_effort.value if f.remediation_effort else None,
                    "references": f.references or [],
                    "confidence": f.confidence,
                    "affected_component": self._get_affected_component(f),
                }
                for f in findings
            ],
            "targets": [
                {
                    "id": str(t.id),
                    "value": t.normalized_value,
                    "type": t.target_type.value,
                    "status": t.status.value,
                    "classification": t.classification,
                }
                for t in targets
            ],
            "target_info": {
                "total": len(targets),
                "types": list(set(t.target_type.value for t in targets)),
            },
        }

        return scan_data

    async def _fetch_target_data(self, scan_id: str, target_id: str) -> Dict[str, Any]:
        """
        Fetch data for a single target.

        Args:
            scan_id: Scan UUID
            target_id: Target UUID

        Returns:
            Dictionary with target info and findings
        """
        logger.info(f"Fetching target data for {target_id}")

        # Get target
        target = await self.db.get(Target, UUID(target_id))
        if not target or str(target.scan_id) != scan_id:
            raise ValueError(f"Target {target_id} not found in scan {scan_id}")

        # Get findings for this target
        findings_result = await self.db.execute(
            select(Finding).where(Finding.target_id == UUID(target_id))
        )
        findings = findings_result.scalars().all()

        # Calculate risk score for this target
        total_findings = len(findings)
        weights = {"critical": 10, "high": 7, "medium": 4, "low": 2, "info": 1}
        severity_counts = {
            "critical": sum(1 for f in findings if f.severity == Severity.CRITICAL),
            "high": sum(1 for f in findings if f.severity == Severity.HIGH),
            "medium": sum(1 for f in findings if f.severity == Severity.MEDIUM),
            "low": sum(1 for f in findings if f.severity == Severity.LOW),
            "info": sum(1 for f in findings if f.severity == Severity.INFO),
        }

        total_weight = sum(severity_counts[sev] * weights[sev] for sev in weights)
        max_weight = total_findings * 10 if total_findings > 0 else 1
        risk_score = (total_weight / max_weight * 10) if total_findings > 0 else 0

        target_data = {
            "target": {
                "id": str(target.id),
                "normalized_value": target.normalized_value,
                "target_type": target.target_type.value,
                "status": target.status.value,
                "classification": target.classification,
            },
            "scan_date": target.created_at.strftime("%Y-%m-%d %H:%M"),
            "risk_score": risk_score,
            "findings": [
                {
                    "id": str(f.id),
                    "title": f.title,
                    "description": f.description,
                    "severity": f.severity.value,
                    "finding_type": f.finding_type,
                    "cve_id": f.cve_id,
                    "cwe_id": f.cwe_id,
                    "cvss_score": f.cvss_score,
                    "evidence": f.evidence,
                    "remediation": f.remediation,
                    "references": f.references or [],
                    "confidence": f.confidence,
                    "affected_component": self._get_affected_component(f),
                }
                for f in findings
            ],
        }

        return target_data

    def _get_affected_component(self, finding: Finding) -> str:
        """
        Get affected component from finding evidence.

        Args:
            finding: Finding object

        Returns:
            Affected component string
        """
        # Try to extract from evidence
        if finding.evidence:
            if "url" in finding.evidence:
                return finding.evidence["url"]
            if "component" in finding.evidence:
                return finding.evidence["component"]
            if "path" in finding.evidence:
                return finding.evidence["path"]

        # Fallback to finding type
        return finding.finding_type or "Unknown"

    async def generate_technical_report(self, scan_id: str) -> str:
        """
        Generate technical report only.

        Args:
            scan_id: Scan UUID

        Returns:
            Path to generated report
        """
        scan_data = await self._fetch_scan_data(scan_id)
        return self.pdf_generator.generate_technical_report(scan_id, scan_data)

    async def generate_executive_report(self, scan_id: str) -> str:
        """
        Generate executive report only.

        Args:
            scan_id: Scan UUID

        Returns:
            Path to generated report
        """
        scan_data = await self._fetch_scan_data(scan_id)
        return self.pdf_generator.generate_executive_report(scan_id, scan_data)

    async def generate_target_report(self, scan_id: str, target_id: str) -> str:
        """
        Generate individual target report.

        Args:
            scan_id: Scan UUID
            target_id: Target UUID

        Returns:
            Path to generated report
        """
        target_data = await self._fetch_target_data(scan_id, target_id)
        return self.pdf_generator.generate_individual_target_report(
            scan_id, target_id, target_data
        )
