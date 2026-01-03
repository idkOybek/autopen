"""Unit tests for PDF report generator."""

import os
from datetime import datetime
from uuid import uuid4

import pytest

from backend.reports.pdf_generator import PDFReportGenerator


@pytest.fixture
def pdf_generator():
    """Create PDF generator instance."""
    return PDFReportGenerator()


@pytest.fixture
def sample_scan_data():
    """Sample scan data for testing."""
    return {
        "scan_info": {
            "id": str(uuid4()),
            "name": "Test Security Scan",
            "description": "Test scan description",
            "date": datetime.utcnow(),
            "duration": 45.5,
            "total_targets": 10,
            "total_findings": 25,
            "risk_score": 7.5,
            "pipeline_config": {"stages": []},
        },
        "summary": {
            "total_targets": 10,
            "total_findings": 25,
            "critical_count": 5,
            "high_count": 8,
            "medium_count": 7,
            "low_count": 3,
            "info_count": 2,
            "critical_pct": 20.0,
            "high_pct": 32.0,
            "medium_pct": 28.0,
            "low_pct": 12.0,
            "info_pct": 8.0,
            "risk_score": 7.5,
        },
        "findings": [
            {
                "id": str(uuid4()),
                "title": "SQL Injection Vulnerability",
                "description": "SQL injection found in login form",
                "severity": "critical",
                "finding_type": "SQLi",
                "cve_id": "CVE-2024-1234",
                "cwe_id": "CWE-89",
                "cvss_score": 9.8,
                "evidence": {"request": "GET /login?user=admin' OR '1'='1", "response": "200 OK"},
                "remediation": "Use parameterized queries",
                "remediation_effort": "medium",
                "references": ["https://owasp.org/www-community/attacks/SQL_Injection"],
                "confidence": 0.95,
                "affected_component": "/login",
            },
            {
                "id": str(uuid4()),
                "title": "Cross-Site Scripting (XSS)",
                "description": "Reflected XSS in search parameter",
                "severity": "high",
                "finding_type": "XSS",
                "cve_id": None,
                "cwe_id": "CWE-79",
                "cvss_score": 7.5,
                "evidence": {"proof": "<script>alert('XSS')</script>"},
                "remediation": "Sanitize user input and encode output",
                "remediation_effort": "low",
                "references": ["https://owasp.org/www-community/attacks/xss/"],
                "confidence": 0.90,
                "affected_component": "/search",
            },
        ],
        "targets": [],
        "target_info": {"total": 10, "types": ["web", "api"]},
    }


def test_pdf_generator_init(pdf_generator):
    """Test PDF generator initialization."""
    assert pdf_generator is not None
    assert pdf_generator.styles is not None
    assert "CustomTitle" in pdf_generator.styles
    assert "SectionHeader" in pdf_generator.styles


def test_generate_cover_page(pdf_generator, sample_scan_data):
    """Test cover page generation."""
    elements = pdf_generator.generate_cover_page(sample_scan_data["scan_info"])
    
    assert len(elements) > 0
    # Should have title, metadata table, and page break
    assert any("Security Assessment Report" in str(e) for e in elements if hasattr(e, "text"))


def test_generate_executive_summary(pdf_generator, sample_scan_data):
    """Test executive summary generation."""
    elements = pdf_generator.generate_executive_summary(sample_scan_data["summary"])
    
    assert len(elements) > 0
    # Should have section header, overview, and stats table
    assert any("Executive Summary" in str(e) for e in elements if hasattr(e, "text"))


def test_generate_findings_section(pdf_generator, sample_scan_data):
    """Test findings section generation."""
    elements = pdf_generator.generate_findings_section(
        sample_scan_data["findings"], sample_scan_data["target_info"]
    )
    
    assert len(elements) > 0
    # Should have findings header and finding cards
    assert any("Detailed Findings" in str(e) for e in elements if hasattr(e, "text"))


def test_group_findings_by_severity(pdf_generator, sample_scan_data):
    """Test grouping findings by severity."""
    grouped = pdf_generator._group_findings_by_severity(sample_scan_data["findings"])
    
    assert "critical" in grouped
    assert "high" in grouped
    assert len(grouped["critical"]) == 1
    assert len(grouped["high"]) == 1


def test_get_severity_color(pdf_generator):
    """Test severity color mapping."""
    assert pdf_generator._get_severity_color("critical") == "#c0392b"
    assert pdf_generator._get_severity_color("high") == "#e74c3c"
    assert pdf_generator._get_severity_color("medium") == "#f39c12"
    assert pdf_generator._get_severity_color("low") == "#f1c40f"
    assert pdf_generator._get_severity_color("info") == "#3498db"


def test_format_evidence(pdf_generator):
    """Test evidence formatting."""
    evidence = {
        "request": "GET /test",
        "response": "200 OK",
        "proof": "Exploit successful",
    }
    
    formatted = pdf_generator._format_evidence(evidence)
    
    assert "Request:" in formatted
    assert "Response:" in formatted
    assert "Proof:" in formatted


def test_generate_technical_report(pdf_generator, sample_scan_data):
    """Test technical report generation."""
    scan_id = str(uuid4())
    
    report_path = pdf_generator.generate_technical_report(scan_id, sample_scan_data)
    
    assert report_path is not None
    assert report_path.endswith(".pdf")
    assert os.path.exists(report_path)
    
    # Cleanup
    os.remove(report_path)


def test_generate_executive_report(pdf_generator, sample_scan_data):
    """Test executive report generation."""
    scan_id = str(uuid4())
    
    report_path = pdf_generator.generate_executive_report(scan_id, sample_scan_data)
    
    assert report_path is not None
    assert report_path.endswith(".pdf")
    assert os.path.exists(report_path)
    
    # Cleanup
    os.remove(report_path)


def test_generate_individual_target_report(pdf_generator):
    """Test individual target report generation."""
    scan_id = str(uuid4())
    target_id = str(uuid4())
    
    target_data = {
        "target": {
            "id": target_id,
            "normalized_value": "https://example.com",
            "target_type": "web",
            "status": "completed",
            "classification": {"technologies": ["nginx", "php"]},
        },
        "scan_date": "2024-01-01 12:00",
        "risk_score": 6.5,
        "findings": [
            {
                "id": str(uuid4()),
                "title": "Test Finding",
                "description": "Test description",
                "severity": "medium",
                "finding_type": "test",
                "cve_id": None,
                "cwe_id": None,
                "cvss_score": None,
                "evidence": {},
                "remediation": "Fix it",
                "references": [],
                "confidence": 0.8,
                "affected_component": "test",
            }
        ],
    }
    
    report_path = pdf_generator.generate_individual_target_report(
        scan_id, target_id, target_data
    )
    
    assert report_path is not None
    assert report_path.endswith(".pdf")
    assert os.path.exists(report_path)
    
    # Cleanup
    os.remove(report_path)
