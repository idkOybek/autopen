"""Target management endpoints."""

from typing import List

from fastapi import APIRouter, Depends, File, HTTPException, UploadFile
from loguru import logger

from backend.api.schemas.target import (
    TargetClassification,
    TargetClassifyRequest,
    TargetValidation,
    TargetValidateRequest,
    TargetUploadResponse,
)
from backend.core.target_classifier import TargetClassifier
from backend.models.target import TargetType

router = APIRouter()


@router.post("/classify", response_model=List[TargetClassification])
async def classify_targets(request: TargetClassifyRequest):
    """
    Classify target types and recommend scanning tools.

    Args:
        request: List of targets to classify

    Returns:
        Classification results for each target

    Example:
        ```json
        {
            "targets": [
                "https://example.com",
                "192.168.1.1",
                "10.0.0.0/24"
            ]
        }
        ```

        Response:
        ```json
        [
            {
                "raw_value": "https://example.com",
                "normalized_value": "https://example.com",
                "target_type": "web",
                "confidence": 1.0,
                "classification": {...},
                "recommended_tools": ["nuclei", "nikto", "gobuster"]
            }
        ]
        ```
    """
    try:
        classifier = TargetClassifier()
        results = []

        for target in request.targets:
            classification = classifier.classify_target(target)
            normalized = classifier.normalize_target(target, classification["type"])
            enriched = classifier.enrich_target(classification)
            recommended_tools = classifier.get_tools_for_target(classification["type"])

            results.append(
                TargetClassification(
                    raw_value=target,
                    normalized_value=normalized,
                    target_type=classification["type"],
                    confidence=classification.get("confidence", 0.8),
                    classification=enriched,
                    recommended_tools=recommended_tools,
                )
            )

        return results

    except Exception as e:
        logger.error(f"Error classifying targets: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Classification failed: {str(e)}")


@router.post("/validate", response_model=List[TargetValidation])
async def validate_targets(request: TargetValidateRequest):
    """
    Validate target formats and check for common issues.

    Args:
        request: List of targets to validate

    Returns:
        Validation results for each target

    Example:
        Response:
        ```json
        [
            {
                "target": "https://example.com",
                "valid": true,
                "errors": [],
                "warnings": []
            },
            {
                "target": "invalid target",
                "valid": false,
                "errors": ["Could not determine target type"],
                "warnings": []
            }
        ]
        ```
    """
    try:
        classifier = TargetClassifier()
        results = []

        for target in request.targets:
            errors = []
            warnings = []

            # Try to classify
            try:
                classification = classifier.classify_target(target)

                # Check for warnings
                if classification.get("confidence", 0) < 0.5:
                    warnings.append("Low confidence in target type classification")

            except Exception as e:
                errors.append(f"Could not determine target type: {str(e)}")

            results.append(
                TargetValidation(
                    target=target,
                    valid=len(errors) == 0,
                    errors=errors,
                    warnings=warnings,
                )
            )

        return results

    except Exception as e:
        logger.error(f"Error validating targets: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Validation failed: {str(e)}")


@router.get("/types")
async def get_target_types():
    """
    Get list of all supported target types.

    Returns:
        Dictionary of target types and their descriptions

    Example:
        Response:
        ```json
        {
            "types": {
                "web": "Web applications and websites",
                "api": "REST APIs and web services",
                "ip": "Individual IP addresses",
                ...
            }
        }
        ```
    """
    type_descriptions = {
        TargetType.WEB.value: "Web applications and websites",
        TargetType.API.value: "REST APIs and web services",
        TargetType.IP.value: "Individual IP addresses",
        TargetType.DOMAIN.value: "Domain names",
        TargetType.NETWORK.value: "Network ranges (CIDR notation)",
        TargetType.CLOUD.value: "Cloud infrastructure endpoints",
        TargetType.DATABASE.value: "Database servers",
        TargetType.SSH.value: "SSH services",
        TargetType.SMTP.value: "SMTP mail servers",
        TargetType.FTP.value: "FTP servers",
        TargetType.RDP.value: "RDP services",
        TargetType.IOT.value: "IoT devices",
        TargetType.MOBILE_APP.value: "Mobile applications",
    }

    return {"types": type_descriptions}


@router.post("/upload", response_model=TargetUploadResponse)
async def upload_targets(file: UploadFile = File(...)):
    """
    Upload a file containing targets (one per line).

    Args:
        file: Text file with targets

    Returns:
        Upload statistics

    Example:
        Upload a text file with:
        ```
        https://example.com
        192.168.1.1
        10.0.0.0/24
        ```

        Response:
        ```json
        {
            "total_uploaded": 3,
            "valid_targets": 3,
            "invalid_targets": 0,
            "errors": []
        }
        ```
    """
    try:
        # Read file content
        content = await file.read()
        content_str = content.decode("utf-8")

        # Parse targets (one per line)
        lines = content_str.strip().split("\n")
        raw_targets = [line.strip() for line in lines if line.strip()]

        # Validate targets
        classifier = TargetClassifier()
        valid_targets = []
        invalid_targets = []
        errors = []

        for target in raw_targets:
            try:
                classification = classifier.classify_target(target)
                valid_targets.append(target)
            except Exception as e:
                invalid_targets.append(target)
                errors.append(f"{target}: {str(e)}")

        return TargetUploadResponse(
            total_uploaded=len(raw_targets),
            valid_targets=len(valid_targets),
            invalid_targets=len(invalid_targets),
            errors=errors,
        )

    except Exception as e:
        logger.error(f"Error uploading targets: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Upload failed: {str(e)}")


@router.get("/ftp/sync")
async def sync_ftp_targets():
    """
    Synchronize targets from configured FTP server.

    Returns:
        Synchronization status

    Example:
        Response:
        ```json
        {
            "status": "success",
            "targets_fetched": 150,
            "timestamp": "2024-01-01T00:00:00Z"
        }
        ```
    """
    try:
        from datetime import datetime
        from backend.integrations.ftp_client import FTPClient
        from backend.core.config import settings

        # Connect to FTP and fetch targets
        ftp_client = FTPClient()
        await ftp_client.connect()

        # Fetch from configured path
        targets_path = settings.FTP_REPORTS_DIR + "/targets.txt"
        targets = await ftp_client.fetch_targets(targets_path)

        await ftp_client.disconnect()

        return {
            "status": "success",
            "targets_fetched": len(targets),
            "timestamp": datetime.utcnow().isoformat(),
        }

    except Exception as e:
        logger.error(f"Error syncing FTP targets: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"FTP sync failed: {str(e)}")
