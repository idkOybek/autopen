"""Deduplicator for targets and findings."""

import hashlib
from typing import Dict, List, Tuple, Any

from loguru import logger


class Deduplicator:
    """Deduplicator for removing duplicate targets and findings."""

    def __init__(self):
        """Initialize the deduplicator."""
        logger.info("Initializing Deduplicator")

    def deduplicate_targets(
        self, targets: List[Dict[str, Any]]
    ) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
        """
        Deduplicate targets.

        Args:
            targets: List of target dictionaries

        Returns:
            Tuple of (unique_targets, duplicates)

        Example:
            >>> deduplicator = Deduplicator()
            >>> targets = [
            ...     {"normalized_value": "example.com", "raw_value": "example.com"},
            ...     {"normalized_value": "example.com", "raw_value": "EXAMPLE.COM"}
            ... ]
            >>> unique, dupes = deduplicator.deduplicate_targets(targets)
            >>> len(unique)
            1
        """
        try:
            logger.info(f"Deduplicating {len(targets)} targets")

            seen_hashes = set()
            unique_targets = []
            duplicates = []

            for target in targets:
                target_hash = self.generate_target_hash(target)

                if target_hash in seen_hashes:
                    logger.debug(f"Duplicate target found: {target.get('normalized_value')}")
                    duplicates.append(target)
                else:
                    seen_hashes.add(target_hash)
                    unique_targets.append(target)

            logger.info(
                f"Deduplicated targets: {len(unique_targets)} unique, "
                f"{len(duplicates)} duplicates"
            )

            return unique_targets, duplicates

        except Exception as e:
            logger.error(f"Error deduplicating targets: {e}")
            return targets, []

    def generate_target_hash(self, target: Dict[str, Any]) -> str:
        """
        Generate a unique hash for a target.

        Args:
            target: Target dictionary

        Returns:
            Hash string

        Example:
            >>> deduplicator = Deduplicator()
            >>> target = {"normalized_value": "example.com", "target_type": "domain"}
            >>> hash1 = deduplicator.generate_target_hash(target)
            >>> hash2 = deduplicator.generate_target_hash(target)
            >>> hash1 == hash2
            True
        """
        try:
            # Use normalized value and target type for hashing
            normalized = target.get("normalized_value", "")
            target_type = target.get("target_type", "")

            # Create hash string
            hash_string = f"{normalized}:{target_type}"

            # Generate MD5 hash
            hash_value = hashlib.md5(hash_string.encode()).hexdigest()

            logger.debug(f"Generated hash for {normalized}: {hash_value}")
            return hash_value

        except Exception as e:
            logger.error(f"Error generating target hash: {e}")
            # Fallback to raw value
            return hashlib.md5(
                str(target.get("raw_value", "")).encode()
            ).hexdigest()

    def deduplicate_findings(
        self, findings: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """
        Deduplicate findings and merge metadata.

        Args:
            findings: List of finding dictionaries

        Returns:
            List of unique findings with merged metadata

        Example:
            >>> deduplicator = Deduplicator()
            >>> findings = [
            ...     {
            ...         "title": "XSS",
            ...         "severity": "high",
            ...         "target_id": "123",
            ...         "affected_component": "/api/user",
            ...         "confidence": 80,
            ...         "sources": {"tool1": True}
            ...     },
            ...     {
            ...         "title": "XSS",
            ...         "severity": "high",
            ...         "target_id": "123",
            ...         "affected_component": "/api/user",
            ...         "confidence": 90,
            ...         "sources": {"tool2": True}
            ...     }
            ... ]
            >>> unique = deduplicator.deduplicate_findings(findings)
            >>> len(unique)
            1
        """
        try:
            logger.info(f"Deduplicating {len(findings)} findings")

            fingerprint_map = {}

            for finding in findings:
                fingerprint = self.generate_finding_fingerprint(finding)

                if fingerprint in fingerprint_map:
                    # Merge with existing
                    logger.debug(
                        f"Duplicate finding found: {finding.get('title')} - "
                        f"{finding.get('affected_component')}"
                    )
                    existing = fingerprint_map[fingerprint]
                    self.merge_finding_metadata(existing, finding)
                else:
                    fingerprint_map[fingerprint] = finding
                    # Store fingerprint in finding
                    finding["fingerprint"] = fingerprint

            unique_findings = list(fingerprint_map.values())

            logger.info(
                f"Deduplicated findings: {len(unique_findings)} unique, "
                f"{len(findings) - len(unique_findings)} merged"
            )

            return unique_findings

        except Exception as e:
            logger.error(f"Error deduplicating findings: {e}")
            return findings

    def generate_finding_fingerprint(self, finding: Dict[str, Any]) -> str:
        """
        Generate a fingerprint for a finding.

        Args:
            finding: Finding dictionary

        Returns:
            Fingerprint string

        Example:
            >>> deduplicator = Deduplicator()
            >>> finding = {
            ...     "title": "SQL Injection",
            ...     "severity": "critical",
            ...     "finding_type": "SQLi",
            ...     "target_id": "abc123",
            ...     "affected_component": "/api/users"
            ... }
            >>> fp = deduplicator.generate_finding_fingerprint(finding)
            >>> isinstance(fp, str)
            True
        """
        try:
            # Components for fingerprint
            title = finding.get("title", "").lower().strip()
            severity = finding.get("severity", "").lower()
            finding_type = finding.get("finding_type", "").lower()
            target_id = finding.get("target_id", "")
            component = finding.get("affected_component", "").lower()

            # Optional: include port if available in evidence
            port = ""
            evidence = finding.get("evidence", {})
            if isinstance(evidence, dict) and "port" in evidence:
                port = str(evidence.get("port"))

            # Create fingerprint string
            fingerprint_string = ":".join(
                [
                    finding_type,
                    severity,
                    title,
                    str(target_id),
                    component,
                    port,
                ]
            )

            # Generate SHA256 hash
            fingerprint = hashlib.sha256(fingerprint_string.encode()).hexdigest()

            logger.debug(
                f"Generated fingerprint for {finding_type}/{title}: {fingerprint[:16]}..."
            )

            return fingerprint

        except Exception as e:
            logger.error(f"Error generating finding fingerprint: {e}")
            # Fallback to simple hash
            return hashlib.sha256(str(finding).encode()).hexdigest()

    def merge_finding_metadata(
        self, existing: Dict[str, Any], duplicate: Dict[str, Any]
    ) -> None:
        """
        Merge metadata from duplicate finding into existing.

        Args:
            existing: Existing finding dictionary (modified in place)
            duplicate: Duplicate finding dictionary

        Note:
            This method modifies the existing dictionary in place.

        Example:
            >>> deduplicator = Deduplicator()
            >>> existing = {
            ...     "confidence": 80,
            ...     "sources": {"tool1": {"timestamp": "2024-01-01"}}
            ... }
            >>> duplicate = {
            ...     "confidence": 90,
            ...     "sources": {"tool2": {"timestamp": "2024-01-02"}}
            ... }
            >>> deduplicator.merge_finding_metadata(existing, duplicate)
            >>> existing["confidence"]
            90
        """
        try:
            logger.debug(
                f"Merging finding metadata for {existing.get('title')}"
            )

            # Increase confidence to the highest value
            existing_confidence = existing.get("confidence", 0)
            duplicate_confidence = duplicate.get("confidence", 0)
            if duplicate_confidence > existing_confidence:
                existing["confidence"] = duplicate_confidence
                logger.debug(
                    f"Updated confidence: {existing_confidence} -> {duplicate_confidence}"
                )

            # Merge sources
            existing_sources = existing.get("sources", {})
            duplicate_sources = duplicate.get("sources", {})

            if isinstance(existing_sources, dict) and isinstance(duplicate_sources, dict):
                # Merge source dictionaries
                for tool, data in duplicate_sources.items():
                    if tool not in existing_sources:
                        existing_sources[tool] = data
                        logger.debug(f"Added source: {tool}")

                existing["sources"] = existing_sources

            # Update false_positive_probability to the lower value (more confident)
            existing_fpp = existing.get("false_positive_probability")
            duplicate_fpp = duplicate.get("false_positive_probability")

            if existing_fpp is not None and duplicate_fpp is not None:
                existing["false_positive_probability"] = min(existing_fpp, duplicate_fpp)

            # Merge evidence if both are dictionaries
            existing_evidence = existing.get("evidence", {})
            duplicate_evidence = duplicate.get("evidence", {})

            if isinstance(existing_evidence, dict) and isinstance(
                duplicate_evidence, dict
            ):
                # Add any new evidence fields
                for key, value in duplicate_evidence.items():
                    if key not in existing_evidence:
                        existing_evidence[key] = value

                existing["evidence"] = existing_evidence

            logger.debug(f"Successfully merged finding metadata")

        except Exception as e:
            logger.error(f"Error merging finding metadata: {e}")

    def get_deduplication_stats(
        self, original_count: int, unique_count: int
    ) -> Dict[str, Any]:
        """
        Get deduplication statistics.

        Args:
            original_count: Original number of items
            unique_count: Number of unique items

        Returns:
            Statistics dictionary

        Example:
            >>> deduplicator = Deduplicator()
            >>> stats = deduplicator.get_deduplication_stats(100, 75)
            >>> stats["duplicate_count"]
            25
            >>> stats["deduplication_rate"]
            25.0
        """
        duplicate_count = original_count - unique_count
        deduplication_rate = (
            (duplicate_count / original_count * 100) if original_count > 0 else 0.0
        )

        return {
            "original_count": original_count,
            "unique_count": unique_count,
            "duplicate_count": duplicate_count,
            "deduplication_rate": round(deduplication_rate, 2),
        }
