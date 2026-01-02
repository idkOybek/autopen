"""Target classifier for identifying and categorizing scan targets."""

import re
import ipaddress
from typing import Dict, List, Tuple, Any, Optional
from urllib.parse import urlparse

from loguru import logger

from backend.models.target import TargetType


# Tool mapping for different target types
TOOL_MAPPING = {
    TargetType.WEB: [
        "nuclei",
        "nikto",
        "gobuster",
        "sqlmap",
        "xsstrike",
        "wpscan",
        "whatweb",
    ],
    TargetType.API: [
        "nuclei",
        "ffuf",
        "arjun",
        "postman",
        "swagger-scanner",
    ],
    TargetType.IP: [
        "nmap",
        "masscan",
        "nuclei",
    ],
    TargetType.DOMAIN: [
        "subfinder",
        "amass",
        "dnsrecon",
        "dig",
        "nmap",
    ],
    TargetType.NETWORK: [
        "nmap",
        "masscan",
        "arp-scan",
    ],
    TargetType.CLOUD: [
        "nuclei",
        "cloud-enum",
        "s3scanner",
    ],
    TargetType.DATABASE: [
        "sqlmap",
        "nmap",
        "metasploit",
    ],
    TargetType.SSH: [
        "nmap",
        "ssh-audit",
        "hydra",
    ],
    TargetType.SMTP: [
        "nmap",
        "smtp-user-enum",
    ],
    TargetType.FTP: [
        "nmap",
        "ftp-scan",
    ],
    TargetType.RDP: [
        "nmap",
        "rdp-sec-check",
    ],
    TargetType.IOT: [
        "nmap",
        "nuclei",
        "shodan",
    ],
    TargetType.MOBILE_APP: [
        "mobsf",
        "apktool",
        "jadx",
    ],
}

# Target type patterns
TARGET_PATTERNS = {
    "web": [
        re.compile(r'^https?://'),
        re.compile(r'.*\.(html|php|asp|aspx|jsp)$'),
    ],
    "api": [
        re.compile(r'/api/'),
        re.compile(r'/v\d+/'),
        re.compile(r'.*\.(json|xml)$'),
        re.compile(r'/graphql'),
        re.compile(r'/rest/'),
    ],
    "ip": [
        re.compile(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$'),
    ],
    "domain": [
        re.compile(r'^[a-zA-Z0-9][a-zA-Z0-9-]{0,61}[a-zA-Z0-9]?(\.[a-zA-Z]{2,})+$'),
    ],
    "network": [
        re.compile(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d{1,2}$'),
    ],
    "cloud": [
        re.compile(r's3\.amazonaws\.com'),
        re.compile(r'\.s3\.'),
        re.compile(r'blob\.core\.windows\.net'),
        re.compile(r'storage\.googleapis\.com'),
    ],
    "database": [
        re.compile(r':3306'),  # MySQL
        re.compile(r':5432'),  # PostgreSQL
        re.compile(r':1433'),  # MSSQL
        re.compile(r':27017'),  # MongoDB
    ],
    "ssh": [
        re.compile(r':22$'),
        re.compile(r'ssh://'),
    ],
    "smtp": [
        re.compile(r':25$'),
        re.compile(r':587$'),
        re.compile(r'smtp://'),
    ],
    "ftp": [
        re.compile(r':21$'),
        re.compile(r'ftp://'),
    ],
    "rdp": [
        re.compile(r':3389$'),
        re.compile(r'rdp://'),
    ],
}


class TargetClassifier:
    """Classifier for identifying and categorizing scan targets."""

    def __init__(self):
        """Initialize the target classifier."""
        logger.info("Initializing TargetClassifier")

    def classify_target(self, raw_target: str) -> Dict[str, Any]:
        """
        Classify a target and return detailed classification.

        Args:
            raw_target: Raw target string

        Returns:
            Dictionary containing classification details

        Example:
            >>> classifier = TargetClassifier()
            >>> result = classifier.classify_target("https://example.com/api/v1")
            >>> result['target_type']
            'api'
        """
        try:
            logger.debug(f"Classifying target: {raw_target}")

            target_type = self._determine_target_type(raw_target)
            classification = {
                "target_type": target_type,
                "is_url": self._is_url(raw_target),
                "is_ip": self._is_ip_address(raw_target),
                "is_domain": self._is_domain(raw_target),
                "is_network": self._is_network(raw_target),
                "protocol": self._extract_protocol(raw_target),
                "port": self._extract_port(raw_target),
                "path": self._extract_path(raw_target),
                "has_subdomain": self._has_subdomain(raw_target),
            }

            logger.debug(f"Classification result for {raw_target}: {classification}")
            return classification

        except Exception as e:
            logger.error(f"Error classifying target {raw_target}: {e}")
            return {
                "target_type": TargetType.WEB,
                "error": str(e),
            }

    def normalize_target(self, raw_target: str, target_type: str) -> str:
        """
        Normalize a target for deduplication.

        Args:
            raw_target: Raw target string
            target_type: Target type

        Returns:
            Normalized target string

        Example:
            >>> classifier = TargetClassifier()
            >>> classifier.normalize_target("HTTPS://Example.COM/path/", "web")
            'https://example.com/path'
        """
        try:
            logger.debug(f"Normalizing target: {raw_target} (type: {target_type})")

            normalized = raw_target.strip()

            # Normalize based on type
            if target_type in [TargetType.WEB.value, TargetType.API.value]:
                normalized = self._normalize_url(normalized)
            elif target_type == TargetType.DOMAIN.value:
                normalized = self._normalize_domain(normalized)
            elif target_type == TargetType.IP.value:
                normalized = self._normalize_ip(normalized)
            elif target_type == TargetType.NETWORK.value:
                normalized = self._normalize_network(normalized)

            logger.debug(f"Normalized {raw_target} -> {normalized}")
            return normalized

        except Exception as e:
            logger.error(f"Error normalizing target {raw_target}: {e}")
            return raw_target

    def enrich_target(self, target: Dict[str, Any]) -> Dict[str, Any]:
        """
        Enrich target with additional information.

        Args:
            target: Target dictionary

        Returns:
            Enriched target dictionary

        Note:
            This is a placeholder for future enrichment logic.
            Could include DNS lookups, port scanning, tech detection, etc.
        """
        try:
            logger.debug(f"Enriching target: {target.get('raw_value')}")

            enriched = target.copy()
            target_type = target.get("target_type")

            # Placeholder for enrichment logic
            # In production, this would include:
            # - DNS lookups for domains
            # - Quick port scan for IPs
            # - Technology detection for web targets
            # - Cloud provider detection

            enriched["enrichment"] = {
                "timestamp": "placeholder",
                "source": "target_classifier",
            }

            logger.debug(f"Target enriched: {target.get('raw_value')}")
            return enriched

        except Exception as e:
            logger.error(f"Error enriching target: {e}")
            return target

    def get_tools_for_target(self, target_type: str) -> List[str]:
        """
        Get list of tools for a target type.

        Args:
            target_type: Target type

        Returns:
            List of tool names

        Example:
            >>> classifier = TargetClassifier()
            >>> tools = classifier.get_tools_for_target("web")
            >>> "nuclei" in tools
            True
        """
        try:
            # Convert string to TargetType enum if needed
            if isinstance(target_type, str):
                target_type = TargetType(target_type)

            tools = TOOL_MAPPING.get(target_type, [])
            logger.debug(f"Tools for {target_type}: {tools}")
            return tools

        except Exception as e:
            logger.error(f"Error getting tools for target type {target_type}: {e}")
            return []

    # Private helper methods

    def _determine_target_type(self, raw_target: str) -> str:
        """Determine the target type based on patterns."""
        # Check API patterns first (more specific)
        if self._matches_patterns(raw_target, TARGET_PATTERNS.get("api", [])):
            return TargetType.API.value

        # Check cloud patterns
        if self._matches_patterns(raw_target, TARGET_PATTERNS.get("cloud", [])):
            return TargetType.CLOUD.value

        # Check protocol-specific patterns
        for service in ["ssh", "smtp", "ftp", "rdp", "database"]:
            if self._matches_patterns(raw_target, TARGET_PATTERNS.get(service, [])):
                return getattr(TargetType, service.upper()).value

        # Check network
        if self._matches_patterns(raw_target, TARGET_PATTERNS.get("network", [])):
            return TargetType.NETWORK.value

        # Check IP
        if self._is_ip_address(raw_target):
            return TargetType.IP.value

        # Check web URL
        if self._matches_patterns(raw_target, TARGET_PATTERNS.get("web", [])):
            return TargetType.WEB.value

        # Check domain
        if self._is_domain(raw_target):
            return TargetType.DOMAIN.value

        # Default to web
        return TargetType.WEB.value

    def _matches_patterns(self, target: str, patterns: List[re.Pattern]) -> bool:
        """Check if target matches any of the patterns."""
        return any(pattern.search(target) for pattern in patterns)

    def _is_url(self, target: str) -> bool:
        """Check if target is a URL."""
        try:
            result = urlparse(target)
            return all([result.scheme, result.netloc])
        except Exception:
            return False

    def _is_ip_address(self, target: str) -> bool:
        """Check if target is an IP address."""
        try:
            # Remove port if present
            target_clean = target.split(':')[0]
            ipaddress.ip_address(target_clean)
            return True
        except ValueError:
            return False

    def _is_domain(self, target: str) -> bool:
        """Check if target is a domain."""
        domain_pattern = re.compile(
            r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
        )
        return bool(domain_pattern.match(target))

    def _is_network(self, target: str) -> bool:
        """Check if target is a network CIDR."""
        try:
            ipaddress.ip_network(target, strict=False)
            return True
        except ValueError:
            return False

    def _extract_protocol(self, target: str) -> Optional[str]:
        """Extract protocol from target."""
        if self._is_url(target):
            return urlparse(target).scheme
        elif 'ssh://' in target:
            return 'ssh'
        elif 'ftp://' in target:
            return 'ftp'
        elif 'rdp://' in target:
            return 'rdp'
        return None

    def _extract_port(self, target: str) -> Optional[int]:
        """Extract port from target."""
        try:
            if ':' in target:
                port_str = target.split(':')[-1].split('/')[0]
                return int(port_str)
        except (ValueError, IndexError):
            pass
        return None

    def _extract_path(self, target: str) -> Optional[str]:
        """Extract path from URL target."""
        if self._is_url(target):
            path = urlparse(target).path
            return path if path else None
        return None

    def _has_subdomain(self, target: str) -> bool:
        """Check if domain has subdomain."""
        try:
            if self._is_url(target):
                hostname = urlparse(target).hostname
            else:
                hostname = target.split(':')[0]

            if hostname and self._is_domain(hostname):
                parts = hostname.split('.')
                return len(parts) > 2
        except Exception:
            pass
        return False

    def _normalize_url(self, url: str) -> str:
        """Normalize URL."""
        # Convert to lowercase
        url = url.lower()

        # Remove trailing slash
        if url.endswith('/'):
            url = url[:-1]

        # Ensure protocol
        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url

        return url

    def _normalize_domain(self, domain: str) -> str:
        """Normalize domain."""
        # Convert to lowercase
        domain = domain.lower()

        # Remove protocol if present
        if '://' in domain:
            domain = urlparse(domain).hostname or domain

        # Remove port if present
        domain = domain.split(':')[0]

        # Remove trailing dot
        if domain.endswith('.'):
            domain = domain[:-1]

        return domain

    def _normalize_ip(self, ip: str) -> str:
        """Normalize IP address."""
        try:
            # Remove port if present
            ip_clean = ip.split(':')[0]
            # Validate and normalize
            return str(ipaddress.ip_address(ip_clean))
        except ValueError:
            return ip

    def _normalize_network(self, network: str) -> str:
        """Normalize network CIDR."""
        try:
            return str(ipaddress.ip_network(network, strict=False))
        except ValueError:
            return network
