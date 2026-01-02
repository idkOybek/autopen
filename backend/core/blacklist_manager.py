"""Blacklist manager for filtering forbidden targets."""

import re
import ipaddress
from typing import Dict, List, Tuple, Any, Optional
from datetime import datetime

from loguru import logger
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from backend.models.blacklist import BlacklistEntry, BlacklistEntryType


class BlacklistManager:
    """Manager for blacklist operations and target filtering."""

    def __init__(self, db_session: AsyncSession):
        """
        Initialize the blacklist manager.

        Args:
            db_session: Database session
        """
        self.db_session = db_session
        self.blacklist_cache: Dict[str, List[Dict[str, Any]]] = {
            "ip": [],
            "domain": [],
            "network": [],
            "pattern": [],
            "asn": [],
        }
        self.compiled_patterns: List[re.Pattern] = []
        logger.info("Initializing BlacklistManager")

    async def load_blacklist(self) -> None:
        """
        Load blacklist from database into memory.

        Example:
            >>> manager = BlacklistManager(db_session)
            >>> await manager.load_blacklist()
        """
        try:
            logger.info("Loading blacklist from database")

            # Query active blacklist entries
            result = await self.db_session.execute(
                select(BlacklistEntry).where(
                    BlacklistEntry.active == True,
                    (BlacklistEntry.expires_at.is_(None))
                    | (BlacklistEntry.expires_at > datetime.utcnow()),
                )
            )
            entries = result.scalars().all()

            # Clear cache
            for key in self.blacklist_cache:
                self.blacklist_cache[key] = []
            self.compiled_patterns = []

            # Organize by type
            for entry in entries:
                entry_dict = {
                    "id": str(entry.id),
                    "value": entry.value,
                    "reason": entry.reason,
                    "source": entry.source,
                    "severity": entry.severity,
                }

                entry_type = entry.entry_type.value
                if entry_type in self.blacklist_cache:
                    self.blacklist_cache[entry_type].append(entry_dict)

                # Compile regex patterns
                if entry_type == BlacklistEntryType.PATTERN.value:
                    try:
                        pattern = re.compile(entry.value, re.IGNORECASE)
                        self.compiled_patterns.append(pattern)
                        logger.debug(f"Compiled pattern: {entry.value}")
                    except re.error as e:
                        logger.error(f"Invalid regex pattern {entry.value}: {e}")

            total_entries = sum(len(v) for v in self.blacklist_cache.values())
            logger.info(
                f"Loaded {total_entries} blacklist entries: "
                f"{len(self.blacklist_cache['ip'])} IPs, "
                f"{len(self.blacklist_cache['domain'])} domains, "
                f"{len(self.blacklist_cache['network'])} networks, "
                f"{len(self.blacklist_cache['pattern'])} patterns, "
                f"{len(self.blacklist_cache['asn'])} ASNs"
            )

        except Exception as e:
            logger.error(f"Error loading blacklist: {e}")
            raise

    async def is_blacklisted(self, target: str) -> Tuple[bool, str]:
        """
        Check if a target is blacklisted.

        Args:
            target: Target string to check

        Returns:
            Tuple of (is_blocked, reason)

        Example:
            >>> manager = BlacklistManager(db_session)
            >>> await manager.load_blacklist()
            >>> is_blocked, reason = await manager.is_blacklisted("192.168.1.1")
            >>> is_blocked
            False
        """
        try:
            logger.debug(f"Checking if target is blacklisted: {target}")

            # Check IP addresses
            if self._is_ip(target):
                is_blocked, reason = self.check_ip_blacklist(target)
                if is_blocked:
                    logger.info(f"Target {target} blocked by IP blacklist: {reason}")
                    await self._update_hit_count(target)
                    return True, reason

            # Check domains
            domain = self._extract_domain(target)
            if domain:
                is_blocked, reason = self.check_domain_blacklist(domain)
                if is_blocked:
                    logger.info(f"Target {target} blocked by domain blacklist: {reason}")
                    await self._update_hit_count(domain)
                    return True, reason

            # Check patterns
            is_blocked, reason = self.check_pattern_blacklist(target)
            if is_blocked:
                logger.info(f"Target {target} blocked by pattern: {reason}")
                await self._update_hit_count(target)
                return True, reason

            logger.debug(f"Target {target} is not blacklisted")
            return False, ""

        except Exception as e:
            logger.error(f"Error checking blacklist for {target}: {e}")
            # Fail open - don't block on error
            return False, ""

    async def filter_targets(
        self, targets: List[Dict[str, Any]]
    ) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
        """
        Filter a list of targets against blacklist.

        Args:
            targets: List of target dictionaries

        Returns:
            Tuple of (allowed_targets, blacklisted_targets)

        Example:
            >>> manager = BlacklistManager(db_session)
            >>> await manager.load_blacklist()
            >>> targets = [
            ...     {"normalized_value": "example.com"},
            ...     {"normalized_value": "blocked.com"}
            ... ]
            >>> allowed, blocked = await manager.filter_targets(targets)
        """
        try:
            logger.info(f"Filtering {len(targets)} targets against blacklist")

            allowed = []
            blacklisted = []

            for target in targets:
                target_value = target.get("normalized_value", target.get("raw_value", ""))

                is_blocked, reason = await self.is_blacklisted(target_value)

                if is_blocked:
                    target["blacklisted"] = True
                    target["blacklist_reason"] = reason
                    blacklisted.append(target)
                else:
                    allowed.append(target)

            logger.info(
                f"Filtered targets: {len(allowed)} allowed, {len(blacklisted)} blocked"
            )

            return allowed, blacklisted

        except Exception as e:
            logger.error(f"Error filtering targets: {e}")
            # Fail open - return all targets as allowed
            return targets, []

    async def add_entry(
        self,
        entry_type: str,
        value: str,
        reason: str,
        source: str = "manual",
        severity: str = "high",
    ) -> None:
        """
        Add an entry to the blacklist.

        Args:
            entry_type: Type of entry (ip, domain, network, pattern, asn)
            value: Value to blacklist
            reason: Reason for blacklisting
            source: Source of entry (manual, corporate, automatic)
            severity: Severity level

        Example:
            >>> manager = BlacklistManager(db_session)
            >>> await manager.add_entry("domain", "malicious.com", "Known malware distributor")
        """
        try:
            logger.info(f"Adding blacklist entry: {entry_type} - {value}")

            entry = BlacklistEntry(
                entry_type=BlacklistEntryType(entry_type),
                value=value,
                reason=reason,
                source=source,
                severity=severity,
                active=True,
            )

            self.db_session.add(entry)
            await self.db_session.commit()

            # Reload blacklist to include new entry
            await self.load_blacklist()

            logger.info(f"Added blacklist entry: {value}")

        except Exception as e:
            logger.error(f"Error adding blacklist entry: {e}")
            await self.db_session.rollback()
            raise

    def check_ip_blacklist(self, ip: str) -> Tuple[bool, str]:
        """
        Check if an IP is blacklisted.

        Args:
            ip: IP address to check

        Returns:
            Tuple of (is_blocked, reason)
        """
        try:
            # Clean IP (remove port if present)
            ip_clean = ip.split(":")[0]
            ip_obj = ipaddress.ip_address(ip_clean)

            # Check direct IP match
            for entry in self.blacklist_cache["ip"]:
                if entry["value"] == str(ip_obj):
                    return True, entry["reason"]

            # Check network ranges
            is_in_network, reason = self.check_ip_in_network(
                str(ip_obj), self.blacklist_cache["network"]
            )
            if is_in_network:
                return True, reason

            return False, ""

        except ValueError:
            # Not a valid IP
            return False, ""

    def check_ip_in_network(
        self, ip: str, networks: List[Dict[str, Any]]
    ) -> Tuple[bool, str]:
        """
        Check if an IP belongs to blacklisted networks.

        Args:
            ip: IP address
            networks: List of network entries

        Returns:
            Tuple of (is_in_network, reason)
        """
        try:
            ip_obj = ipaddress.ip_address(ip)

            for entry in networks:
                try:
                    network = ipaddress.ip_network(entry["value"], strict=False)
                    if ip_obj in network:
                        return True, entry["reason"]
                except ValueError:
                    continue

            return False, ""

        except ValueError:
            return False, ""

    def check_domain_blacklist(self, domain: str) -> Tuple[bool, str]:
        """
        Check if a domain is blacklisted.

        Args:
            domain: Domain to check

        Returns:
            Tuple of (is_blocked, reason)
        """
        domain_lower = domain.lower()

        # Check exact match
        for entry in self.blacklist_cache["domain"]:
            if entry["value"].lower() == domain_lower:
                return True, entry["reason"]

        # Check if subdomain of blacklisted domain
        is_subdomain, reason = self.check_subdomain(
            domain_lower, self.blacklist_cache["domain"]
        )
        if is_subdomain:
            return True, reason

        return False, ""

    def check_subdomain(
        self, domain: str, blacklisted_domains: List[Dict[str, Any]]
    ) -> Tuple[bool, str]:
        """
        Check if domain is a subdomain of blacklisted domains.

        Args:
            domain: Domain to check
            blacklisted_domains: List of blacklisted domain entries

        Returns:
            Tuple of (is_subdomain, reason)
        """
        for entry in blacklisted_domains:
            blacklisted = entry["value"].lower()

            # Check if domain ends with blacklisted domain
            if domain.endswith("." + blacklisted) or domain == blacklisted:
                return True, entry["reason"]

        return False, ""

    def check_pattern_blacklist(self, target: str) -> Tuple[bool, str]:
        """
        Check if target matches any blacklist patterns.

        Args:
            target: Target to check

        Returns:
            Tuple of (matches, reason)
        """
        for i, pattern in enumerate(self.compiled_patterns):
            if pattern.search(target):
                # Get corresponding entry for reason
                if i < len(self.blacklist_cache["pattern"]):
                    return True, self.blacklist_cache["pattern"][i]["reason"]
                return True, "Matches blacklist pattern"

        return False, ""

    async def _update_hit_count(self, value: str) -> None:
        """Update hit count for a blacklist entry."""
        try:
            result = await self.db_session.execute(
                select(BlacklistEntry).where(BlacklistEntry.value == value)
            )
            entry = result.scalar_one_or_none()

            if entry:
                entry.hit_count += 1
                entry.last_hit = datetime.utcnow()
                await self.db_session.commit()

        except Exception as e:
            logger.error(f"Error updating hit count: {e}")
            await self.db_session.rollback()

    # Helper methods

    def _is_ip(self, target: str) -> bool:
        """Check if target is an IP address."""
        try:
            # Remove port if present
            target_clean = target.split(":")[0]
            ipaddress.ip_address(target_clean)
            return True
        except ValueError:
            return False

    def _extract_domain(self, target: str) -> Optional[str]:
        """Extract domain from target."""
        try:
            # Remove protocol
            if "://" in target:
                target = target.split("://", 1)[1]

            # Remove path
            if "/" in target:
                target = target.split("/", 1)[0]

            # Remove port
            if ":" in target:
                target = target.split(":", 1)[0]

            # Check if it's a domain (not IP)
            if not self._is_ip(target):
                return target.lower()

            return None

        except Exception:
            return None
