"""Scanner manager for registering and executing security scanners."""

from typing import Dict, List, Type, Any, Optional

from loguru import logger

from backend.scanners.base import BaseScanner, ScanResult
from backend.models.target import TargetType


class ScannerManager:
    """Manager for security scanner registry and execution."""

    def __init__(self):
        """Initialize the scanner manager."""
        self.registry: Dict[str, Type[BaseScanner]] = {}
        self.instances: Dict[str, BaseScanner] = {}
        self.target_type_mapping: Dict[str, List[str]] = {
            TargetType.WEB.value: ["nuclei", "nikto", "sqlmap"],
            TargetType.API.value: ["nuclei", "ffuf", "arjun"],
            TargetType.IP.value: ["nmap", "masscan"],
            TargetType.DOMAIN.value: ["nmap", "subfinder", "dnsrecon"],
            TargetType.NETWORK.value: ["nmap", "masscan"],
            TargetType.CLOUD.value: ["nuclei", "cloud-enum"],
            TargetType.DATABASE.value: ["nmap", "sqlmap"],
            TargetType.SSH.value: ["nmap", "ssh-audit"],
            TargetType.SMTP.value: ["nmap", "smtp-user-enum"],
            TargetType.FTP.value: ["nmap"],
            TargetType.RDP.value: ["nmap", "rdp-sec-check"],
            TargetType.IOT.value: ["nmap", "nuclei"],
            TargetType.MOBILE_APP.value: ["mobsf"],
        }

        logger.info("Initialized ScannerManager")

    def register_scanner(
        self, name: str, scanner_class: Type[BaseScanner]
    ) -> None:
        """
        Register a scanner class.

        Args:
            name: Scanner name/identifier
            scanner_class: Scanner class (subclass of BaseScanner)

        Example:
            >>> manager = ScannerManager()
            >>> manager.register_scanner("nmap", NmapScanner)
        """
        if not issubclass(scanner_class, BaseScanner):
            raise ValueError(
                f"{scanner_class} must be a subclass of BaseScanner"
            )

        self.registry[name] = scanner_class
        logger.info(f"Registered scanner: {name}")

    def get_scanner(
        self, name: str, config: Optional[Dict[str, Any]] = None
    ) -> Optional[BaseScanner]:
        """
        Get a scanner instance by name.

        Args:
            name: Scanner name
            config: Scanner configuration (optional)

        Returns:
            Scanner instance or None if not found

        Example:
            >>> manager = ScannerManager()
            >>> scanner = manager.get_scanner("nmap", {"timeout": 300})
        """
        if name not in self.registry:
            logger.warning(f"Scanner {name} not found in registry")
            return None

        # Return cached instance if no config provided
        if config is None and name in self.instances:
            return self.instances[name]

        # Create new instance
        scanner_class = self.registry[name]
        config = config or {}

        try:
            scanner = scanner_class(config)
            self.instances[name] = scanner
            logger.debug(f"Created scanner instance: {name}")
            return scanner

        except Exception as e:
            logger.error(f"Failed to create scanner {name}: {e}")
            return None

    def get_scanners_for_type(
        self, target_type: str, config: Optional[Dict[str, Any]] = None
    ) -> List[BaseScanner]:
        """
        Get all scanners suitable for a target type.

        Args:
            target_type: Target type (e.g., 'web', 'ip', 'domain')
            config: Scanner configuration (optional)

        Returns:
            List of scanner instances

        Example:
            >>> manager = ScannerManager()
            >>> scanners = manager.get_scanners_for_type("web")
        """
        scanner_names = self.target_type_mapping.get(target_type, [])

        scanners = []
        for name in scanner_names:
            scanner = self.get_scanner(name, config)
            if scanner:
                scanners.append(scanner)

        logger.debug(
            f"Found {len(scanners)} scanners for target type {target_type}"
        )

        return scanners

    async def execute_scanner(
        self,
        scanner_name: str,
        target: Dict[str, Any],
        config: Optional[Dict[str, Any]] = None,
    ) -> Optional[ScanResult]:
        """
        Execute a specific scanner against a target.

        Args:
            scanner_name: Scanner name
            target: Target dictionary
            config: Scanner configuration (optional)

        Returns:
            ScanResult or None if scanner not found

        Example:
            >>> manager = ScannerManager()
            >>> result = await manager.execute_scanner(
            ...     "nmap",
            ...     {"raw_value": "192.168.1.1", "target_type": "ip"}
            ... )
        """
        scanner = self.get_scanner(scanner_name, config)

        if not scanner:
            logger.error(f"Scanner {scanner_name} not available")
            return None

        try:
            # Validate target
            if not scanner.validate_target(target):
                logger.warning(
                    f"Target {target.get('raw_value')} not suitable for {scanner_name}"
                )
                return None

            # Execute scan with retry logic
            result = await scanner.scan_with_retry(target)

            return result

        except Exception as e:
            logger.error(f"Error executing scanner {scanner_name}: {e}")
            return scanner.handle_error(e, target)

    async def execute_pipeline(
        self,
        target: Dict[str, Any],
        pipeline: List[str],
        config: Optional[Dict[str, Any]] = None,
    ) -> List[ScanResult]:
        """
        Execute a pipeline of scanners against a target.

        Args:
            target: Target dictionary
            pipeline: List of scanner names to execute in order
            config: Scanner configuration (optional)

        Returns:
            List of ScanResults

        Example:
            >>> manager = ScannerManager()
            >>> results = await manager.execute_pipeline(
            ...     {"raw_value": "example.com", "target_type": "web"},
            ...     ["nmap", "nuclei"]
            ... )
        """
        results = []

        logger.info(
            f"Executing pipeline with {len(pipeline)} scanners for "
            f"{target.get('raw_value')}"
        )

        for scanner_name in pipeline:
            try:
                result = await self.execute_scanner(scanner_name, target, config)

                if result:
                    results.append(result)
                    logger.info(
                        f"Scanner {scanner_name} completed with "
                        f"{len(result.findings)} findings"
                    )
                else:
                    logger.warning(f"Scanner {scanner_name} returned no result")

            except Exception as e:
                logger.error(f"Error in pipeline for {scanner_name}: {e}")
                continue

        logger.info(
            f"Pipeline completed: {len(results)} scanner results, "
            f"{sum(len(r.findings) for r in results)} total findings"
        )

        return results

    def list_scanners(self) -> List[str]:
        """
        List all registered scanners.

        Returns:
            List of scanner names

        Example:
            >>> manager = ScannerManager()
            >>> scanners = manager.list_scanners()
        """
        return list(self.registry.keys())

    def get_scanner_info(self, name: str) -> Optional[Dict[str, Any]]:
        """
        Get information about a scanner.

        Args:
            name: Scanner name

        Returns:
            Dictionary with scanner information or None

        Example:
            >>> manager = ScannerManager()
            >>> info = manager.get_scanner_info("nmap")
        """
        if name not in self.registry:
            return None

        scanner_class = self.registry[name]

        return {
            "name": name,
            "class": scanner_class.__name__,
            "module": scanner_class.__module__,
            "doc": scanner_class.__doc__,
        }

    def auto_register_scanners(self) -> None:
        """
        Automatically register all available scanners.

        Example:
            >>> manager = ScannerManager()
            >>> manager.auto_register_scanners()
        """
        try:
            # Import scanner classes
            from backend.scanners.network.nmap_scanner import NmapScanner
            from backend.scanners.network.masscan_scanner import MasscanScanner
            from backend.scanners.web.nuclei_scanner import NucleiScanner

            # Register scanners
            self.register_scanner("nmap", NmapScanner)
            self.register_scanner("masscan", MasscanScanner)
            self.register_scanner("nuclei", NucleiScanner)

            logger.info(
                f"Auto-registered {len(self.registry)} scanners"
            )

        except ImportError as e:
            logger.error(f"Failed to import scanner classes: {e}")


# Global scanner manager instance
scanner_manager = ScannerManager()
scanner_manager.auto_register_scanners()
