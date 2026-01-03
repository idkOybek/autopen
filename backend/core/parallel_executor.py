"""Parallel executor for running multiple scanners concurrently."""

import asyncio
from typing import List, Dict, Any, Callable, Optional
from datetime import datetime

from loguru import logger

from backend.scanners.base import BaseScanner, ScanResult, ScannerStatus
from backend.core.error_handler import ErrorHandler, ErrorCategory


class ParallelExecutor:
    """Execute scanners in parallel with rate limiting and error handling."""

    def __init__(
        self,
        max_workers: int = 5,
        rate_limit: Optional[int] = None,
        retry_on_error: bool = True,
    ):
        """
        Initialize the parallel executor.

        Args:
            max_workers: Maximum number of concurrent tasks
            rate_limit: Maximum tasks per second (None for unlimited)
            retry_on_error: Whether to retry on errors
        """
        self.max_workers = max_workers
        self.rate_limit = rate_limit
        self.retry_on_error = retry_on_error
        self.error_handler = ErrorHandler()

        # Statistics
        self.stats = {
            "total_tasks": 0,
            "completed": 0,
            "failed": 0,
            "in_progress": 0,
        }

        logger.info(
            f"Initialized ParallelExecutor with max_workers={max_workers}, "
            f"rate_limit={rate_limit}"
        )

    async def execute_parallel(
        self,
        targets: List[Dict[str, Any]],
        scanner: BaseScanner,
        progress_callback: Optional[Callable] = None,
    ) -> List[ScanResult]:
        """
        Execute scanner against multiple targets in parallel.

        Args:
            targets: List of target dictionaries
            scanner: Scanner instance to use
            progress_callback: Optional callback for progress updates

        Returns:
            List of ScanResults

        Example:
            >>> executor = ParallelExecutor(max_workers=10)
            >>> scanner = NmapScanner(config={})
            >>> targets = [{"raw_value": "192.168.1.1"}, ...]
            >>> results = await executor.execute_parallel(targets, scanner)
        """
        self.stats["total_tasks"] = len(targets)
        self.stats["completed"] = 0
        self.stats["failed"] = 0
        self.stats["in_progress"] = 0

        logger.info(
            f"Starting parallel execution of {len(targets)} targets "
            f"with {scanner.name}"
        )

        # Create semaphore for concurrency control
        semaphore = asyncio.Semaphore(self.max_workers)

        # Create tasks
        tasks = [
            self._execute_with_semaphore(
                target, scanner, semaphore, progress_callback
            )
            for target in targets
        ]

        # Execute all tasks
        results = await asyncio.gather(*tasks, return_exceptions=True)

        # Process results
        processed_results = []
        for i, result in enumerate(results):
            if isinstance(result, Exception):
                logger.error(f"Task {i} raised exception: {result}")
                # Create error result
                error_result = scanner.handle_error(result, targets[i])
                processed_results.append(error_result)
            else:
                processed_results.append(result)

        logger.info(
            f"Parallel execution completed: {self.stats['completed']} succeeded, "
            f"{self.stats['failed']} failed"
        )

        return processed_results

    async def _execute_with_semaphore(
        self,
        target: Dict[str, Any],
        scanner: BaseScanner,
        semaphore: asyncio.Semaphore,
        progress_callback: Optional[Callable] = None,
    ) -> ScanResult:
        """Execute single scan with semaphore control."""
        async with semaphore:
            self.stats["in_progress"] += 1

            try:
                # Apply rate limiting if configured
                if self.rate_limit:
                    await self._apply_rate_limit()

                # Execute scan
                result = await scanner.scan_with_retry(target)

                # Update statistics
                if result.status == ScannerStatus.COMPLETED:
                    self.stats["completed"] += 1
                else:
                    self.stats["failed"] += 1

                self.stats["in_progress"] -= 1

                # Call progress callback
                if progress_callback:
                    await progress_callback(target, result, self.stats)

                return result

            except Exception as e:
                self.stats["failed"] += 1
                self.stats["in_progress"] -= 1

                logger.error(
                    f"Error executing scan for {target.get('raw_value')}: {e}"
                )

                return scanner.handle_error(e, target)

    async def _apply_rate_limit(self) -> None:
        """Apply rate limiting delay."""
        if self.rate_limit:
            delay = 1.0 / self.rate_limit
            await asyncio.sleep(delay)

    async def execute_pipeline_parallel(
        self,
        targets: List[Dict[str, Any]],
        scanners: List[BaseScanner],
        progress_callback: Optional[Callable] = None,
    ) -> Dict[str, List[ScanResult]]:
        """
        Execute multiple scanners against multiple targets in parallel.

        Args:
            targets: List of target dictionaries
            scanners: List of scanner instances
            progress_callback: Optional callback for progress updates

        Returns:
            Dictionary mapping scanner names to lists of ScanResults

        Example:
            >>> executor = ParallelExecutor()
            >>> scanners = [NmapScanner({}), NucleiScanner({})]
            >>> targets = [{"raw_value": "example.com"}]
            >>> results = await executor.execute_pipeline_parallel(targets, scanners)
        """
        logger.info(
            f"Starting pipeline execution: {len(scanners)} scanners x "
            f"{len(targets)} targets"
        )

        results = {}

        # Execute each scanner against all targets
        for scanner in scanners:
            logger.info(f"Executing {scanner.name} against {len(targets)} targets")

            scanner_results = await self.execute_parallel(
                targets, scanner, progress_callback
            )

            results[scanner.name] = scanner_results

        logger.info("Pipeline execution completed")

        return results

    async def execute_with_timeout(
        self,
        targets: List[Dict[str, Any]],
        scanner: BaseScanner,
        timeout: int,
        progress_callback: Optional[Callable] = None,
    ) -> List[ScanResult]:
        """
        Execute with global timeout.

        Args:
            targets: List of targets
            scanner: Scanner instance
            timeout: Global timeout in seconds
            progress_callback: Optional progress callback

        Returns:
            List of ScanResults

        Raises:
            TimeoutError: If execution exceeds timeout
        """
        try:
            results = await asyncio.wait_for(
                self.execute_parallel(targets, scanner, progress_callback),
                timeout=timeout,
            )

            return results

        except asyncio.TimeoutError:
            logger.error(f"Parallel execution timed out after {timeout}s")
            raise TimeoutError(f"Execution timed out after {timeout}s")

    def get_statistics(self) -> Dict[str, Any]:
        """
        Get execution statistics.

        Returns:
            Dictionary with statistics

        Example:
            >>> executor = ParallelExecutor()
            >>> stats = executor.get_statistics()
            >>> print(stats["completed"])
        """
        completion_rate = 0.0
        if self.stats["total_tasks"] > 0:
            completion_rate = (
                self.stats["completed"] / self.stats["total_tasks"] * 100
            )

        return {
            **self.stats,
            "completion_rate": round(completion_rate, 2),
        }

    async def execute_with_batching(
        self,
        targets: List[Dict[str, Any]],
        scanner: BaseScanner,
        batch_size: int = 100,
        progress_callback: Optional[Callable] = None,
    ) -> List[ScanResult]:
        """
        Execute in batches to manage memory.

        Args:
            targets: List of targets
            scanner: Scanner instance
            batch_size: Number of targets per batch
            progress_callback: Optional progress callback

        Returns:
            List of ScanResults
        """
        all_results = []
        total_batches = (len(targets) + batch_size - 1) // batch_size

        logger.info(
            f"Executing {len(targets)} targets in {total_batches} batches "
            f"of {batch_size}"
        )

        for i in range(0, len(targets), batch_size):
            batch_num = i // batch_size + 1
            batch = targets[i : i + batch_size]

            logger.info(
                f"Processing batch {batch_num}/{total_batches} "
                f"({len(batch)} targets)"
            )

            batch_results = await self.execute_parallel(
                batch, scanner, progress_callback
            )

            all_results.extend(batch_results)

            # Small delay between batches
            if i + batch_size < len(targets):
                await asyncio.sleep(1)

        logger.info(f"Batched execution completed: {len(all_results)} results")

        return all_results
