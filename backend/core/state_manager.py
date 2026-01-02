"""State manager for scan state and checkpoint management using Redis."""

import json
from typing import Dict, Any, Optional
from datetime import datetime, timedelta

from loguru import logger
import redis.asyncio as aioredis


class StateManager:
    """Manager for scan state and checkpoint operations using Redis."""

    def __init__(self, redis_client: aioredis.Redis):
        """
        Initialize the state manager.

        Args:
            redis_client: Async Redis client

        Example:
            >>> redis_client = aioredis.from_url("redis://localhost:6379/0")
            >>> manager = StateManager(redis_client)
        """
        self.redis = redis_client
        logger.info("Initializing StateManager with Redis")

    async def create_checkpoint(
        self,
        scan_id: str,
        target_id: str,
        stage: str,
        data: Dict[str, Any],
        ttl: int = 86400,
    ) -> bool:
        """
        Create a checkpoint for scan recovery.

        Args:
            scan_id: Scan identifier
            target_id: Target identifier
            stage: Current stage name
            data: Checkpoint data
            ttl: Time-to-live in seconds (default: 24 hours)

        Returns:
            True if successful, False otherwise

        Example:
            >>> manager = StateManager(redis_client)
            >>> await manager.create_checkpoint(
            ...     "scan-123",
            ...     "target-456",
            ...     "reconnaissance",
            ...     {"completed": ["nmap"], "pending": ["nikto"]}
            ... )
            True
        """
        try:
            key = self._get_checkpoint_key(scan_id, target_id)

            checkpoint = {
                "scan_id": scan_id,
                "target_id": target_id,
                "stage": stage,
                "data": data,
                "timestamp": datetime.utcnow().isoformat(),
            }

            # Store checkpoint
            await self.redis.setex(
                key, ttl, json.dumps(checkpoint, default=str)
            )

            logger.debug(
                f"Created checkpoint for scan {scan_id}, target {target_id}, stage {stage}"
            )

            return True

        except Exception as e:
            logger.error(f"Error creating checkpoint: {e}")
            return False

    async def load_checkpoint(
        self, scan_id: str, target_id: str
    ) -> Optional[Dict[str, Any]]:
        """
        Load a checkpoint from Redis.

        Args:
            scan_id: Scan identifier
            target_id: Target identifier

        Returns:
            Checkpoint dictionary or None if not found

        Example:
            >>> manager = StateManager(redis_client)
            >>> checkpoint = await manager.load_checkpoint("scan-123", "target-456")
            >>> checkpoint["stage"]
            'reconnaissance'
        """
        try:
            key = self._get_checkpoint_key(scan_id, target_id)

            # Get checkpoint
            data = await self.redis.get(key)

            if data:
                checkpoint = json.loads(data)
                logger.debug(
                    f"Loaded checkpoint for scan {scan_id}, target {target_id}"
                )
                return checkpoint

            logger.debug(f"No checkpoint found for scan {scan_id}, target {target_id}")
            return None

        except Exception as e:
            logger.error(f"Error loading checkpoint: {e}")
            return None

    async def delete_checkpoint(self, scan_id: str, target_id: str) -> bool:
        """
        Delete a checkpoint.

        Args:
            scan_id: Scan identifier
            target_id: Target identifier

        Returns:
            True if deleted, False otherwise
        """
        try:
            key = self._get_checkpoint_key(scan_id, target_id)
            deleted = await self.redis.delete(key)

            if deleted:
                logger.debug(
                    f"Deleted checkpoint for scan {scan_id}, target {target_id}"
                )

            return bool(deleted)

        except Exception as e:
            logger.error(f"Error deleting checkpoint: {e}")
            return False

    async def update_scan_status(
        self, scan_id: str, status: str, ttl: int = 86400
    ) -> bool:
        """
        Update scan status in Redis.

        Args:
            scan_id: Scan identifier
            status: New status
            ttl: Time-to-live in seconds (default: 24 hours)

        Returns:
            True if successful, False otherwise

        Example:
            >>> manager = StateManager(redis_client)
            >>> await manager.update_scan_status("scan-123", "running")
            True
        """
        try:
            key = self._get_status_key(scan_id)

            status_data = {
                "scan_id": scan_id,
                "status": status,
                "updated_at": datetime.utcnow().isoformat(),
            }

            await self.redis.setex(
                key, ttl, json.dumps(status_data, default=str)
            )

            logger.debug(f"Updated scan {scan_id} status to {status}")

            return True

        except Exception as e:
            logger.error(f"Error updating scan status: {e}")
            return False

    async def get_scan_status(self, scan_id: str) -> Optional[str]:
        """
        Get current scan status from Redis.

        Args:
            scan_id: Scan identifier

        Returns:
            Status string or None if not found

        Example:
            >>> manager = StateManager(redis_client)
            >>> status = await manager.get_scan_status("scan-123")
            >>> status
            'running'
        """
        try:
            key = self._get_status_key(scan_id)

            data = await self.redis.get(key)

            if data:
                status_data = json.loads(data)
                return status_data.get("status")

            return None

        except Exception as e:
            logger.error(f"Error getting scan status: {e}")
            return None

    async def save_scan_state(
        self, scan_id: str, state: Dict[str, Any], ttl: int = 86400
    ) -> bool:
        """
        Save complete scan state.

        Args:
            scan_id: Scan identifier
            state: State dictionary
            ttl: Time-to-live in seconds (default: 24 hours)

        Returns:
            True if successful, False otherwise

        Example:
            >>> manager = StateManager(redis_client)
            >>> state = {
            ...     "total_targets": 100,
            ...     "completed_targets": 50,
            ...     "current_stage": "scanning",
            ...     "tools_running": ["nmap", "nikto"]
            ... }
            >>> await manager.save_scan_state("scan-123", state)
            True
        """
        try:
            key = self._get_state_key(scan_id)

            state_data = {
                "scan_id": scan_id,
                "state": state,
                "timestamp": datetime.utcnow().isoformat(),
            }

            await self.redis.setex(
                key, ttl, json.dumps(state_data, default=str)
            )

            logger.debug(f"Saved state for scan {scan_id}")

            return True

        except Exception as e:
            logger.error(f"Error saving scan state: {e}")
            return False

    async def get_scan_state(self, scan_id: str) -> Optional[Dict[str, Any]]:
        """
        Get complete scan state.

        Args:
            scan_id: Scan identifier

        Returns:
            State dictionary or None if not found

        Example:
            >>> manager = StateManager(redis_client)
            >>> state = await manager.get_scan_state("scan-123")
            >>> state["total_targets"]
            100
        """
        try:
            key = self._get_state_key(scan_id)

            data = await self.redis.get(key)

            if data:
                state_data = json.loads(data)
                logger.debug(f"Loaded state for scan {scan_id}")
                return state_data.get("state")

            return None

        except Exception as e:
            logger.error(f"Error getting scan state: {e}")
            return None

    async def delete_scan_state(self, scan_id: str) -> bool:
        """
        Delete all scan-related data from Redis.

        Args:
            scan_id: Scan identifier

        Returns:
            True if successful, False otherwise

        Example:
            >>> manager = StateManager(redis_client)
            >>> await manager.delete_scan_state("scan-123")
            True
        """
        try:
            # Get all keys for this scan
            pattern = f"scan:{scan_id}:*"
            keys = []

            # Scan for all matching keys
            cursor = 0
            while True:
                cursor, partial_keys = await self.redis.scan(
                    cursor, match=pattern, count=100
                )
                keys.extend(partial_keys)
                if cursor == 0:
                    break

            # Delete all keys
            if keys:
                deleted = await self.redis.delete(*keys)
                logger.info(
                    f"Deleted {deleted} keys for scan {scan_id}"
                )

            return True

        except Exception as e:
            logger.error(f"Error deleting scan state: {e}")
            return False

    async def set_scan_metadata(
        self, scan_id: str, key: str, value: Any, ttl: int = 86400
    ) -> bool:
        """
        Set custom metadata for a scan.

        Args:
            scan_id: Scan identifier
            key: Metadata key
            value: Metadata value
            ttl: Time-to-live in seconds

        Returns:
            True if successful, False otherwise

        Example:
            >>> manager = StateManager(redis_client)
            >>> await manager.set_scan_metadata(
            ...     "scan-123",
            ...     "start_time",
            ...     datetime.utcnow().isoformat()
            ... )
            True
        """
        try:
            redis_key = f"scan:{scan_id}:metadata:{key}"

            await self.redis.setex(
                redis_key, ttl, json.dumps(value, default=str)
            )

            logger.debug(f"Set metadata {key} for scan {scan_id}")

            return True

        except Exception as e:
            logger.error(f"Error setting scan metadata: {e}")
            return False

    async def get_scan_metadata(
        self, scan_id: str, key: str
    ) -> Optional[Any]:
        """
        Get custom metadata for a scan.

        Args:
            scan_id: Scan identifier
            key: Metadata key

        Returns:
            Metadata value or None if not found
        """
        try:
            redis_key = f"scan:{scan_id}:metadata:{key}"

            data = await self.redis.get(redis_key)

            if data:
                return json.loads(data)

            return None

        except Exception as e:
            logger.error(f"Error getting scan metadata: {e}")
            return None

    async def increment_counter(
        self, scan_id: str, counter_name: str, amount: int = 1
    ) -> int:
        """
        Increment a counter for a scan.

        Args:
            scan_id: Scan identifier
            counter_name: Counter name
            amount: Amount to increment by

        Returns:
            New counter value

        Example:
            >>> manager = StateManager(redis_client)
            >>> count = await manager.increment_counter("scan-123", "targets_completed")
            >>> count
            1
        """
        try:
            key = f"scan:{scan_id}:counter:{counter_name}"

            new_value = await self.redis.incrby(key, amount)

            # Set expiry
            await self.redis.expire(key, 86400)

            logger.debug(
                f"Incremented {counter_name} for scan {scan_id} to {new_value}"
            )

            return new_value

        except Exception as e:
            logger.error(f"Error incrementing counter: {e}")
            return 0

    async def get_counter(self, scan_id: str, counter_name: str) -> int:
        """
        Get counter value for a scan.

        Args:
            scan_id: Scan identifier
            counter_name: Counter name

        Returns:
            Counter value
        """
        try:
            key = f"scan:{scan_id}:counter:{counter_name}"

            value = await self.redis.get(key)

            if value:
                return int(value)

            return 0

        except Exception as e:
            logger.error(f"Error getting counter: {e}")
            return 0

    async def acquire_lock(
        self, lock_name: str, ttl: int = 60
    ) -> bool:
        """
        Acquire a distributed lock.

        Args:
            lock_name: Lock name
            ttl: Lock timeout in seconds

        Returns:
            True if lock acquired, False otherwise

        Example:
            >>> manager = StateManager(redis_client)
            >>> acquired = await manager.acquire_lock("scan:123:target:456")
            >>> acquired
            True
        """
        try:
            key = f"lock:{lock_name}"

            # Try to set key with NX (only if not exists)
            acquired = await self.redis.set(
                key, "1", ex=ttl, nx=True
            )

            if acquired:
                logger.debug(f"Acquired lock: {lock_name}")
            else:
                logger.debug(f"Failed to acquire lock: {lock_name}")

            return bool(acquired)

        except Exception as e:
            logger.error(f"Error acquiring lock: {e}")
            return False

    async def release_lock(self, lock_name: str) -> bool:
        """
        Release a distributed lock.

        Args:
            lock_name: Lock name

        Returns:
            True if released, False otherwise
        """
        try:
            key = f"lock:{lock_name}"

            deleted = await self.redis.delete(key)

            if deleted:
                logger.debug(f"Released lock: {lock_name}")

            return bool(deleted)

        except Exception as e:
            logger.error(f"Error releasing lock: {e}")
            return False

    # Helper methods for key generation

    def _get_checkpoint_key(self, scan_id: str, target_id: str) -> str:
        """Generate Redis key for checkpoint."""
        return f"scan:{scan_id}:checkpoints:{target_id}"

    def _get_status_key(self, scan_id: str) -> str:
        """Generate Redis key for scan status."""
        return f"scan:{scan_id}:status"

    def _get_state_key(self, scan_id: str) -> str:
        """Generate Redis key for scan state."""
        return f"scan:{scan_id}:state"
