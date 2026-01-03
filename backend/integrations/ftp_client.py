"""
FTP/SFTP client for fetching targets and uploading reports.
"""

import asyncio
import ftplib
import os
from pathlib import Path
from typing import List, Optional

import paramiko
from loguru import logger

from backend.core.config import settings


class FTPClient:
    """
    FTP/SFTP client for file operations.

    Supports both standard FTP and SFTP protocols.
    Automatically selects protocol based on configuration.
    """

    def __init__(
        self,
        host: Optional[str] = None,
        port: Optional[int] = None,
        username: Optional[str] = None,
        password: Optional[str] = None,
        use_sftp: bool = True,
    ):
        """
        Initialize FTP client.

        Args:
            host: FTP server hostname (defaults to settings.FTP_HOST)
            port: FTP server port (defaults to settings.FTP_PORT)
            username: FTP username (defaults to settings.FTP_USERNAME)
            password: FTP password (defaults to settings.FTP_PASSWORD)
            use_sftp: Whether to use SFTP instead of FTP (default: True)
        """
        self.host = host or settings.FTP_HOST
        self.port = port or settings.FTP_PORT or (22 if use_sftp else 21)
        self.username = username or settings.FTP_USERNAME
        self.password = password or settings.FTP_PASSWORD
        self.use_sftp = use_sftp

        self._ftp_client: Optional[ftplib.FTP] = None
        self._sftp_client: Optional[paramiko.SFTPClient] = None
        self._ssh_client: Optional[paramiko.SSHClient] = None
        self._connected = False

    async def connect(self) -> None:
        """
        Establish connection to FTP/SFTP server.

        Raises:
            ConnectionError: If connection fails
        """
        try:
            if self.use_sftp:
                await self._connect_sftp()
            else:
                await self._connect_ftp()

            self._connected = True
            logger.info(
                f"Connected to {'SFTP' if self.use_sftp else 'FTP'} server at {self.host}:{self.port}"
            )

        except Exception as e:
            logger.error(f"Failed to connect to FTP server: {e}", exc_info=True)
            raise ConnectionError(f"FTP connection failed: {e}")

    async def disconnect(self) -> None:
        """Close connection to FTP/SFTP server."""
        try:
            if self.use_sftp and self._sftp_client:
                self._sftp_client.close()
                if self._ssh_client:
                    self._ssh_client.close()
            elif self._ftp_client:
                self._ftp_client.quit()

            self._connected = False
            logger.info("Disconnected from FTP server")

        except Exception as e:
            logger.warning(f"Error during FTP disconnect: {e}")

    async def fetch_targets(self, remote_path: str) -> List[str]:
        """
        Fetch targets from a file on FTP server.

        Args:
            remote_path: Path to targets file on FTP server

        Returns:
            List of target strings (one per line)

        Raises:
            ConnectionError: If not connected
            FileNotFoundError: If remote file doesn't exist
        """
        if not self._connected:
            raise ConnectionError("Not connected to FTP server")

        try:
            # Download file to temporary location
            local_path = f"/tmp/targets_{os.getpid()}.txt"

            if self.use_sftp:
                await self._sftp_get(remote_path, local_path)
            else:
                await self._ftp_get(remote_path, local_path)

            # Read targets from file
            with open(local_path, "r") as f:
                targets = [line.strip() for line in f if line.strip()]

            # Clean up temp file
            os.remove(local_path)

            logger.info(f"Fetched {len(targets)} targets from {remote_path}")
            return targets

        except Exception as e:
            logger.error(f"Error fetching targets from FTP: {e}", exc_info=True)
            raise

    async def upload_report(
        self, local_path: str, remote_path: str
    ) -> bool:
        """
        Upload report file to FTP server.

        Args:
            local_path: Path to local report file
            remote_path: Destination path on FTP server

        Returns:
            True if upload successful

        Raises:
            ConnectionError: If not connected
            FileNotFoundError: If local file doesn't exist
        """
        if not self._connected:
            raise ConnectionError("Not connected to FTP server")

        if not os.path.exists(local_path):
            raise FileNotFoundError(f"Local file not found: {local_path}")

        try:
            # Ensure remote directory exists
            remote_dir = str(Path(remote_path).parent)
            await self._ensure_remote_directory(remote_dir)

            # Upload file
            if self.use_sftp:
                await self._sftp_put(local_path, remote_path)
            else:
                await self._ftp_put(local_path, remote_path)

            logger.info(f"Uploaded report to {remote_path}")
            return True

        except Exception as e:
            logger.error(f"Error uploading report to FTP: {e}", exc_info=True)
            raise

    async def list_directory(self, remote_path: str = ".") -> List[str]:
        """
        List files in remote directory.

        Args:
            remote_path: Remote directory path (default: current directory)

        Returns:
            List of filenames

        Raises:
            ConnectionError: If not connected
        """
        if not self._connected:
            raise ConnectionError("Not connected to FTP server")

        try:
            if self.use_sftp:
                files = self._sftp_client.listdir(remote_path)
            else:
                files = self._ftp_client.nlst(remote_path)

            return files

        except Exception as e:
            logger.error(f"Error listing directory {remote_path}: {e}", exc_info=True)
            raise

    # Private methods for SFTP

    async def _connect_sftp(self) -> None:
        """Establish SFTP connection."""
        loop = asyncio.get_event_loop()

        def _connect():
            self._ssh_client = paramiko.SSHClient()
            self._ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            self._ssh_client.connect(
                hostname=self.host,
                port=self.port,
                username=self.username,
                password=self.password,
                timeout=30,
            )
            self._sftp_client = self._ssh_client.open_sftp()

        await loop.run_in_executor(None, _connect)

    async def _sftp_get(self, remote_path: str, local_path: str) -> None:
        """Download file via SFTP."""
        loop = asyncio.get_event_loop()
        await loop.run_in_executor(
            None, self._sftp_client.get, remote_path, local_path
        )

    async def _sftp_put(self, local_path: str, remote_path: str) -> None:
        """Upload file via SFTP."""
        loop = asyncio.get_event_loop()
        await loop.run_in_executor(
            None, self._sftp_client.put, local_path, remote_path
        )

    # Private methods for FTP

    async def _connect_ftp(self) -> None:
        """Establish FTP connection."""
        loop = asyncio.get_event_loop()

        def _connect():
            self._ftp_client = ftplib.FTP()
            self._ftp_client.connect(self.host, self.port, timeout=30)
            self._ftp_client.login(self.username, self.password)

        await loop.run_in_executor(None, _connect)

    async def _ftp_get(self, remote_path: str, local_path: str) -> None:
        """Download file via FTP."""
        loop = asyncio.get_event_loop()

        def _download():
            with open(local_path, "wb") as f:
                self._ftp_client.retrbinary(f"RETR {remote_path}", f.write)

        await loop.run_in_executor(None, _download)

    async def _ftp_put(self, local_path: str, remote_path: str) -> None:
        """Upload file via FTP."""
        loop = asyncio.get_event_loop()

        def _upload():
            with open(local_path, "rb") as f:
                self._ftp_client.storbinary(f"STOR {remote_path}", f)

        await loop.run_in_executor(None, _upload)

    # Shared helper methods

    async def _ensure_remote_directory(self, remote_dir: str) -> None:
        """Ensure remote directory exists, create if needed."""
        if not remote_dir or remote_dir == ".":
            return

        try:
            if self.use_sftp:
                # Try to stat the directory
                try:
                    self._sftp_client.stat(remote_dir)
                except FileNotFoundError:
                    # Directory doesn't exist, create it
                    self._sftp_client.mkdir(remote_dir)
            else:
                # Try to change to directory
                current = self._ftp_client.pwd()
                try:
                    self._ftp_client.cwd(remote_dir)
                    self._ftp_client.cwd(current)  # Go back
                except ftplib.error_perm:
                    # Directory doesn't exist, create it
                    self._ftp_client.mkd(remote_dir)

        except Exception as e:
            logger.warning(f"Could not ensure directory {remote_dir}: {e}")

    def __del__(self):
        """Cleanup on deletion."""
        if self._connected:
            # Run disconnect in sync mode for cleanup
            try:
                if self.use_sftp and self._sftp_client:
                    self._sftp_client.close()
                    if self._ssh_client:
                        self._ssh_client.close()
                elif self._ftp_client:
                    self._ftp_client.quit()
            except:
                pass


class FTPClientPool:
    """
    Pool of FTP connections for concurrent operations.

    Useful when multiple tasks need to access FTP simultaneously.
    """

    def __init__(self, pool_size: int = 5):
        """
        Initialize FTP connection pool.

        Args:
            pool_size: Maximum number of concurrent connections
        """
        self.pool_size = pool_size
        self._pool: List[FTPClient] = []
        self._semaphore = asyncio.Semaphore(pool_size)

    async def get_client(self) -> FTPClient:
        """
        Get an FTP client from the pool.

        Returns:
            Connected FTP client
        """
        async with self._semaphore:
            if self._pool:
                client = self._pool.pop()
            else:
                client = FTPClient()
                await client.connect()

            return client

    async def return_client(self, client: FTPClient) -> None:
        """
        Return FTP client to the pool.

        Args:
            client: FTP client to return
        """
        if len(self._pool) < self.pool_size:
            self._pool.append(client)
        else:
            await client.disconnect()

    async def close_all(self) -> None:
        """Close all connections in the pool."""
        for client in self._pool:
            await client.disconnect()
        self._pool.clear()
