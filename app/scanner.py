from dataclasses import dataclass
import logging
import os
import socket
import struct

logger = logging.getLogger("sentinel.scanner")

EICAR_MARKER = b"EICAR-STANDARD-ANTIVIRUS-TEST-FILE"
DEFAULT_TIMEOUT_SECONDS = 5.0


@dataclass
class ScanResult:
    status: str
    engine: str
    detail: str


def _scan_mock(filename: str, content: bytes) -> ScanResult:
    lowered = filename.lower()
    if EICAR_MARKER in content:
        return ScanResult(
            status="malicious",
            engine="mock",
            detail="EICAR test signature detected",
        )
    if "malicious" in lowered or "eicar" in lowered:
        return ScanResult(
            status="malicious",
            engine="mock",
            detail="Filename pattern flagged by mock policy",
        )
    return ScanResult(status="clean", engine="mock", detail="No signature matched")


def _scan_clamav(content: bytes) -> ScanResult:
    host = os.getenv("CLAMAV_HOST", "clamav")
    port = int(os.getenv("CLAMAV_PORT", "3310"))
    timeout = float(os.getenv("CLAMAV_TIMEOUT_SECONDS", str(DEFAULT_TIMEOUT_SECONDS)))
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            sock.sendall(b"zINSTREAM\0")
            # Send one chunk then terminate stream. ClamAV expects a 4-byte size prefix.
            sock.sendall(struct.pack(">I", len(content)))
            sock.sendall(content)
            sock.sendall(struct.pack(">I", 0))
            response = sock.recv(4096).decode("utf-8", errors="replace").strip()
    except Exception as exc:
        # Log full detail internally; keep API response free of infrastructure info.
        logger.warning("ClamAV connection failed (host=%s port=%s): %s", host, port, exc)
        return ScanResult(status="error", engine="clamav", detail="ClamAV unavailable")

    if "FOUND" in response:
        signature = response.split("FOUND")[0].split(":")[-1].strip()
        return ScanResult(
            status="malicious",
            engine="clamav",
            detail=f"Signature detected: {signature}",
        )
    if "OK" in response:
        return ScanResult(status="clean", engine="clamav", detail="No signature matched")
    if "ERROR" in response:
        return ScanResult(status="error", engine="clamav", detail=response)
    return ScanResult(status="error", engine="clamav", detail=f"Unexpected response: {response}")


def scan_bytes(filename: str, content: bytes) -> ScanResult:
    """
    Scan mode:
    - mock: always use mock scanner
    - clamav: require ClamAV, return error on scanner failure
    - auto (default): try ClamAV, fallback to mock if unavailable
    """
    mode = os.getenv("SCANNER_MODE", "auto").strip().lower()
    if mode == "mock":
        return _scan_mock(filename, content)
    if mode == "clamav":
        return _scan_clamav(content)

    # auto mode
    clamav = _scan_clamav(content)
    if clamav.status == "error":
        mock = _scan_mock(filename, content)
        mock.detail = f"{mock.detail} (fallback: ClamAV unavailable)"
        return mock
    return clamav
