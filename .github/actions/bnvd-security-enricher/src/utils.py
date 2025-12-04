import logging
import os
import sys
from datetime import datetime
from typing import Any, Dict, Optional

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
    handlers=[logging.StreamHandler(sys.stdout)]
)

logger = logging.getLogger("bnvd-enricher")


def get_env(name: str, default: str = "") -> str:
    return os.environ.get(name, default)


def get_env_bool(name: str, default: bool = False) -> bool:
    value = get_env(name, str(default)).lower()
    return value in ("true", "1", "yes", "on")


def get_env_int(name: str, default: int = 0) -> int:
    try:
        return int(get_env(name, str(default)))
    except ValueError:
        return default


def write_github_output(key: str, value: Any) -> None:
    github_output = os.environ.get("GITHUB_OUTPUT")
    if github_output:
        with open(github_output, "a", encoding="utf-8") as f:
            if isinstance(value, (dict, list)):
                import json
                value = json.dumps(value, ensure_ascii=False)
            f.write(f"{key}={value}\n")
        logger.debug(f"Output set: {key}={value}")


def write_github_summary(content: str) -> None:
    github_step_summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if github_step_summary:
        with open(github_step_summary, "a", encoding="utf-8") as f:
            f.write(content + "\n")


def log_group_start(title: str) -> None:
    print(f"::group::{title}")


def log_group_end() -> None:
    print("::endgroup::")


def log_warning(message: str, file: Optional[str] = None, line: Optional[int] = None) -> None:
    location = ""
    if file:
        location += f" file={file}"
    if line:
        location += f",line={line}"
    print(f"::warning{location}::{message}")


def log_error(message: str, file: Optional[str] = None, line: Optional[int] = None) -> None:
    location = ""
    if file:
        location += f" file={file}"
    if line:
        location += f",line={line}"
    print(f"::error{location}::{message}")


def log_notice(message: str, title: Optional[str] = None) -> None:
    title_str = f" title={title}" if title else ""
    print(f"::notice{title_str}::{message}")


def format_timestamp(dt: Optional[datetime] = None) -> str:
    if dt is None:
        dt = datetime.utcnow()
    return dt.strftime("%Y-%m-%dT%H:%M:%S.000Z")


def parse_timestamp(ts: str) -> Optional[datetime]:
    formats = [
        "%Y-%m-%dT%H:%M:%S.%fZ",
        "%Y-%m-%dT%H:%M:%SZ",
        "%Y-%m-%dT%H:%M:%S.%f",
        "%Y-%m-%dT%H:%M:%S",
        "%Y-%m-%d"
    ]
    for fmt in formats:
        try:
            return datetime.strptime(ts, fmt)
        except ValueError:
            continue
    return None


def sanitize_cve_id(cve_id: Optional[str]) -> Optional[str]:
    """
    Valida e normaliza um ID de CVE.
    
    Formato válido: CVE-YYYY-NNNNN (ex: CVE-2024-12345)
    Retorna None se o ID não for válido.
    """
    if not cve_id:
        return None
    cve_id = cve_id.strip().upper()
    if cve_id.startswith("CVE-"):
        parts = cve_id.split("-")
        if len(parts) == 3:
            try:
                int(parts[1])
                int(parts[2])
                return cve_id
            except ValueError:
                pass
    return None


def sanitize_cwe_id(cwe_id: Optional[str]) -> Optional[str]:
    """
    Valida e normaliza um ID de CWE.
    
    Formato válido: CWE-NNN (ex: CWE-89, CWE-22)
    Retorna None se o ID não for válido.
    """
    if not cwe_id:
        return None
    cwe_id = cwe_id.strip().upper()
    if cwe_id.startswith("CWE-"):
        parts = cwe_id.split("-")
        if len(parts) == 2:
            try:
                int(parts[1])
                return cwe_id
            except ValueError:
                pass
    return None


def get_severity_from_score(score: float) -> str:
    if score >= 9.0:
        return "CRITICAL"
    elif score >= 7.0:
        return "HIGH"
    elif score >= 4.0:
        return "MEDIUM"
    elif score > 0:
        return "LOW"
    return "NONE"


def get_severity_emoji(severity: str) -> str:
    severity_emojis = {
        "CRITICAL": "🔴",
        "HIGH": "🟠",
        "MEDIUM": "🟡",
        "LOW": "🟢",
        "NONE": "⚪"
    }
    return severity_emojis.get(severity.upper(), "⚪")


def get_severity_badge(severity: str) -> str:
    colors = {
        "CRITICAL": "critical",
        "HIGH": "important",
        "MEDIUM": "warning",
        "LOW": "success",
        "NONE": "inactive"
    }
    color = colors.get(severity.upper(), "inactive")
    return f"![{severity}](https://img.shields.io/badge/{severity}-{color})"


def mask_secret(value: str) -> str:
    if len(value) <= 4:
        return "****"
    return value[:2] + "*" * (len(value) - 4) + value[-2:]


class Timer:
    def __init__(self):
        self.start_time = None
        self.end_time = None

    def start(self) -> "Timer":
        self.start_time = datetime.utcnow()
        return self

    def stop(self) -> float:
        self.end_time = datetime.utcnow()
        return self.elapsed

    @property
    def elapsed(self) -> float:
        if self.start_time is None:
            return 0.0
        end = self.end_time or datetime.utcnow()
        return (end - self.start_time).total_seconds()

    def __str__(self) -> str:
        elapsed = self.elapsed
        if elapsed < 60:
            return f"{elapsed:.2f}s"
        minutes = int(elapsed // 60)
        seconds = elapsed % 60
        return f"{minutes}m {seconds:.2f}s"
