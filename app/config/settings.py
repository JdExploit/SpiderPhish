"""Application configuration.

- AppSettings: runtime settings persisted to config/app.json (window state, paths,
  analysis parameters). Never stores API keys.
- SecureStore: encrypted storage for API keys (config/secure.json) using Fernet.
  The Fernet key lives in config/.spiderphish.key (generated on first run;
  legacy .jdexploit.key is migrated automatically).
- .env support via python-dotenv for CI/bootstrap; keys set there are imported
  into the secure store on first run if the secure store is empty.
"""
from __future__ import annotations

import base64
import json
import os
from pathlib import Path
from typing import Optional

from dotenv import load_dotenv
from pydantic import BaseModel, Field
from pydantic_settings import BaseSettings

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
CONFIG_DIR = PROJECT_ROOT / "config"
DATA_DIR = PROJECT_ROOT / "data"

load_dotenv(PROJECT_ROOT / ".env")


def _env(name: str, default: str = "") -> str:
    return os.environ.get(name, default)


class AnalysisSettings(BaseModel):
    timeout_seconds: float = 12.0
    retries: int = 2
    max_redirects: int = 10
    concurrent_requests: int = 6
    verify_tls: bool = True
    proxy: str = ""
    allow_internal_targets: bool = False   # SSRF guard; keep False in production


class UISettings(BaseModel):
    log_level: str = "INFO"
    animations: bool = True
    font_size: int = 10


class StorageSettings(BaseModel):
    db_path: str = str(DATA_DIR / "spiderphish.db")
    report_path: str = str(PROJECT_ROOT / "reports")
    case_dir: str = str(PROJECT_ROOT / "cases")


class AppSettings(BaseSettings):
    demo_mode: bool = True
    analyst_name: str = "Operator"
    analysis: AnalysisSettings = Field(default_factory=AnalysisSettings)
    ui: UISettings = Field(default_factory=UISettings)
    storage: StorageSettings = Field(default_factory=StorageSettings)

    # ------------------------------------------------------------------
    @staticmethod
    def path() -> Path:
        CONFIG_DIR.mkdir(parents=True, exist_ok=True)
        return CONFIG_DIR / "app.json"

    def save(self) -> None:
        self.path().write_text(self.model_dump_json(indent=2), encoding="utf-8")

    @classmethod
    def load(cls) -> "AppSettings":
        p = cls.path()
        data: dict = {}
        if p.exists():
            try:
                data = json.loads(p.read_text(encoding="utf-8"))
            except Exception:
                data = {}
        # env overrides (SPIDERPHISH_* preferred, legacy JDEXPLOIT_* accepted)
        def _e(new: str, old: str) -> str:
            return _env(new) or _env(old)
        if _e("SPIDERPHISH_DEMO_MODE", "JDEXPLOIT_DEMO_MODE"):
            data["demo_mode"] = _e("SPIDERPHISH_DEMO_MODE",
                                   "JDEXPLOIT_DEMO_MODE") == "1"
        if _e("SPIDERPHISH_LOG_LEVEL", "JDEXPLOIT_LOG_LEVEL"):
            data.setdefault("ui", {})["log_level"] = _e(
                "SPIDERPHISH_LOG_LEVEL", "JDEXPLOIT_LOG_LEVEL")
        if _e("SPIDERPHISH_DB_PATH", "JDEXPLOIT_DB_PATH"):
            data.setdefault("storage", {})["db_path"] = _e(
                "SPIDERPHISH_DB_PATH", "JDEXPLOIT_DB_PATH")
        # one-time rebrand: repoint a persisted legacy db_path to the new name
        sp = data.get("storage", {})
        bp = sp.get("db_path", "") if isinstance(sp, dict) else ""
        if bp.endswith("jdexploit.db"):
            new_bp = str(Path(bp).with_name("spiderphish.db"))
            sp["db_path"] = new_bp
            data["storage"] = sp
        return cls(**data)


# ----------------------------------------------------------------------
class SecureStore:
    """Fernet-encrypted key/value storage for API keys."""

    _KEY_NAMES = ["ABUSEIPDB_API_KEY", "URLSCAN_API_KEY", "VIRUSTOTAL_API_KEY",
                  "OTX_API_KEY", "GREYNOISE_API_KEY"]

    def __init__(self) -> None:
        from cryptography.fernet import Fernet

        CONFIG_DIR.mkdir(parents=True, exist_ok=True)
        self._store_path = CONFIG_DIR / "secure.json"
        self._key_path = CONFIG_DIR / ".spiderphish.key"
        legacy_key = CONFIG_DIR / ".jdexploit.key"
        if not self._key_path.exists() and legacy_key.exists():
            # rebrand migration: reuse the existing Fernet key so stored
            # API keys keep decrypting; legacy file kept as backup.
            self._key_path.write_bytes(legacy_key.read_bytes())
        if not self._key_path.exists():
            self._key_path.write_bytes(Fernet.generate_key())
        try:
            self._key_path.chmod(0o600)  # best effort on Windows
        except OSError:
            pass
        self._fernet = Fernet(self._key_path.read_bytes())
        self._data: dict[str, str] = {}
        if self._store_path.exists():
            try:
                blob = self._store_path.read_bytes()
                self._data = json.loads(self._fernet.decrypt(blob).decode("utf-8"))
            except Exception:
                self._data = {}
        self._bootstrap_from_env()

    def _bootstrap_from_env(self) -> None:
        """Import keys declared in .env into the encrypted store (first run only)."""
        changed = False
        for name in self._KEY_NAMES:
            val = _env(name)
            if val and not self._data.get(name):
                self._data[name] = val
                changed = True
        if changed:
            self.save()

    def get(self, name: str, default: str | None = None) -> Optional[str]:
        v = self._data.get(name)
        return v if v else default

    def set(self, name: str, value: str) -> None:
        value = value.strip()
        if value:
            self._data[name] = value
        else:
            self._data.pop(name, None)
        self.save()

    def save(self) -> None:
        blob = self._fernet.encrypt(json.dumps(self._data).encode("utf-8"))
        self._store_path.write_bytes(blob)

    @staticmethod
    def mask(value: Optional[str]) -> str:
        if not value:
            return ""
        if len(value) <= 8:
            return "*" * len(value)
        return f"{value[:4]}{'*' * 12}{value[-4:]}"


_secure_store: Optional[SecureStore] = None


def secure_store() -> SecureStore:
    global _secure_store
    if _secure_store is None:
        _secure_store = SecureStore()
    return _secure_store


def b64e(s: str) -> str:
    return base64.b64encode(s.encode()).decode()


def b64d(s: str) -> str:
    return base64.b64decode(s.encode()).decode()
