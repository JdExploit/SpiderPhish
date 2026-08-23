"""Shared application context wired once at startup."""
from __future__ import annotations

from typing import Optional

from PySide6.QtCore import QObject, Signal


class AppContext(QObject):
    """Dependency container passed to every page."""

    analysis_ready = Signal(object)     # EmailAnalysis
    save_case_suggested = Signal(str)   # case_id

    def __init__(self, settings=None, registry=None, analyzer=None,
                 redirect_analyzer=None, db=None) -> None:
        super().__init__()
        self.settings = settings
        self.registry = registry
        self.analyzer = analyzer
        self.redirect_analyzer = redirect_analyzer
        self.db = db
        self.provider_summary: dict = {}
        self.last_analysis = None          # latest EmailAnalysis (for correlation)

    def refresh_providers(self) -> dict:
        from app.integrations.registry import configured_summary
        self.provider_summary = configured_summary(self.registry)
        return dict(self.provider_summary)

    def log_console_append(self, ts: str, level: str, msg: str) -> None:
        # convenience hook; the LogBus handles real routing
        pass

    def save_current_case(self, analysis, notes: str = "",
                          tags: list[str] | None = None) -> str:
        from datetime import datetime
        case_id = analysis.case_id
        urls = [u.url for u in analysis.urls[:20]]
        domains = sorted({d for d in analysis.domains.keys()})
        self.db.save_case({
            "id": case_id,
            "created_at": analysis.analyzed_at or datetime.now().isoformat(timespec="seconds"),
            "analyst": analysis.analyst,
            "severity": analysis.risk.band.value,
            "sender": analysis.from_addr,
            "origin_ip": analysis.origin_ip.ip,
            "domains": domains,
            "urls": urls,
            "verdict": analysis.risk.verdict,
            "risk_score": analysis.risk.score,
            "notes": notes,
            "tags": tags or [],
            "analysis_json": {"analysis": analysis.model_dump()},
        })
        try:
            self.db.execute(
                """INSERT INTO emails (case_id, analyzed_at, subject, from_addr,
                   return_path, reply_to, message_id, size_bytes)
                   VALUES (?,?,?,?,?,?,?,?)""",
                (case_id, analysis.analyzed_at, analysis.subject, analysis.from_addr,
                 analysis.return_path, analysis.reply_to, analysis.message_id,
                 analysis.size_bytes))
            for ioc in analysis.iocs[:100]:
                self.db.execute(
                    "INSERT INTO iocs (case_id, type, value, context, severity) "
                    "VALUES (?,?,?,?,?)",
                    (case_id, ioc.type.value, ioc.value, ioc.context,
                     ioc.severity.value))
            for u in analysis.urls[:50]:
                self.db.execute(
                    "INSERT INTO urls (case_id, url, domain, final_url, "
                    "redirect_count, risk_level, flags) VALUES (?,?,?,?,?,?,?)",
                    (case_id, u.url, u.domain, u.final_url, u.redirect_count,
                     u.risk_level.value, ",".join(u.flags)))
            for dname, d in list(analysis.domains.items())[:20]:
                self.db.execute(
                    "INSERT INTO domains (case_id, domain, registrar, creation_date,"
                    " age_days, flags) VALUES (?,?,?,?,?,?)",
                    (case_id, dname, d.registrar, d.creation_date, d.age_days,
                     ",".join(d.flags)))
            if analysis.origin_ip.ip:
                r = analysis.ip_reputation
                self.db.execute(
                    "INSERT INTO ip_reputation (case_id, ip, provider, score, verdict,"
                    " country, isp) VALUES (?,?,?,?,?,?,?)",
                    (case_id, analysis.origin_ip.ip, r.provider, r.score,
                     (r.band.value if r.score is not None else r.verdict.value),
                     r.country, r.isp))
        except Exception as e:  # noqa: BLE001
            from app.core.logging_setup import get_logger
            get_logger("ctx").warning("Case persistence partial failure: %s", e)
        return case_id


def build_context() -> AppContext:
    from app.analyzers.email_analyzer import EmailAnalyzer
    from app.config.settings import AppSettings
    from app.core.database import get_db
    from app.core.logging_setup import setup_logging
    from app.integrations.registry import build_registry

    settings = AppSettings.load()
    setup_logging(settings.ui.log_level)
    db = get_db()
    registry = build_registry()
    ctx = AppContext(settings=settings, registry=registry, db=db)
    ctx.redirect_analyzer = __import__(
        "app.analyzers.redirect_analyzer", fromlist=["RedirectAnalyzer"]
    ).RedirectAnalyzer(settings)
    ctx.analyzer = EmailAnalyzer(settings, registry)
    ctx.refresh_providers()
    return ctx
