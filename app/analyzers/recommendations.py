"""Dynamic recommendations based on real analysis results."""
from __future__ import annotations

from app.models.schemas import EmailAnalysis, Recommendation, Status


def build_recommendations(a: EmailAnalysis) -> list[Recommendation]:
    recs: list[Recommendation] = []
    band = a.risk.band
    high = band.value.startswith(("CRITICAL", "HIGH"))

    if high or band.value == "SUSPICIOUS":
        recs.append(Recommendation(
            title="DO NOT CLICK LINKS",
            detail="No abra ningún enlace del correo. Verifique la legitimidad "
                   "por un canal oficial independiente.",
            priority=Status.CRITICAL if high else Status.SUSPICIOUS))

    for att in a.attachments:
        if att.dangerous:
            recs.append(Recommendation(
                title="Do not download/open attachments",
                detail=f"'{att.filename}' es un tipo de archivo de alto riesgo "
                       f"(.{att.extension}). Analícelo en sandbox antes de "
                       f"cualquier contacto.",
                priority=Status.HIGH))
            break

    if high:
        recs.append(Recommendation(
            title="Block the sender",
            detail=f"Bloquear remitente '{a.from_addr}' en el gateway de correo.",
            priority=Status.HIGH))

    ipr = a.ip_reputation
    if ipr.score is not None and ipr.score >= 60:
        recs.append(Recommendation(
            title="Block origin IP if appropriate",
            detail=f"IP de origen {ipr.ip} con reputación {ipr.score}/100. "
                   f"Evalúe bloqueo en firewall/EDR si no aloja servicios propios.",
            priority=Status.HIGH))

    malicious_domains = sorted({
        u.domain for u in a.urls
        if u.risk_score >= 70 or u.urlscan_malicious or u.urlscan_suspicious} | {
        d for d, di in a.domains.items()
        if any("recently registered" in f.lower() or "Punycode" in f
               for f in di.flags)})
    if malicious_domains and high:
        recs.append(Recommendation(
            title="Block malicious domains",
            detail="Dominios: " + ", ".join(list(malicious_domains)[:6]),
            priority=Status.HIGH))

    cred = any("Credential harvesting" in f for u in a.urls for f in u.flags) \
        or any("Credential" in i.label or "password reset" in i.label.lower()
               for i in a.advanced_detections)
    if cred:
        recs.append(Recommendation(
            title="Reset credentials if submitted",
            detail="Si algún usuario introdujo credenciales en las páginas "
                   "detectadas, fuerce el restablecimiento inmediato y revoque "
                   "tokens/sesiones.",
            priority=Status.CRITICAL))
        recs.append(Recommendation(
            title="Investigate related messages",
            detail="Busque en el entorno correos con los mismos IOCs "
                   "(remitente, dominios, URLs) y elimínelos en cuarentena.",
            priority=Status.HIGH))

    recs.append(Recommendation(
        title="Report the incident",
        detail="Documente el caso y notifíquelo al equipo de seguridad / CSIRT "
               "según su política.",
        priority=Status.INFO))
    return recs
