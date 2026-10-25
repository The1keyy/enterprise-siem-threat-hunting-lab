"""Explainable risk score. Weights and multipliers come from Settings."""

from decimal import ROUND_HALF_UP, Decimal

from app.core.config import Settings


def final_score(subtotal: int, multiplier: float) -> int:
    """Match JavaScript Math.round for positive fixture scores."""

    value = Decimal(subtotal) * Decimal(str(multiplier))
    return int(value.to_integral_value(rounding=ROUND_HALF_UP))


def severity_band(score: int, settings: Settings) -> str:
    if score >= settings.severity_critical:
        return "critical"
    if score >= settings.severity_high:
        return "high"
    if score >= settings.severity_medium:
        return "medium"
    if score > 0:
        return "low"
    return "info"
