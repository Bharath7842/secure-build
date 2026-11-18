from app.services.iac_app.scanner.processing.deduplicator import deduplicate_findings
from app.services.iac_app.scanner.processing.risk_engine import calculate_risk
from app.services.iac_app.scanner.processing.compliance import map_compliance
from app.services.iac_app.scanner.processing.suppression import apply_suppressions
from app.services.iac_app.scanner.processing.comparison import compare_findings

__all__ = [
    "deduplicate_findings",
    "calculate_risk",
    "map_compliance",
    "apply_suppressions",
    "compare_findings",
]
