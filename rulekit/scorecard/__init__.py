"""Detection-content scorecards.

``dvp rules score`` turns the rule library into a tracked quality metric:
per-rule grades, a library average, and a per-dimension breakdown showing where
the library is systemically weak rather than just which rules are worst.
"""

from __future__ import annotations

from rulekit.scorecard.model import DimensionScore, Grade, LibraryScore, RuleScore
from rulekit.scorecard.scoring import WEIGHTS, ScoringContext, score_library, score_rule

__all__ = [
    "WEIGHTS",
    "DimensionScore",
    "Grade",
    "LibraryScore",
    "RuleScore",
    "ScoringContext",
    "score_library",
    "score_rule",
]
