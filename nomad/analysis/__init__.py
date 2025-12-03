"""
nomAD Analysis Module
=====================

Deterministic path discovery and risk assessment algorithms.

Components:
- path_finder.py: Graph traversal algorithms for attack path discovery
- risk_scoring.py: Heuristic-based risk assessment
- summarizer.py: Prepares data summaries for AI reasoning

Design Philosophy:
- All analysis works without AI (deterministic first)
- AI is an optional enhancement layer, not a requirement
- Algorithms are optimized for typical AD graph sizes (10k-100k nodes)
"""

from .path_finder import AttackPathFinder
from .risk_scoring import RiskScorer
from .summarizer import AnalysisSummarizer

