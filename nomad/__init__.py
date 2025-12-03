"""
nomAD - AI-Assisted Active Directory Attack-Path Analysis Tool
===============================================================

A Python-based framework for analyzing Active Directory environments,
discovering potential attack paths, and providing AI-enhanced risk assessment.

Architecture Overview:
----------------------
- ingestion/: Parsers for BloodHound JSON, LDAP dumps, and other data sources
- model/: Graph representation and typed data models
- analysis/: Deterministic path discovery and risk scoring algorithms
- ai_engine/: LLM integration for enhanced analysis and explanations
- reporting/: Visualization and report generation
- gui_integration/: Bridge module for Streamlit GUI communication

Design Decisions:
-----------------
1. NetworkX is used as the graph backend for flexibility and rich algorithm support
2. All data models use Python dataclasses for type safety and clarity
3. AI reasoning is optional and can be disabled via configuration
4. The framework supports both LDAP live collection and BloodHound JSON import

Author: nomAD Research Project
License: Research/Educational Use Only
"""

__version__ = "1.0.0"
__author__ = "nomAD Research Team"

from .config import NomadConfig

