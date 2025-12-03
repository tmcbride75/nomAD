"""
nomAD GUI Integration Module
============================

Bridge functions for GUI communication.

This module exposes high-level functions that the Streamlit GUI can call
to run analysis and retrieve results.

Key Functions:
- run_analysis(): Main entry point for starting analysis
- get_attack_path_visual(): Get visualization for a specific path
"""

from .bridge import run_analysis, get_attack_path_visual

