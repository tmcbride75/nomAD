"""
nomAD Reporting Module
======================

Report generation and visualization for analysis results.

Components:
- report_builder.py: Builds structured report objects
- visualization.py: Graph visualizations using networkx/pyvis
- export_html.py: HTML report generation

Design Philosophy:
- Reports are structured data that can be rendered multiple ways
- Visualizations are interactive when possible (HTML/pyvis)
- All outputs are suitable for embedding in the GUI
"""

from .report_builder import ReportBuilder
from .visualization import GraphVisualizer
from .export_html import HTMLExporter

