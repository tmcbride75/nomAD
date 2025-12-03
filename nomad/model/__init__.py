"""
nomAD Model Module
==================

Contains the core data models and graph representation for AD objects.

Key Components:
- schemas.py: Typed dataclasses for AD entities (User, Group, Computer, etc.)
- graph_builder.py: NetworkX-based graph construction and manipulation

Design Philosophy:
- All entities inherit from a common ADNode base class
- Edges are typed and carry metadata about the relationship
- The graph abstraction layer allows future backend swaps
"""

from .schemas import (
    NodeType,
    EdgeType,
    RiskLevel,
    ADNode,
    User,
    Group,
    Computer,
    Domain,
    OU,
    GPO,
    ADEdge,
    AttackPath,
    AnalysisResult
)
from .graph_builder import ADGraph

