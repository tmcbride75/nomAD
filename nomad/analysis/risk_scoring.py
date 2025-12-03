"""
Risk Scoring Module
===================

Heuristic-based risk assessment for attack paths.

Scoring Factors:
- Path length (shorter = higher risk)
- Privilege gained (Domain Admin = highest)
- Edge types used (easier exploits = higher risk)
- Sensitive nodes traversed
- Special conditions (Kerberoastable, DCSync, etc.)

Output:
- risk_score: 0-100 numeric score
- risk_level: Categorical (Critical, High, Medium, Low, Info)

Design Decisions:
-----------------
1. Scoring is deterministic and reproducible
2. Weights are configurable for different environments
3. Multiple factors are combined using weighted average
4. Special conditions can override base scores
"""

from ..model.schemas import (
    AttackPath, ADEdge, EdgeType, RiskLevel, 
    User, Group, Computer, NodeType
)
from ..model.graph_builder import ADGraph
from ..config import AnalysisConfig


class RiskScorer:
    """Calculates risk scores for attack paths.
    
    Usage:
        scorer = RiskScorer(graph, config)
        
        # Score a single path
        scored_path = scorer.score_path(attack_path)
        
        # Score multiple paths
        scored_paths = scorer.score_paths(paths)
    
    Scoring Philosophy:
        A path is more dangerous when:
        1. It's short (fewer steps = faster compromise)
        2. It leads to high privilege (DA > local admin)
        3. It uses easily exploitable edges (ACLs > sessions)
        4. It starts from an easily compromised account
    """
    
    def __init__(self, graph: ADGraph, config: AnalysisConfig = None):
        """Initialize the risk scorer.
        
        Args:
            graph: ADGraph containing the environment data
            config: Analysis configuration
        """
        self.graph = graph
        self.config = config or AnalysisConfig()
        
        # Privilege gain scores (out of 40)
        self.privilege_scores = {
            "Domain Admin": 40,
            "Enterprise Admin": 40,
            "Domain Admin (via group)": 38,
            "Enterprise Admin (via group)": 38,
            "Domain Controller": 35,
            "DCSync (Domain Credential Dump)": 40,
            "Local Administrator (via group)": 25,
            "Unconstrained Delegation": 30,
            "High-Value Group": 25,
            "Privileged User": 20,
            "Computer": 15,
            "User Account": 10,
            "Group Membership": 10,
        }
        
        # Edge type risk scores (1-10, higher = easier/more dangerous)
        self.edge_risk_scores = {
            EdgeType.MEMBER_OF: 9,           # Trivial - group membership
            EdgeType.GENERIC_ALL: 9,         # Full control
            EdgeType.WRITE_DACL: 8,          # Can modify ACL
            EdgeType.WRITE_OWNER: 8,         # Can take ownership
            EdgeType.FORCE_CHANGE_PASSWORD: 8, # Password reset
            EdgeType.ADD_MEMBER: 8,          # Add to group
            EdgeType.OWNS: 8,                # Ownership
            EdgeType.GENERIC_WRITE: 7,       # Write access
            EdgeType.ALL_EXTENDED_RIGHTS: 7, # Extended rights
            EdgeType.GET_CHANGES_ALL: 9,     # DCSync
            EdgeType.GET_CHANGES: 6,         # DCSync prep
            EdgeType.ADD_KEY_CREDENTIAL_LINK: 8, # Shadow credentials
            EdgeType.READ_LAPS_PASSWORD: 7,  # LAPS read
            EdgeType.READ_GMSA_PASSWORD: 7,  # GMSA read
            EdgeType.ADMIN_TO: 6,            # Admin access
            EdgeType.CAN_RDP: 5,             # RDP access
            EdgeType.CAN_PSREMOTE: 5,        # PSRemote
            EdgeType.EXECUTE_DCOM: 5,        # DCOM
            EdgeType.HAS_SESSION: 4,         # Session (needs cred theft)
            EdgeType.ALLOWED_TO_DELEGATE: 5, # Delegation
            EdgeType.ALLOWED_TO_ACT: 5,      # RBCD
            EdgeType.HAS_SID_HISTORY: 7,     # SID history
            EdgeType.SQL_ADMIN: 5,           # SQL admin
            EdgeType.CONTAINS: 2,            # Container
            EdgeType.GP_LINK: 4,             # GPO link
            EdgeType.TRUSTED_BY: 4,          # Trust
        }
    
    def score_path(self, path: AttackPath) -> AttackPath:
        """Calculate risk score for an attack path.
        
        Scoring Components (total 100):
        - Privilege gain: 0-40 points
        - Path length: 0-30 points (shorter = more points)
        - Edge exploitability: 0-20 points
        - Special conditions: 0-10 bonus points
        
        Args:
            path: AttackPath to score
            
        Returns:
            Same AttackPath with risk_score and risk_level set
        """
        score = 0.0
        
        # 1. Privilege gain score (0-40)
        privilege_score = self._score_privilege_gain(path.privilege_gain)
        score += privilege_score
        
        # 2. Path length score (0-30)
        # Shorter paths are more dangerous
        length_score = self._score_path_length(path.estimated_steps)
        score += length_score
        
        # 3. Edge exploitability score (0-20)
        edge_score = self._score_edges(path.edges)
        score += edge_score
        
        # 4. Special conditions bonus (0-10)
        special_score = self._score_special_conditions(path)
        score += special_score
        
        # Ensure score is in range [0, 100]
        path.risk_score = min(100.0, max(0.0, score))
        path.risk_level = RiskLevel.from_score(path.risk_score)
        
        return path
    
    def score_paths(self, paths: list[AttackPath]) -> list[AttackPath]:
        """Score multiple paths (preserves order).
        
        Args:
            paths: List of AttackPath objects
            
        Returns:
            List of scored paths (same order as input)
        """
        return [self.score_path(path) for path in paths]
    
    def _score_privilege_gain(self, privilege_gain: str) -> float:
        """Score based on what privilege is gained.
        
        Args:
            privilege_gain: Description of privilege gained
            
        Returns:
            Score from 0-40
        """
        # Check exact matches first
        for key, score in self.privilege_scores.items():
            if key.lower() in privilege_gain.lower():
                return float(score)
        
        # Default score for unknown privileges
        return 10.0
    
    def _score_path_length(self, steps: int) -> float:
        """Score based on path length.
        
        Shorter paths = higher score (more dangerous).
        
        Args:
            steps: Number of steps in the path
            
        Returns:
            Score from 0-30
        """
        if steps <= 1:
            return 30.0  # Direct access
        elif steps == 2:
            return 27.0
        elif steps == 3:
            return 24.0
        elif steps == 4:
            return 20.0
        elif steps == 5:
            return 15.0
        elif steps <= 7:
            return 10.0
        elif steps <= 10:
            return 5.0
        else:
            return 2.0  # Very long paths are less practical
    
    def _score_edges(self, edges: list[ADEdge]) -> float:
        """Score based on edge types used.
        
        More exploitable edges = higher score.
        
        Args:
            edges: List of edges in the path
            
        Returns:
            Score from 0-20
        """
        if not edges:
            return 0.0
        
        # Calculate average edge risk
        total_risk = 0.0
        for edge in edges:
            total_risk += self.edge_risk_scores.get(edge.edge_type, 5)
        
        avg_risk = total_risk / len(edges)
        
        # Scale to 0-20
        return (avg_risk / 10.0) * 20.0
    
    def _score_special_conditions(self, path: AttackPath) -> float:
        """Score bonus for special dangerous conditions.
        
        Args:
            path: AttackPath to check
            
        Returns:
            Bonus score from 0-10
        """
        bonus = 0.0
        
        # Kerberoastable start
        if path.properties.get('kerberoastable_start'):
            bonus += 3.0
        
        # DCSync path
        if path.properties.get('dcsync_path'):
            bonus += 5.0
        
        # Authenticated user path (starting from real user context)
        if path.properties.get('from_authenticated_user'):
            bonus += 5.0
        
        # Check for dangerous edge combinations
        edge_types = [e.edge_type for e in path.edges]
        
        # GenericAll + anything = very dangerous
        if EdgeType.GENERIC_ALL in edge_types:
            bonus += 2.0
        
        # DCSync edges
        if EdgeType.GET_CHANGES_ALL in edge_types:
            bonus += 3.0
        
        # Shadow credentials
        if EdgeType.ADD_KEY_CREDENTIAL_LINK in edge_types:
            bonus += 2.0
        
        return min(10.0, bonus)  # Cap at 10
    
    def calculate_environment_risk(self) -> dict:
        """Calculate overall environment risk metrics.
        
        Returns:
            Dictionary with environment risk statistics
        """
        stats = self.graph.get_environment_stats()
        
        # Calculate risk factors
        risk_factors = {}
        
        # DA:User ratio (more DAs = higher risk)
        if stats.total_users > 0:
            da_ratio = stats.domain_admin_count / stats.total_users
            risk_factors['da_ratio'] = min(100, da_ratio * 1000)  # Scale
        
        # Kerberoastable users
        if stats.total_users > 0:
            kerb_ratio = stats.kerberoastable_users / stats.total_users
            risk_factors['kerberoastable_ratio'] = min(100, kerb_ratio * 200)
        
        # Unconstrained delegation
        risk_factors['unconstrained_count'] = min(100, stats.unconstrained_delegation_count * 10)
        
        # Disabled users (attack surface)
        if stats.total_users > 0:
            disabled_ratio = stats.disabled_users / stats.total_users
            risk_factors['disabled_ratio'] = disabled_ratio * 50
        
        # Calculate overall environment score
        if risk_factors:
            overall_score = sum(risk_factors.values()) / len(risk_factors)
        else:
            overall_score = 50.0
        
        return {
            'environment_stats': stats.to_dict(),
            'risk_factors': risk_factors,
            'overall_environment_risk': overall_score,
            'risk_level': RiskLevel.from_score(overall_score).value
        }
    
    def rank_paths(self, paths: list[AttackPath]) -> list[AttackPath]:
        """Rank paths by risk and deduplicate similar paths.
        
        Args:
            paths: List of scored AttackPath objects
            
        Returns:
            Deduplicated and ranked list
        """
        # First, score all paths
        scored = self.score_paths(paths)
        
        # Deduplicate based on similar targets and steps
        seen_patterns = set()
        unique_paths = []
        
        for path in scored:
            # Create a pattern key: target + edge types
            edge_pattern = tuple(e.edge_type for e in path.edges)
            pattern_key = (path.privilege_gain, edge_pattern)
            
            if pattern_key not in seen_patterns:
                seen_patterns.add(pattern_key)
                unique_paths.append(path)
        
        return unique_paths

