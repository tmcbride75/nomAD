"""
Attack Path Finder
==================

Simple pivot-chain discovery for Active Directory attack paths.

This module finds direct user-to-user attack chains:
- Start from owned user
- Find direct takeover permissions to other users
- Pivot to newly owned users
- Repeat until no more pivots possible

Design: Keep it simple - focus on actionable pivot chains, not complex graph theory.
"""

from typing import Optional, Set, List, Tuple
import uuid

import networkx as nx

from ..model.graph_builder import ADGraph
from ..model.schemas import (
    ADNode, ADEdge, NodeType, EdgeType, 
    AttackPath, User, Group, Computer
)
from ..config import AnalysisConfig

# Edge types that allow "taking over" another principal
TAKEOVER_EDGES = {
    EdgeType.GENERIC_ALL,
    EdgeType.GENERIC_WRITE,
    EdgeType.WRITE_OWNER,
    EdgeType.WRITE_DACL,
    EdgeType.FORCE_CHANGE_PASSWORD,
    EdgeType.ALL_EXTENDED_RIGHTS,
    EdgeType.ADD_KEY_CREDENTIAL_LINK,
    EdgeType.OWNS,
    EdgeType.GET_CHANGES_ALL,  # DCSync
}


class AttackPathFinder:
    """Simple pivot-chain discovery for AD attack paths.
    
    Usage:
        finder = AttackPathFinder(graph)
        chain = finder.find_pivot_chain("olivia_sid")
        # Returns: [(olivia, GenericAll, michael), (michael, ForceChangePassword, benjamin), ...]
    """
    
    def __init__(self, graph: ADGraph, config: Optional[AnalysisConfig] = None):
        """Initialize the path finder.
        
        Args:
            graph: ADGraph to analyze
            config: Analysis configuration (uses defaults if None)
        """
        self.graph = graph
        self.config = config or AnalysisConfig()
    
    def find_pivot_chain(self, start_user_id: str) -> List[AttackPath]:
        """Find the pivot chain from a starting user.
        
        This method finds attack paths by:
        1. Direct permissions from user to other users
        2. Permissions inherited via group membership
        3. Chains through groups (User → Group → Target)
        4. Group escalation (User's group → control over privileged group)
        
        Args:
            start_user_id: SID of the starting (owned) user
            
        Returns:
            List of AttackPath objects representing each pivot
        """
        paths = []
        owned_principals = {start_user_id}  # Users/groups we control
        queue = [start_user_id]  # Principals to check for pivots
        processed = set()  # Avoid reprocessing
        group_escalation_shown = set()  # Track which group escalations we've shown
        goal_reached = False  # Stop once we reach Domain Admins or equivalent
        
        while queue and not goal_reached:
            current_id = queue.pop(0)
            
            if current_id in processed:
                continue
            processed.add(current_id)
            
            current_node = self.graph.get_node(current_id)
            current_name = current_node.name if current_node else self.graph.get_node_name(current_id)
            
            # Get all groups this principal is a member of (to check inherited permissions)
            member_groups = self._get_member_groups(current_id)
            
            # Check for group escalation paths (e.g., DirManagement → Domain Admins)
            for group_id in member_groups:
                if goal_reached:
                    break
                    
                group_node = self.graph.get_node(group_id)
                if not group_node:
                    continue
                group_name = group_node.name
                
                # Check if this group has control over privileged groups
                for edge in self.graph.get_outgoing_edges(group_id):
                    if goal_reached:
                        break
                        
                    if edge.edge_type not in TAKEOVER_EDGES:
                        continue
                    
                    target = self.graph.get_node(edge.target_id)
                    if not target or target.node_type != NodeType.GROUP:
                        continue
                    
                    target_name = target.name
                    
                    # Is this a high-value group?
                    if self._is_high_value_group(target_name):
                        escalation_key = f"{current_id}-{edge.target_id}"
                        if escalation_key not in group_escalation_shown:
                            group_escalation_shown.add(escalation_key)
                            
                            # Create path showing the intermediate group (e.g., DirManagement)
                            # Path: User → [MemberOf] → IntermediateGroup → [Permission] → TargetGroup
                            path = AttackPath(
                                id=str(uuid.uuid4())[:8],
                                nodes=[current_id, group_id, edge.target_id],  # Include intermediate group
                                edges=[edge],
                                estimated_steps=2,
                                privilege_gain=f"Join {target_name}",
                                raw_explanation=f"{current_name} → [MemberOf] → {group_name} → [{edge.edge_type.value}] → {target_name}",
                                properties={
                                    'source_name': current_name,
                                    'target_name': target_name,
                                    'edge_type': 'AddSelfToGroup',
                                    'via_group': group_name,
                                    'via_group_id': group_id,
                                    'target_group': target_name,
                                    'permission_type': edge.edge_type.value,
                                    'intermediate_group': group_name,  # The misconfigured group
                                }
                            )
                            paths.append(path)
                            owned_principals.add(edge.target_id)
                            
                            # Check if we've reached the goal (Domain Admins, etc.)
                            if self._is_goal_reached(target_name):
                                goal_reached = True
                                break
            
            # Stop if we've reached the goal
            if goal_reached:
                break
            
            # Check permissions from this principal AND all groups they're in
            principals_to_check = [current_id] + list(member_groups)
            
            for principal_id in principals_to_check:
                if goal_reached:
                    break
                principal_node = self.graph.get_node(principal_id)
                principal_name = principal_node.name if principal_node else self.graph.get_node_name(principal_id)
                
                # Find all takeover edges from this principal
                for edge in self.graph.get_outgoing_edges(principal_id):
                    # Only consider takeover edges
                    if edge.edge_type not in TAKEOVER_EDGES:
                        continue
                    
                    target = self.graph.get_node(edge.target_id)
                    if not target:
                        continue
                    
                    # Skip if already owned
                    if edge.target_id in owned_principals:
                        continue
                    
                    target_name = target.name if target else self.graph.get_node_name(edge.target_id)
                    
                    # Handle based on target type
                    if target.node_type == NodeType.USER:
                        # Direct user takeover
                        via_group = f" (via {principal_name})" if principal_id != current_id else ""
                        
                        path = AttackPath(
                            id=str(uuid.uuid4())[:8],
                            nodes=[current_id, edge.target_id],
                            edges=[edge],
                            estimated_steps=1,
                            privilege_gain=f"Takeover of {target_name}",
                            raw_explanation=f"{current_name} → [{edge.edge_type.value}]{via_group} → {target_name}",
                            properties={
                                'source_name': current_name,
                                'target_name': target_name,
                                'edge_type': edge.edge_type.value,
                                'pivot_from': current_id,
                                'via_group': principal_name if principal_id != current_id else None,
                            }
                        )
                        paths.append(path)
                        
                        # Add to owned and queue for further pivoting
                        owned_principals.add(edge.target_id)
                        queue.append(edge.target_id)
                    
                    elif target.node_type == NodeType.GROUP:
                        # We have control over a group - check what members it has
                        # and what permissions those members grant
                        via_group = f" (via {principal_name})" if principal_id != current_id else ""
                        
                        # Check if this group has permissions over users
                        group_targets = self._get_group_takeover_targets(edge.target_id, owned_principals)
                        
                        for group_target_edge, group_target_node in group_targets:
                            if group_target_node.node_type == NodeType.USER:
                                target_user_name = group_target_node.name if group_target_node else self.graph.get_node_name(group_target_edge.target_id)
                                
                                # Determine the effective attack type
                                # GenericAll on group + target is service account = Kerberoast
                                effective_edge_type = group_target_edge.edge_type.value
                                attack_method = "PasswordChange"
                                
                                # Check if target might be a service account (for kerberoasting)
                                if '_svc' in target_user_name.lower() or 'svc_' in target_user_name.lower() or 'service' in target_user_name.lower():
                                    attack_method = "Kerberoast"
                                
                                path = AttackPath(
                                    id=str(uuid.uuid4())[:8],
                                    nodes=[current_id, edge.target_id, group_target_edge.target_id],
                                    edges=[edge, group_target_edge],
                                    estimated_steps=2,
                                    privilege_gain=f"Takeover of {target_user_name}",
                                    raw_explanation=f"{current_name} → [{edge.edge_type.value}]{via_group} → {target_name} → [{effective_edge_type}] → {target_user_name}",
                                    properties={
                                        'source_name': current_name,
                                        'target_name': target_user_name,
                                        'edge_type': effective_edge_type,
                                        'via_group': target_name,
                                        'attack_method': attack_method,
                                    }
                                )
                                paths.append(path)
                                
                                owned_principals.add(group_target_edge.target_id)
                                queue.append(group_target_edge.target_id)
                        
                        # Also add the group itself to owned
                        owned_principals.add(edge.target_id)
        
        return paths
    
    def _get_member_groups(self, principal_id: str) -> Set[str]:
        """Get all groups a principal is a member of (including nested).
        
        Args:
            principal_id: SID of the principal
            
        Returns:
            Set of group SIDs
        """
        groups = set()
        queue = [principal_id]
        visited = set()
        
        while queue:
            current = queue.pop(0)
            if current in visited:
                continue
            visited.add(current)
            
            # Find MemberOf edges
            for edge in self.graph.get_outgoing_edges(current):
                if edge.edge_type == EdgeType.MEMBER_OF:
                    target = self.graph.get_node(edge.target_id)
                    if target and target.node_type == NodeType.GROUP:
                        groups.add(edge.target_id)
                        queue.append(edge.target_id)  # Check nested groups
        
        return groups
    
    def _get_group_takeover_targets(self, group_id: str, already_owned: Set[str]) -> List[Tuple[ADEdge, ADNode]]:
        """Get users/principals that a group has takeover permissions over.
        
        Args:
            group_id: SID of the group
            already_owned: Set of already owned principals to skip
            
        Returns:
            List of (edge, target_node) tuples
        """
        targets = []
        
        for edge in self.graph.get_outgoing_edges(group_id):
            if edge.edge_type not in TAKEOVER_EDGES:
                continue
            
            if edge.target_id in already_owned:
                continue
            
            target = self.graph.get_node(edge.target_id)
            if target:
                targets.append((edge, target))
        
        return targets
    
    def _is_high_value_group(self, group_name: str) -> bool:
        """Check if a group is considered high-value (privileged).
        
        Args:
            group_name: Name of the group
            
        Returns:
            True if this is a high-value privileged group
        """
        high_value_patterns = [
            'domain admins',
            'enterprise admins',
            'administrators',
            'schema admins',
            'account operators',
            'backup operators',
            'server operators',
            'print operators',
            'dnsadmins',
            'group policy creator',
        ]
        
        name_lower = group_name.lower()
        return any(pattern in name_lower for pattern in high_value_patterns)
    
    def _is_goal_reached(self, group_name: str) -> bool:
        """Check if we've reached a goal group (Domain Admins or equivalent).
        
        Once we reach these groups, there's no need to continue - we own the domain.
        
        Args:
            group_name: Name of the group
            
        Returns:
            True if this is a goal group (stop exploring)
        """
        goal_groups = [
            'domain admins',
            'enterprise admins',
        ]
        
        name_lower = group_name.lower()
        return any(goal in name_lower for goal in goal_groups)
    
    def find_paths_from_user(self, user_id: str, max_paths: int = None) -> List[AttackPath]:
        """Find attack paths from a user - wrapper for compatibility.
        
        Args:
            user_id: Starting user SID
            max_paths: Maximum paths to return (ignored, returns all pivots)
            
        Returns:
            List of AttackPath objects
        """
        return self.find_pivot_chain(user_id)
    
    def find_all_paths_to_high_value(
        self,
        starting_nodes: Optional[Set[str]] = None,
        max_paths: int = None
    ) -> List[AttackPath]:
        """Find paths from starting nodes - wrapper for compatibility."""
        if starting_nodes:
            all_paths = []
            for start_id in starting_nodes:
                all_paths.extend(self.find_pivot_chain(start_id))
            return all_paths
        return []
    
    def get_attack_surface(self, user_id: str) -> dict:
        """Get simple attack surface stats from a user."""
        paths = self.find_pivot_chain(user_id)
        owned_users = {p.nodes[-1] for p in paths}
        owned_users.add(user_id)
        
        return {
            'total_pivots': len(paths),
            'users_owned': len(owned_users),
            'owned_user_names': [
                self.graph.get_node_name(uid) for uid in owned_users
            ]
        }

