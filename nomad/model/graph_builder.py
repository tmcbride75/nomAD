"""
nomAD Graph Builder
===================

NetworkX-based graph representation of Active Directory environments.

Design Decisions:
-----------------
1. Uses NetworkX DiGraph as the underlying data structure
2. Provides a thin abstraction layer to allow future backend swaps
3. Nodes are stored with their full ADNode data as attributes
4. Edges are stored with ADEdge data as attributes
5. Supports efficient querying by node type and edge type

The graph is directed because AD relationships have directionality:
- MemberOf: User -> Group
- AdminTo: User/Group -> Computer
- ACL permissions: Source -> Target

This module is the central data structure that all analysis operates on.
"""

import networkx as nx
from typing import Iterator, Optional, Set
from collections import defaultdict

from .schemas import (
    ADNode, ADEdge, NodeType, EdgeType,
    User, Group, Computer, Domain, OU, GPO,
    EnvironmentStats
)


class ADGraph:
    """Abstraction layer over NetworkX for AD graph operations.
    
    This class provides:
    - Type-safe node/edge operations
    - Efficient queries by node type
    - Path finding utilities
    - Statistics gathering
    
    Design Philosophy:
        The graph is the central data structure. All loaders (BloodHound, LDAP)
        populate this graph, and all analysis operates on it. The abstraction
        allows us to swap NetworkX for a different backend (e.g., Neo4j) if needed.
    
    Example Usage:
        graph = ADGraph()
        graph.add_node(User(object_id="S-1-5-...", name="admin"))
        graph.add_edge(ADEdge(source_id="S-1-5-...", target_id="S-1-5-...", 
                             edge_type=EdgeType.MEMBER_OF))
        
        # Query
        admins = graph.get_nodes_by_type(NodeType.USER)
        paths = graph.find_paths_to_targets(start_id, targets)
    """
    
    def __init__(self):
        """Initialize empty AD graph."""
        self._graph = nx.DiGraph()
        
        # Index structures for efficient queries
        self._nodes_by_type: dict[NodeType, set[str]] = defaultdict(set)
        self._nodes_by_name: dict[str, str] = {}  # name.lower() -> object_id
        self._edges_by_type: dict[EdgeType, set[tuple]] = defaultdict(set)
        
        # Cache for high-value targets
        self._high_value_targets: set[str] = set()
        self._domain_admins: set[str] = set()
        self._enterprise_admins: set[str] = set()
        self._domain_controllers: set[str] = set()
    
    @property
    def nx_graph(self) -> nx.DiGraph:
        """Access underlying NetworkX graph for advanced operations."""
        return self._graph
    
    def add_node(self, node: ADNode) -> None:
        """Add a node to the graph.
        
        Args:
            node: ADNode object (User, Group, Computer, etc.)
        """
        # Add to NetworkX with full node data as attributes
        self._graph.add_node(
            node.object_id,
            node_obj=node,
            node_type=node.node_type,
            name=node.name,
            domain=node.domain,
            **node.properties
        )
        
        # Update indices
        self._nodes_by_type[node.node_type].add(node.object_id)
        if node.name:
            self._nodes_by_name[node.name.lower()] = node.object_id
            if node.domain:
                # Also index with domain suffix
                full_name = f"{node.name}@{node.domain}".lower()
                self._nodes_by_name[full_name] = node.object_id
        
        # Track high-value targets
        self._update_high_value_tracking(node)
    
    def _update_high_value_tracking(self, node: ADNode) -> None:
        """Update high-value target tracking for a node."""
        if isinstance(node, User):
            if node.is_domain_admin:
                self._domain_admins.add(node.object_id)
                self._high_value_targets.add(node.object_id)
            if node.is_enterprise_admin:
                self._enterprise_admins.add(node.object_id)
                self._high_value_targets.add(node.object_id)
        elif isinstance(node, Group):
            if node.is_high_value:
                self._high_value_targets.add(node.object_id)
            # Check for well-known high-value groups by name
            hvt_names = [
                "domain admins", "enterprise admins", "administrators",
                "schema admins", "account operators", "backup operators",
                "server operators", "print operators", "dnsadmins",
                "group policy creator owners"
            ]
            if node.name and node.name.lower() in hvt_names:
                self._high_value_targets.add(node.object_id)
                if "domain admins" in node.name.lower():
                    self._domain_admins.add(node.object_id)
                if "enterprise admins" in node.name.lower():
                    self._enterprise_admins.add(node.object_id)
        elif isinstance(node, Computer):
            if node.is_dc:
                self._domain_controllers.add(node.object_id)
                self._high_value_targets.add(node.object_id)
            if node.is_unconstrained:
                self._high_value_targets.add(node.object_id)
    
    def add_edge(self, edge: ADEdge) -> None:
        """Add an edge to the graph.
        
        Args:
            edge: ADEdge object representing the relationship
            
        Note:
            If source or target nodes don't exist, they are created as UNKNOWN type.
        """
        # Ensure both endpoints exist
        if not self._graph.has_node(edge.source_id):
            self._graph.add_node(edge.source_id, node_type=NodeType.UNKNOWN)
        if not self._graph.has_node(edge.target_id):
            self._graph.add_node(edge.target_id, node_type=NodeType.UNKNOWN)
        
        # Add edge with attributes
        self._graph.add_edge(
            edge.source_id,
            edge.target_id,
            edge_obj=edge,
            edge_type=edge.edge_type,
            **edge.properties
        )
        
        # Update index
        self._edges_by_type[edge.edge_type].add((edge.source_id, edge.target_id))
    
    def get_node(self, object_id: str) -> Optional[ADNode]:
        """Get a node by its object ID.
        
        Args:
            object_id: The node's object ID (SID or GUID)
            
        Returns:
            ADNode object or None if not found
        """
        if not self._graph.has_node(object_id):
            return None
        
        attrs = self._graph.nodes[object_id]
        return attrs.get('node_obj')
    
    def get_node_by_name(self, name: str) -> Optional[ADNode]:
        """Get a node by its name.
        
        Args:
            name: The node's name (case-insensitive)
            
        Returns:
            ADNode object or None if not found
        """
        object_id = self._nodes_by_name.get(name.lower())
        if object_id:
            return self.get_node(object_id)
        return None
    
    def get_node_id_by_name(self, name: str) -> Optional[str]:
        """Get a node's object ID by its name.
        
        Args:
            name: The node's name (case-insensitive)
            
        Returns:
            Object ID string or None if not found
        """
        return self._nodes_by_name.get(name.lower())
    
    def get_edge(self, source_id: str, target_id: str) -> Optional[ADEdge]:
        """Get an edge between two nodes.
        
        Args:
            source_id: Source node object ID
            target_id: Target node object ID
            
        Returns:
            ADEdge object or None if not found
        """
        if not self._graph.has_edge(source_id, target_id):
            return None
        
        attrs = self._graph.edges[source_id, target_id]
        return attrs.get('edge_obj')
    
    def get_nodes_by_type(self, node_type: NodeType) -> Iterator[ADNode]:
        """Iterate over all nodes of a specific type.
        
        Args:
            node_type: NodeType enum value
            
        Yields:
            ADNode objects of the specified type
        """
        for object_id in self._nodes_by_type[node_type]:
            node = self.get_node(object_id)
            if node:
                yield node
    
    def get_edges_by_type(self, edge_type: EdgeType) -> Iterator[ADEdge]:
        """Iterate over all edges of a specific type.
        
        Args:
            edge_type: EdgeType enum value
            
        Yields:
            ADEdge objects of the specified type
        """
        for source_id, target_id in self._edges_by_type[edge_type]:
            edge = self.get_edge(source_id, target_id)
            if edge:
                yield edge
    
    def get_outgoing_edges(self, object_id: str) -> Iterator[ADEdge]:
        """Get all outgoing edges from a node.
        
        Args:
            object_id: Source node object ID
            
        Yields:
            ADEdge objects for outgoing edges
        """
        if not self._graph.has_node(object_id):
            return
        
        for target_id in self._graph.successors(object_id):
            edge = self.get_edge(object_id, target_id)
            if edge:
                yield edge
    
    def get_incoming_edges(self, object_id: str) -> Iterator[ADEdge]:
        """Get all incoming edges to a node.
        
        Args:
            object_id: Target node object ID
            
        Yields:
            ADEdge objects for incoming edges
        """
        if not self._graph.has_node(object_id):
            return
        
        for source_id in self._graph.predecessors(object_id):
            edge = self.get_edge(source_id, object_id)
            if edge:
                yield edge
    
    def get_successors(self, object_id: str) -> Iterator[str]:
        """Get all direct successors of a node.
        
        Args:
            object_id: Source node object ID
            
        Yields:
            Object IDs of successor nodes
        """
        if self._graph.has_node(object_id):
            yield from self._graph.successors(object_id)
    
    def get_predecessors(self, object_id: str) -> Iterator[str]:
        """Get all direct predecessors of a node.
        
        Args:
            object_id: Target node object ID
            
        Yields:
            Object IDs of predecessor nodes
        """
        if self._graph.has_node(object_id):
            yield from self._graph.predecessors(object_id)
    
    def get_high_value_targets(self) -> Set[str]:
        """Get object IDs of all high-value targets."""
        return self._high_value_targets.copy()
    
    def get_domain_admins(self) -> Set[str]:
        """Get object IDs of Domain Admin users/groups."""
        return self._domain_admins.copy()
    
    def get_enterprise_admins(self) -> Set[str]:
        """Get object IDs of Enterprise Admin users/groups."""
        return self._enterprise_admins.copy()
    
    def get_domain_controllers(self) -> Set[str]:
        """Get object IDs of Domain Controller computers."""
        return self._domain_controllers.copy()
    
    def has_path(self, source_id: str, target_id: str) -> bool:
        """Check if a path exists between two nodes.
        
        Args:
            source_id: Starting node object ID
            target_id: Target node object ID
            
        Returns:
            True if a path exists, False otherwise
        """
        if not self._graph.has_node(source_id) or not self._graph.has_node(target_id):
            return False
        return nx.has_path(self._graph, source_id, target_id)
    
    def find_shortest_path(self, source_id: str, target_id: str) -> Optional[list]:
        """Find the shortest path between two nodes.
        
        Args:
            source_id: Starting node object ID
            target_id: Target node object ID
            
        Returns:
            List of node IDs along the path, or None if no path exists
        """
        if not self.has_path(source_id, target_id):
            return None
        
        try:
            return nx.shortest_path(self._graph, source_id, target_id)
        except nx.NetworkXNoPath:
            return None
    
    def find_all_simple_paths(self, source_id: str, target_id: str, 
                              cutoff: int = 10) -> Iterator[list]:
        """Find all simple paths (no repeated nodes) between two nodes.
        
        Args:
            source_id: Starting node object ID
            target_id: Target node object ID
            cutoff: Maximum path length to consider
            
        Yields:
            Lists of node IDs representing paths
        """
        if not self._graph.has_node(source_id) or not self._graph.has_node(target_id):
            return
        
        try:
            yield from nx.all_simple_paths(self._graph, source_id, target_id, cutoff=cutoff)
        except nx.NetworkXNoPath:
            return
    
    def get_reachable_nodes(self, source_id: str, max_depth: int = None) -> Set[str]:
        """Get all nodes reachable from a source node.
        
        Args:
            source_id: Starting node object ID
            max_depth: Maximum traversal depth (None for unlimited)
            
        Returns:
            Set of reachable node object IDs
        """
        if not self._graph.has_node(source_id):
            return set()
        
        if max_depth is None:
            return set(nx.descendants(self._graph, source_id))
        else:
            # BFS with depth limit
            reachable = set()
            queue = [(source_id, 0)]
            visited = {source_id}
            
            while queue:
                current, depth = queue.pop(0)
                if depth < max_depth:
                    for successor in self._graph.successors(current):
                        if successor not in visited:
                            visited.add(successor)
                            reachable.add(successor)
                            queue.append((successor, depth + 1))
            
            return reachable
    
    def get_environment_stats(self) -> EnvironmentStats:
        """Calculate statistics about the AD environment.
        
        Returns:
            EnvironmentStats object with counts and metrics
        """
        stats = EnvironmentStats()
        
        # Count by type
        stats.total_users = len(self._nodes_by_type[NodeType.USER])
        stats.total_groups = len(self._nodes_by_type[NodeType.GROUP])
        stats.total_computers = len(self._nodes_by_type[NodeType.COMPUTER])
        stats.total_domains = len(self._nodes_by_type[NodeType.DOMAIN])
        
        # Count high-value targets
        stats.domain_admin_count = len(self._domain_admins)
        stats.enterprise_admin_count = len(self._enterprise_admins)
        stats.dc_count = len(self._domain_controllers)
        
        # Detailed user statistics
        for user in self.get_nodes_by_type(NodeType.USER):
            if isinstance(user, User):
                if user.enabled:
                    stats.enabled_users += 1
                else:
                    stats.disabled_users += 1
                if user.is_kerberoastable:
                    stats.kerberoastable_users += 1
        
        # Unconstrained delegation count
        for computer in self.get_nodes_by_type(NodeType.COMPUTER):
            if isinstance(computer, Computer) and computer.is_unconstrained:
                stats.unconstrained_delegation_count += 1
        
        return stats
    
    @property
    def node_count(self) -> int:
        """Total number of nodes in the graph."""
        return self._graph.number_of_nodes()
    
    @property
    def edge_count(self) -> int:
        """Total number of edges in the graph."""
        return self._graph.number_of_edges()
    
    def clear(self) -> None:
        """Clear all nodes and edges from the graph."""
        self._graph.clear()
        self._nodes_by_type.clear()
        self._nodes_by_name.clear()
        self._edges_by_type.clear()
        self._high_value_targets.clear()
        self._domain_admins.clear()
        self._enterprise_admins.clear()
        self._domain_controllers.clear()
    
    def get_node_name(self, object_id: str) -> str:
        """Get the display name for a node.
        
        Args:
            object_id: Node object ID
            
        Returns:
            Human-readable name or the object_id if name not available
        """
        node = self.get_node(object_id)
        if node:
            return node.display_name
        
        # Try to get name from graph attributes
        if self._graph.has_node(object_id):
            attrs = self._graph.nodes[object_id]
            return attrs.get('name', object_id)
        
        return object_id
    
    def merge(self, other: "ADGraph") -> None:
        """Merge another graph into this one.
        
        Args:
            other: Another ADGraph to merge
            
        Note:
            Nodes and edges from 'other' will be added. If a node already exists,
            its data will be updated with the new node's data.
        """
        # Merge nodes
        for node_id in other._graph.nodes():
            other_node = other.get_node(node_id)
            if other_node:
                self.add_node(other_node)
        
        # Merge edges
        for source_id, target_id in other._graph.edges():
            other_edge = other.get_edge(source_id, target_id)
            if other_edge:
                self.add_edge(other_edge)
    
    def subgraph(self, node_ids: Set[str]) -> "ADGraph":
        """Create a subgraph containing only specified nodes.
        
        Args:
            node_ids: Set of node object IDs to include
            
        Returns:
            New ADGraph containing only specified nodes and their connecting edges
        """
        subgraph = ADGraph()
        
        # Add nodes
        for node_id in node_ids:
            node = self.get_node(node_id)
            if node:
                subgraph.add_node(node)
        
        # Add edges between included nodes
        for source_id in node_ids:
            for target_id in self.get_successors(source_id):
                if target_id in node_ids:
                    edge = self.get_edge(source_id, target_id)
                    if edge:
                        subgraph.add_edge(edge)
        
        return subgraph
    
    def to_dict(self) -> dict:
        """Convert graph to dictionary for serialization.
        
        Returns:
            Dictionary with 'nodes' and 'edges' keys
        """
        nodes = []
        for node_id in self._graph.nodes():
            node = self.get_node(node_id)
            if node:
                nodes.append({
                    "object_id": node.object_id,
                    "name": node.name,
                    "node_type": node.node_type.value,
                    "domain": node.domain,
                    "properties": node.properties
                })
        
        edges = []
        for source_id, target_id in self._graph.edges():
            edge = self.get_edge(source_id, target_id)
            if edge:
                edges.append({
                    "source_id": edge.source_id,
                    "target_id": edge.target_id,
                    "edge_type": edge.edge_type.value,
                    "properties": edge.properties
                })
        
        return {"nodes": nodes, "edges": edges}

