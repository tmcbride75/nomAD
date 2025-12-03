"""
Graph Visualization Module
==========================

Creates visual representations of AD attack paths.

Supports:
- Interactive HTML visualizations (pyvis)
- Static images (matplotlib/networkx)
- SVG exports for high-quality rendering

Design Decisions:
-----------------
1. Default to interactive HTML for better UX
2. Use color coding for node types and risk levels
3. Highlight attack paths clearly
4. Support both full graph and path-specific views
"""

import os
from pathlib import Path
from typing import Optional

import networkx as nx

from ..model.graph_builder import ADGraph
from ..model.schemas import AttackPath, NodeType, EdgeType, RiskLevel


# Color schemes
NODE_COLORS = {
    NodeType.USER: "#4299e1",       # Blue
    NodeType.GROUP: "#48bb78",      # Green
    NodeType.COMPUTER: "#ed8936",   # Orange
    NodeType.DOMAIN: "#9f7aea",     # Purple
    NodeType.OU: "#ecc94b",         # Yellow
    NodeType.GPO: "#f56565",        # Red
    NodeType.UNKNOWN: "#a0aec0",    # Gray
}

RISK_COLORS = {
    RiskLevel.CRITICAL: "#e53e3e",  # Red
    RiskLevel.HIGH: "#ed8936",      # Orange
    RiskLevel.MEDIUM: "#ecc94b",    # Yellow
    RiskLevel.LOW: "#48bb78",       # Green
    RiskLevel.INFO: "#4299e1",      # Blue
}

EDGE_COLORS = {
    EdgeType.MEMBER_OF: "#718096",
    EdgeType.ADMIN_TO: "#e53e3e",
    EdgeType.HAS_SESSION: "#805ad5",
    EdgeType.GENERIC_ALL: "#e53e3e",
    EdgeType.GENERIC_WRITE: "#ed8936",
    EdgeType.WRITE_DACL: "#ed8936",
    EdgeType.WRITE_OWNER: "#ed8936",
    EdgeType.FORCE_CHANGE_PASSWORD: "#f56565",
    EdgeType.GET_CHANGES_ALL: "#e53e3e",
    EdgeType.CAN_RDP: "#4299e1",
    EdgeType.CAN_PSREMOTE: "#4299e1",
}


class GraphVisualizer:
    """Creates visualizations of AD graphs and attack paths.
    
    Usage:
        visualizer = GraphVisualizer(graph, output_dir="output")
        
        # Visualize full graph
        html_path = visualizer.create_full_graph_visualization()
        
        # Visualize specific attack path
        html_path = visualizer.create_path_visualization(attack_path)
        
        # Create static image
        png_path = visualizer.create_path_image(attack_path)
    
    The visualizer supports:
    - Interactive HTML (using pyvis)
    - Static PNG/SVG (using matplotlib)
    - Both full graph and path-specific views
    """
    
    def __init__(
        self,
        graph: ADGraph,
        output_dir: str = "output"
    ):
        """Initialize the visualizer.
        
        Args:
            graph: ADGraph to visualize
            output_dir: Directory for output files
        """
        self.graph = graph
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
    
    def create_path_visualization(
        self,
        path: AttackPath,
        filename: Optional[str] = None,
        include_neighbors: bool = False  # Changed: only show attack path by default
    ) -> str:
        """Create an interactive HTML visualization for an attack path.
        
        Args:
            path: AttackPath to visualize
            filename: Output filename (auto-generated if None)
            include_neighbors: Whether to include neighboring nodes
            
        Returns:
            Path to the generated HTML file
        """
        filename = filename or f"path_{path.id}.html"
        output_path = self.output_dir / filename
        
        try:
            # Try pyvis first (interactive)
            return self._create_pyvis_visualization(path, output_path, include_neighbors)
        except ImportError:
            # Fall back to matplotlib
            return self._create_matplotlib_visualization(path, output_path)
    
    def _create_pyvis_visualization(
        self,
        path: AttackPath,
        output_path: Path,
        include_neighbors: bool
    ) -> str:
        """Create visualization using pyvis library.
        
        Args:
            path: AttackPath to visualize
            output_path: Output file path
            include_neighbors: Whether to include neighboring nodes
            
        Returns:
            Path to generated HTML file
        """
        from pyvis.network import Network
        
        # Create network with custom options
        net = Network(
            height="600px",
            width="100%",
            bgcolor="#1a202c",
            font_color="#e2e8f0",
            directed=True,
            notebook=False
        )
        
        # Configure physics
        net.set_options("""
        {
            "nodes": {
                "font": {
                    "size": 14,
                    "face": "arial"
                },
                "borderWidth": 2,
                "shadow": true
            },
            "edges": {
                "arrows": {
                    "to": {
                        "enabled": true,
                        "scaleFactor": 0.8
                    }
                },
                "color": {
                    "inherit": false
                },
                "smooth": {
                    "type": "curvedCW",
                    "roundness": 0.2
                },
                "font": {
                    "size": 11,
                    "align": "middle"
                }
            },
            "physics": {
                "enabled": true,
                "solver": "forceAtlas2Based",
                "forceAtlas2Based": {
                    "gravitationalConstant": -100,
                    "centralGravity": 0.01,
                    "springLength": 150
                },
                "stabilization": {
                    "iterations": 100
                }
            },
            "interaction": {
                "hover": true,
                "tooltipDelay": 100,
                "navigationButtons": true
            }
        }
        """)
        
        # Collect nodes to include
        path_nodes = set(path.nodes)
        nodes_to_add = set(path.nodes)
        
        # Optionally include neighbors
        if include_neighbors:
            for node_id in path.nodes:
                for neighbor in self.graph.get_successors(node_id):
                    nodes_to_add.add(neighbor)
                for neighbor in self.graph.get_predecessors(node_id):
                    nodes_to_add.add(neighbor)
        
        # Add nodes
        for node_id in nodes_to_add:
            node = self.graph.get_node(node_id)
            
            # Determine visual properties
            if node:
                node_type = node.node_type
                label = node.display_name
                title = self._create_node_tooltip(node)
            else:
                node_type = NodeType.UNKNOWN
                label = self.graph.get_node_name(node_id)
                title = f"ID: {node_id}"
            
            color = NODE_COLORS.get(node_type, "#a0aec0")
            
            # Highlight path nodes
            if node_id in path_nodes:
                size = 30
                border_color = RISK_COLORS.get(path.risk_level, "#e53e3e")
                border_width = 4
                
                # Special styling for start/end
                if node_id == path.nodes[0]:
                    label = f"🎯 {label}"
                    color = "#48bb78"  # Green for start
                elif node_id == path.nodes[-1]:
                    label = f"🏁 {label}"
                    color = "#e53e3e"  # Red for target
            else:
                size = 20
                border_color = color
                border_width = 1
            
            net.add_node(
                node_id,
                label=label,
                title=title,
                color={
                    "background": color,
                    "border": border_color,
                    "highlight": {"background": "#ecc94b", "border": "#d69e2e"}
                },
                size=size,
                borderWidth=border_width,
                shape="dot"
            )
        
        # Add edges
        edges_added = set()
        
        # First, add path edges (highlighted)
        for edge in path.edges:
            if (edge.source_id, edge.target_id) in edges_added:
                continue
            
            edge_color = EDGE_COLORS.get(edge.edge_type, "#718096")
            
            net.add_edge(
                edge.source_id,
                edge.target_id,
                title=edge.edge_type.value,
                label=edge.edge_type.value,
                color={"color": edge_color, "highlight": "#ecc94b"},
                width=3,
                arrows="to"
            )
            edges_added.add((edge.source_id, edge.target_id))
        
        # Add other edges (if including neighbors)
        if include_neighbors:
            for node_id in nodes_to_add:
                for edge in self.graph.get_outgoing_edges(node_id):
                    if edge.target_id in nodes_to_add:
                        if (edge.source_id, edge.target_id) in edges_added:
                            continue
                        
                        net.add_edge(
                            edge.source_id,
                            edge.target_id,
                            title=edge.edge_type.value,
                            color={"color": "#4a5568", "opacity": 0.5},
                            width=1,
                            arrows="to"
                        )
                        edges_added.add((edge.source_id, edge.target_id))
        
        # Generate HTML
        net.save_graph(str(output_path))
        
        # Add custom styling to the generated HTML
        self._enhance_html(output_path, path)
        
        return str(output_path)
    
    def _create_matplotlib_visualization(
        self,
        path: AttackPath,
        output_path: Path
    ) -> str:
        """Create visualization using matplotlib (fallback).
        
        Args:
            path: AttackPath to visualize
            output_path: Output file path
            
        Returns:
            Path to generated image file
        """
        import matplotlib.pyplot as plt
        
        # Create subgraph with path nodes
        G = nx.DiGraph()
        
        # Add nodes
        for node_id in path.nodes:
            G.add_node(node_id)
        
        # Add edges
        for edge in path.edges:
            G.add_edge(edge.source_id, edge.target_id, label=edge.edge_type.value)
        
        # Create figure
        plt.figure(figsize=(12, 8), facecolor='#1a202c')
        ax = plt.gca()
        ax.set_facecolor('#1a202c')
        
        # Layout
        pos = nx.spring_layout(G, k=2, iterations=50)
        
        # Draw nodes
        node_colors = []
        for node_id in G.nodes():
            node = self.graph.get_node(node_id)
            if node:
                node_colors.append(NODE_COLORS.get(node.node_type, "#a0aec0"))
            else:
                node_colors.append("#a0aec0")
        
        nx.draw_networkx_nodes(
            G, pos,
            node_color=node_colors,
            node_size=2000,
            alpha=0.9
        )
        
        # Draw edges
        nx.draw_networkx_edges(
            G, pos,
            edge_color=RISK_COLORS.get(path.risk_level, "#e53e3e"),
            width=2,
            arrows=True,
            arrowsize=20,
            connectionstyle="arc3,rad=0.1"
        )
        
        # Draw labels
        labels = {
            node_id: self.graph.get_node_name(node_id)[:20]
            for node_id in G.nodes()
        }
        nx.draw_networkx_labels(
            G, pos,
            labels=labels,
            font_size=8,
            font_color='white'
        )
        
        # Draw edge labels
        edge_labels = nx.get_edge_attributes(G, 'label')
        nx.draw_networkx_edge_labels(
            G, pos,
            edge_labels=edge_labels,
            font_size=7,
            font_color='#a0aec0'
        )
        
        plt.title(
            f"Attack Path: {path.privilege_gain}",
            color='white',
            fontsize=14,
            pad=20
        )
        
        plt.axis('off')
        plt.tight_layout()
        
        # Save
        png_path = output_path.with_suffix('.png')
        plt.savefig(png_path, facecolor='#1a202c', edgecolor='none', dpi=150)
        plt.close()
        
        return str(png_path)
    
    def _create_node_tooltip(self, node) -> str:
        """Create tooltip HTML for a node.
        
        Args:
            node: ADNode to create tooltip for
            
        Returns:
            HTML tooltip string
        """
        lines = [
            f"<b>{node.display_name}</b>",
            f"Type: {node.node_type.value}",
        ]
        
        if node.distinguished_name:
            lines.append(f"DN: {node.distinguished_name[:50]}...")
        
        # Type-specific info
        if hasattr(node, 'enabled'):
            lines.append(f"Enabled: {node.enabled}")
        
        if hasattr(node, 'is_domain_admin') and node.is_domain_admin:
            lines.append("⚠️ Domain Admin")
        
        if hasattr(node, 'is_dc') and node.is_dc:
            lines.append("🖥️ Domain Controller")
        
        if hasattr(node, 'is_kerberoastable') and node.is_kerberoastable:
            lines.append("🎯 Kerberoastable")
        
        if hasattr(node, 'is_high_value') and node.is_high_value:
            lines.append("⭐ High Value Target")
        
        return "<br>".join(lines)
    
    def _enhance_html(self, output_path: Path, path: AttackPath) -> None:
        """Add custom styling and info to generated HTML.
        
        Args:
            output_path: Path to the HTML file
            path: AttackPath being visualized
        """
        try:
            with open(output_path, 'r', encoding='utf-8') as f:
                html = f.read()
            
            # Add title bar at top (not overlapping) and legend at bottom-right
            info_panel = f"""
            <div style="background: #2d3748; padding: 10px 20px; color: #e2e8f0; font-family: Arial, sans-serif;
                        display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap;">
                <div>
                    <span style="color: #ecc94b; font-weight: bold; font-size: 18px;">Attack Path</span>
                    <span style="color: #a0aec0; margin-left: 10px;">{path.privilege_gain}</span>
                </div>
                <div style="display: flex; gap: 20px; align-items: center;">
                    <span style="color: {RISK_COLORS.get(path.risk_level, '#e2e8f0')}; font-weight: bold;">
                        {path.risk_level.value} Risk
                    </span>
                    <span style="color: #a0aec0;">{path.estimated_steps} steps</span>
                    <span style="font-size: 12px;">🎯 Start → 🏁 Target</span>
                </div>
            </div>
            """
            
            # Insert after body tag
            html = html.replace('<body>', f'<body style="margin:0; padding:0;">\n{info_panel}')
            
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write(html)
                
        except Exception as e:
            pass  # Silently fail - visualization still works
    
    def create_full_graph_visualization(
        self,
        filename: str = "full_graph.html",
        max_nodes: int = 500
    ) -> str:
        """Create visualization of the entire graph.
        
        Args:
            filename: Output filename
            max_nodes: Maximum nodes to include (for performance)
            
        Returns:
            Path to generated HTML file
        """
        output_path = self.output_dir / filename
        
        try:
            from pyvis.network import Network
            
            net = Network(
                height="800px",
                width="100%",
                bgcolor="#1a202c",
                font_color="#e2e8f0",
                directed=True
            )
            
            # Configure for large graphs
            net.set_options("""
            {
                "physics": {
                    "enabled": true,
                    "solver": "forceAtlas2Based",
                    "stabilization": {"iterations": 50}
                },
                "interaction": {
                    "hideEdgesOnDrag": true,
                    "hideNodesOnDrag": true
                }
            }
            """)
            
            # Add nodes (limited)
            node_count = 0
            for node_id in self.graph.nx_graph.nodes():
                if node_count >= max_nodes:
                    break
                
                node = self.graph.get_node(node_id)
                if node:
                    color = NODE_COLORS.get(node.node_type, "#a0aec0")
                    label = node.display_name[:30]
                else:
                    color = "#a0aec0"
                    label = str(node_id)[:30]
                
                net.add_node(node_id, label=label, color=color, size=15)
                node_count += 1
            
            # Add edges between included nodes
            added_nodes = set(list(self.graph.nx_graph.nodes())[:max_nodes])
            for source, target in self.graph.nx_graph.edges():
                if source in added_nodes and target in added_nodes:
                    edge = self.graph.get_edge(source, target)
                    if edge:
                        net.add_edge(source, target, title=edge.edge_type.value)
            
            net.save_graph(str(output_path))
            return str(output_path)
            
        except ImportError:
            # Fallback message
            with open(output_path, 'w') as f:
                f.write(f"""
                <html>
                <body style="background: #1a202c; color: white; font-family: Arial;">
                <h1>Graph Visualization Unavailable</h1>
                <p>Install pyvis for interactive visualizations: pip install pyvis</p>
                <p>Graph contains {self.graph.node_count} nodes and {self.graph.edge_count} edges.</p>
                </body>
                </html>
                """)
            return str(output_path)
    
    def create_path_image(
        self,
        path: AttackPath,
        filename: Optional[str] = None
    ) -> str:
        """Create a static image of an attack path.
        
        Args:
            path: AttackPath to visualize
            filename: Output filename
            
        Returns:
            Path to generated PNG file
        """
        filename = filename or f"path_{path.id}.png"
        output_path = self.output_dir / filename
        
        return self._create_matplotlib_visualization(path, output_path)
    
    def create_simple_path_html(
        self,
        path: AttackPath,
        filename: Optional[str] = None
    ) -> str:
        """Create a simple HTML visualization showing only the attack path.
        
        Args:
            path: AttackPath to visualize
            filename: Output filename
            
        Returns:
            Path to generated HTML file
        """
        filename = filename or f"path_{path.id}.html"
        output_path = self.output_dir / filename
        
        try:
            from pyvis.network import Network
            
            # Create a simple network with just the path nodes
            net = Network(
                height="500px",
                width="100%",
                bgcolor="#1a202c",
                font_color="#e2e8f0",
                directed=True,
                notebook=False
            )
            
            # Simple physics for linear layout
            net.set_options("""
            {
                "nodes": {
                    "font": {"size": 16, "face": "arial"},
                    "borderWidth": 3,
                    "shadow": true
                },
                "edges": {
                    "arrows": {"to": {"enabled": true, "scaleFactor": 1}},
                    "font": {"size": 14, "align": "middle", "color": "#e2e8f0"},
                    "color": {"color": "#f56565"},
                    "width": 3,
                    "smooth": {"type": "curvedCW", "roundness": 0.2}
                },
                "physics": {
                    "enabled": true,
                    "hierarchicalRepulsion": {"nodeDistance": 200}
                },
                "layout": {
                    "hierarchical": {
                        "enabled": true,
                        "direction": "LR",
                        "sortMethod": "directed",
                        "nodeSpacing": 200,
                        "levelSeparation": 250
                    }
                }
            }
            """)
            
            # Collect all nodes we need (from both path.nodes and edges)
            all_node_ids = set(path.nodes)
            for edge in path.edges:
                all_node_ids.add(edge.source_id)
                all_node_ids.add(edge.target_id)
            
            # Add all nodes
            path_nodes_set = set(path.nodes)
            for node_id in all_node_ids:
                node = self.graph.get_node(node_id)
                
                if node:
                    label = node.display_name
                    node_type = node.node_type
                else:
                    label = self.graph.get_node_name(node_id)
                    node_type = NodeType.UNKNOWN
                
                # Color based on role in path
                if node_id == path.nodes[0]:
                    color = "#48bb78"  # Green for start
                    label = f"🎯 {label}"
                    size = 40
                elif node_id == path.nodes[-1]:
                    color = "#e53e3e"  # Red for target
                    label = f"🏁 {label}"
                    size = 40
                elif node_id in path_nodes_set:
                    color = "#4299e1"  # Blue for intermediate
                    size = 35
                else:
                    # Intermediate node (like a group)
                    color = "#48bb78"  # Green for groups
                    size = 30
                
                net.add_node(
                    node_id,
                    label=label,
                    color={"background": color, "border": "#fff"},
                    size=size,
                    borderWidth=3,
                    shape="dot"
                )
            
            # Add edges - either from path.edges or generate from consecutive nodes
            if path.edges:
                for edge in path.edges:
                    edge_color = EDGE_COLORS.get(edge.edge_type, "#f56565")
                    net.add_edge(
                        edge.source_id,
                        edge.target_id,
                        label=edge.edge_type.value,
                        color={"color": edge_color},
                        width=4,
                        arrows="to"
                    )
            else:
                # Generate edges from consecutive nodes
                edge_type = path.properties.get('edge_type', 'GenericWrite')
                for i in range(len(path.nodes) - 1):
                    net.add_edge(
                        path.nodes[i],
                        path.nodes[i + 1],
                        label=edge_type,
                        color={"color": "#f56565"},
                        width=4,
                        arrows="to"
                    )
            
            # Save
            net.save_graph(str(output_path))
            
            # Enhance HTML
            self._enhance_html(output_path, path)
            
            return str(output_path)
            
        except ImportError:
            # Fallback to matplotlib PNG
            return self.create_path_image(path)
    
    def create_unified_chain_html(
        self,
        paths: list[AttackPath],
        filename: str = "attack_chain.html"
    ) -> str:
        """Create a unified visualization showing the complete attack chain.
        
        Combines multiple paths into one continuous chain, deduplicating
        shared nodes and showing the full pivot path.
        
        Args:
            paths: List of AttackPath objects (in order)
            filename: Output filename
            
        Returns:
            Path to generated HTML file
        """
        output_path = self.output_dir / filename
        
        if not paths:
            return str(output_path)
        
        try:
            from pyvis.network import Network
            
            # Create network
            net = Network(
                height="500px",
                width="100%",
                bgcolor="#1a202c",
                font_color="#e2e8f0",
                directed=True,
                notebook=False
            )
            
            # Use hierarchical left-to-right layout for chain visualization
            net.set_options("""
            {
                "nodes": {
                    "font": {"size": 18, "face": "arial", "color": "#ffffff"},
                    "borderWidth": 4,
                    "shadow": true
                },
                "edges": {
                    "arrows": {"to": {"enabled": true, "scaleFactor": 1.2}},
                    "font": {"size": 14, "align": "middle", "color": "#fbbf24", "background": "#1a202c"},
                    "width": 5,
                    "smooth": {"type": "curvedCW", "roundness": 0.1}
                },
                "physics": {
                    "enabled": false
                },
                "layout": {
                    "hierarchical": {
                        "enabled": true,
                        "direction": "LR",
                        "sortMethod": "directed",
                        "nodeSpacing": 200,
                        "levelSeparation": 300
                    }
                },
                "interaction": {
                    "navigationButtons": true,
                    "keyboard": true,
                    "zoomView": true,
                    "dragView": true
                }
            }
            """)
            
            # Build unified chain from path properties (source_name → target_name)
            # This preserves the actual attack flow order
            seen_nodes = set()
            ordered_nodes = []  # Will contain (node_id, display_name) or just display_name
            chain_edges = []  # List of (source, target, edge_type)
            
            for path in paths:
                source_name = path.properties.get('source_name', '')
                target_name = path.properties.get('target_name', '')
                edge_type = path.properties.get('edge_type', 'Unknown')
                intermediate_group = path.properties.get('intermediate_group', '')
                permission_type = path.properties.get('permission_type', '')
                
                # Add source node
                if source_name and source_name not in seen_nodes:
                    ordered_nodes.append(source_name)
                    seen_nodes.add(source_name)
                
                # If there's an intermediate group, add it and create two edges
                if intermediate_group:
                    if intermediate_group not in seen_nodes:
                        ordered_nodes.append(intermediate_group)
                        seen_nodes.add(intermediate_group)
                    
                    if target_name and target_name not in seen_nodes:
                        ordered_nodes.append(target_name)
                        seen_nodes.add(target_name)
                    
                    # Create edges: source → intermediate (MemberOf), intermediate → target (permission)
                    if source_name and intermediate_group:
                        chain_edges.append((source_name, intermediate_group, 'MemberOf'))
                    if intermediate_group and target_name:
                        chain_edges.append((intermediate_group, target_name, permission_type or edge_type))
                else:
                    # No intermediate - direct edge
                    if target_name and target_name not in seen_nodes:
                        ordered_nodes.append(target_name)
                        seen_nodes.add(target_name)
                    
                    if source_name and target_name:
                        chain_edges.append((source_name, target_name, edge_type))
            
            # Determine start and final nodes
            start_node = ordered_nodes[0] if ordered_nodes else None
            final_nodes = set()
            if ordered_nodes:
                final_nodes.add(ordered_nodes[-1])
            
            # Collect misconfigured groups (intermediate groups that enable escalation)
            misconfigured_groups = set()
            for path in paths:
                ig = path.properties.get('intermediate_group', '')
                if ig:
                    misconfigured_groups.add(ig)
            
            # Add nodes with position indicators (using display names)
            for i, node_name in enumerate(ordered_nodes):
                # Color based on position in chain
                if node_name == start_node:
                    color = "#48bb78"  # Green for start
                    title = "Starting Point (Owned)"
                elif node_name in final_nodes:
                    color = "#e53e3e"  # Red for final target
                    title = "Target (Goal)"
                elif node_name in misconfigured_groups:
                    color = "#9f7aea"  # Purple for misconfigured group
                    title = "Misconfigured Group (Fix This!)"
                else:
                    color = "#f6ad55"  # Orange for intermediate
                    title = f"Pivot {i}"
                
                # Clean the label (remove domain if present for cleaner display)
                label = node_name.split('@')[0] if '@' in node_name else node_name
                
                net.add_node(
                    node_name,  # Use name as ID
                    label=label,
                    title=f"{node_name}\n{title}",
                    color={"background": color, "border": "#fff"},
                    size=45,
                    borderWidth=4,
                    shape="dot"
                )
            
            # Add edges from chain_edges
            seen_edges = set()
            for source, target, edge_type in chain_edges:
                edge_key = (source, target)
                if edge_key not in seen_edges:
                    net.add_edge(
                        source,
                        target,
                        label=edge_type,
                        title=f"{edge_type}",
                        color={"color": "#f56565"},
                        width=5,
                        arrows="to"
                    )
                    seen_edges.add(edge_key)
            
            # Save
            net.save_graph(str(output_path))
            
            # Add custom header
            self._enhance_chain_html(output_path, paths, ordered_nodes)
            
            return str(output_path)
            
        except ImportError:
            return ""
    
    def _enhance_chain_html(self, output_path: Path, paths: list[AttackPath], nodes: list) -> None:
        """Add custom header to unified chain visualization."""
        try:
            with open(output_path, 'r', encoding='utf-8') as f:
                html = f.read()
            
            # Build chain summary (nodes are already display names now)
            clean_nodes = [n.split('@')[0] if '@' in str(n) else str(n) for n in nodes]
            chain_steps = " → ".join(clean_nodes)
            
            info_panel = f"""
            <div style="background: linear-gradient(90deg, #2d3748 0%, #1a202c 100%); 
                        padding: 15px 20px; color: #e2e8f0; font-family: Arial, sans-serif;">
                <div style="display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 10px;">
                    <div>
                        <span style="color: #fbbf24; font-weight: bold; font-size: 20px;">🔗 Complete Attack Chain</span>
                        <span style="color: #a0aec0; margin-left: 15px; font-size: 14px;">{len(nodes)} nodes, {len(paths)} pivots</span>
                    </div>
                    <div style="font-size: 12px; color: #a0aec0;">
                        🎯 Start → ➡️ Pivot → 🏁 Target
                    </div>
                </div>
                <div style="margin-top: 10px; padding: 10px; background: #1a202c; border-radius: 5px; 
                            font-family: monospace; font-size: 13px; overflow-x: auto; white-space: nowrap;">
                    {chain_steps}
                </div>
            </div>
            """
            
            html = html.replace('<body>', f'<body style="margin:0; padding:0;">\n{info_panel}')
            
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write(html)
                
        except Exception:
            pass

