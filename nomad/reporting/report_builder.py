"""
Report Builder Module
=====================

Builds structured report objects from analysis results.

The report contains:
- Environment statistics
- Attack paths with risk scores
- AI commentary (if available)
- Mitigation recommendations
- Visualization references

Design Decisions:
-----------------
1. Reports are structured data (JSON-serializable)
2. Can be rendered to multiple formats (JSON, HTML, PDF)
3. Includes all data needed for GUI display
4. Supports incremental updates
"""

import json
from datetime import datetime
from pathlib import Path
from typing import Optional

from ..model.schemas import AnalysisResult, AttackPath, EnvironmentStats, RiskLevel
from ..model.graph_builder import ADGraph
from .visualization import GraphVisualizer


class ReportBuilder:
    """Builds comprehensive reports from analysis results.
    
    Usage:
        builder = ReportBuilder(graph, output_dir="output")
        
        # Build report
        result = builder.build_report(
            attack_paths=paths,
            ai_result=ai_result
        )
        
        # The result contains all data for GUI display
        print(result.total_paths)
        print(result.attack_paths[0].risk_score)
    """
    
    def __init__(
        self,
        graph: ADGraph,
        output_dir: str = "output"
    ):
        """Initialize the report builder.
        
        Args:
            graph: ADGraph with environment data
            output_dir: Directory for output files
        """
        self.graph = graph
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
        self.visualizer = GraphVisualizer(graph, output_dir)
    
    def build_report(
        self,
        attack_paths: list[AttackPath],
        environment_stats: Optional[EnvironmentStats] = None,
        ai_overall_findings: Optional[str] = None,
        ai_mitigations: Optional[list] = None,
        generate_visualizations: bool = True,
        input_files: Optional[list[str]] = None
    ) -> AnalysisResult:
        """Build a complete analysis report.
        
        Args:
            attack_paths: List of discovered attack paths
            environment_stats: Pre-computed environment statistics
            ai_overall_findings: AI-generated overall findings
            ai_mitigations: AI-generated mitigation summary
            generate_visualizations: Whether to generate visualization files
            input_files: List of input file names for metadata
            
        Returns:
            AnalysisResult object with all report data
        """
        # Get environment stats if not provided
        if environment_stats is None:
            environment_stats = self.graph.get_environment_stats()
        
        # Generate visualizations
        visualization_paths = {}
        if generate_visualizations:
            visualization_paths = self._generate_visualizations(attack_paths)
        
        # Build result object
        result = AnalysisResult(
            attack_paths=attack_paths,
            environment_stats=environment_stats,
            visualization_paths=visualization_paths,
            ai_overall_findings=ai_overall_findings,
            ai_mitigations_summary=ai_mitigations or [],
            metadata={
                'timestamp': datetime.now().isoformat(),
                'input_files': input_files or [],
                'graph_nodes': self.graph.node_count,
                'graph_edges': self.graph.edge_count,
            }
        )
        
        # Calculate path counts (handled in __post_init__ but recalculate to be safe)
        result.total_paths = len(attack_paths)
        result.critical_paths = sum(1 for p in attack_paths if p.risk_level == RiskLevel.CRITICAL)
        result.high_paths = sum(1 for p in attack_paths if p.risk_level == RiskLevel.HIGH)
        result.medium_paths = sum(1 for p in attack_paths if p.risk_level == RiskLevel.MEDIUM)
        result.low_paths = sum(1 for p in attack_paths if p.risk_level == RiskLevel.LOW)
        
        # Save JSON report
        json_path = self._save_json_report(result)
        result.report_path = json_path
        
        return result
    
    def _generate_visualizations(
        self,
        attack_paths: list[AttackPath]
    ) -> dict[str, str]:
        """Generate visualizations for all attack paths.
        
        Args:
            attack_paths: List of attack paths
            
        Returns:
            Dictionary mapping path IDs to visualization file paths
        """
        paths = {}
        
        # First, generate unified chain visualization if we have multiple paths
        if len(attack_paths) > 0:
            try:
                chain_path = self.visualizer.create_unified_chain_html(
                    attack_paths,
                    filename="attack_chain.html"
                )
                if chain_path:
                    paths["unified_chain"] = chain_path
            except Exception as e:
                pass  # Continue with individual paths
        
        # Generate individual path visualizations
        for i, path in enumerate(attack_paths):
            try:
                # Generate simple HTML visualization (only shows path nodes)
                vis_path = self.visualizer.create_simple_path_html(
                    path,
                    filename=f"path_{path.id}.html"
                )
                paths[path.id] = vis_path
            except Exception as e:
                # Try PNG fallback
                try:
                    vis_path = self.visualizer.create_path_image(
                        path,
                        filename=f"path_{path.id}.png"
                    )
                    paths[path.id] = vis_path
                except Exception as e2:
                    pass  # Skip visualization for this path
        
        return paths
    
    def _save_json_report(self, result: AnalysisResult) -> str:
        """Save the report as JSON.
        
        Args:
            result: AnalysisResult to save
            
        Returns:
            Path to saved JSON file
        """
        json_path = self.output_dir / "nomad_results.json"
        
        # Convert to dict
        report_dict = result.to_dict()
        
        # Pretty print JSON
        with open(json_path, 'w', encoding='utf-8') as f:
            json.dump(report_dict, f, indent=2, default=str)
        
        return str(json_path)
    
    def add_path_to_report(
        self,
        result: AnalysisResult,
        path: AttackPath,
        generate_visualization: bool = True
    ) -> AnalysisResult:
        """Add a new path to an existing report.
        
        Args:
            result: Existing AnalysisResult
            path: New AttackPath to add
            generate_visualization: Whether to generate visualization
            
        Returns:
            Updated AnalysisResult
        """
        # Add path
        result.attack_paths.append(path)
        
        # Update counts
        result.total_paths += 1
        if path.risk_level == RiskLevel.CRITICAL:
            result.critical_paths += 1
        elif path.risk_level == RiskLevel.HIGH:
            result.high_paths += 1
        elif path.risk_level == RiskLevel.MEDIUM:
            result.medium_paths += 1
        elif path.risk_level == RiskLevel.LOW:
            result.low_paths += 1
        
        # Generate visualization
        if generate_visualization:
            try:
                vis_path = self.visualizer.create_path_visualization(path)
                result.visualization_paths[path.id] = vis_path
            except Exception:
                pass
        
        return result
    
    def get_summary_stats(self, result: AnalysisResult) -> dict:
        """Get summary statistics from a report.
        
        Args:
            result: AnalysisResult to summarize
            
        Returns:
            Dictionary with summary statistics
        """
        # Calculate average risk score
        if result.attack_paths:
            avg_risk = sum(p.risk_score for p in result.attack_paths) / len(result.attack_paths)
        else:
            avg_risk = 0.0
        
        # Find most common edge types
        edge_types = {}
        for path in result.attack_paths:
            for edge in path.edges:
                edge_type = edge.edge_type.value
                edge_types[edge_type] = edge_types.get(edge_type, 0) + 1
        
        top_edges = sorted(edge_types.items(), key=lambda x: x[1], reverse=True)[:5]
        
        # Most common targets
        targets = {}
        for path in result.attack_paths:
            targets[path.privilege_gain] = targets.get(path.privilege_gain, 0) + 1
        
        top_targets = sorted(targets.items(), key=lambda x: x[1], reverse=True)[:5]
        
        return {
            'total_paths': result.total_paths,
            'critical_paths': result.critical_paths,
            'high_paths': result.high_paths,
            'medium_paths': result.medium_paths,
            'low_paths': result.low_paths,
            'average_risk_score': round(avg_risk, 2),
            'most_common_edges': top_edges,
            'most_common_targets': top_targets,
            'environment_stats': result.environment_stats.to_dict() if result.environment_stats else None,
        }


def generate_text_report(result: AnalysisResult) -> str:
    """Generate a text-based report summary.
    
    Args:
        result: AnalysisResult to summarize
        
    Returns:
        Formatted text report
    """
    lines = [
        "=" * 60,
        "nomAD - Active Directory Attack Path Analysis Report",
        "=" * 60,
        "",
        f"Generated: {result.metadata.get('timestamp', 'Unknown')}",
        f"Graph: {result.metadata.get('graph_nodes', 0)} nodes, {result.metadata.get('graph_edges', 0)} edges",
        "",
        "SUMMARY",
        "-" * 40,
        f"Total Attack Paths: {result.total_paths}",
        f"  - Critical: {result.critical_paths}",
        f"  - High: {result.high_paths}",
        f"  - Medium: {result.medium_paths}",
        f"  - Low: {result.low_paths}",
        "",
    ]
    
    # Environment stats
    if result.environment_stats:
        stats = result.environment_stats
        lines.extend([
            "ENVIRONMENT",
            "-" * 40,
            f"Users: {stats.total_users} ({stats.enabled_users} enabled)",
            f"Groups: {stats.total_groups}",
            f"Computers: {stats.total_computers}",
            f"Domain Controllers: {stats.dc_count}",
            f"Domain Admins: {stats.domain_admin_count}",
            f"Kerberoastable Users: {stats.kerberoastable_users}",
            "",
        ])
    
    # Top paths
    lines.extend([
        "TOP ATTACK PATHS",
        "-" * 40,
    ])
    
    for i, path in enumerate(result.attack_paths[:10], 1):
        lines.extend([
            f"",
            f"#{i} [{path.risk_level.value}] Score: {path.risk_score:.1f}",
            f"   Target: {path.privilege_gain}",
            f"   Steps: {path.estimated_steps}",
            f"   Chain:",
        ])
        for line in path.raw_explanation.split('\n'):
            lines.append(f"      {line}")
        
        if path.ai_risk_commentary:
            lines.append(f"   AI Note: {path.ai_risk_commentary[:100]}...")
    
    # AI findings
    if result.ai_overall_findings:
        lines.extend([
            "",
            "AI OVERALL FINDINGS",
            "-" * 40,
            result.ai_overall_findings,
        ])
    
    # Mitigations
    if result.ai_mitigations_summary:
        lines.extend([
            "",
            "RECOMMENDED MITIGATIONS",
            "-" * 40,
        ])
        for mitigation in result.ai_mitigations_summary[:10]:
            lines.append(f"  • {mitigation}")
    
    lines.extend([
        "",
        "=" * 60,
        "End of Report",
        "=" * 60,
    ])
    
    return "\n".join(lines)

