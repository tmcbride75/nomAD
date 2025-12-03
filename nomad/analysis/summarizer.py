"""
Analysis Summarizer
===================

Prepares compact data summaries for the AI reasoning layer.

The AI receives summarized, structured data rather than raw huge files.
This module creates:
- Environment overview summaries
- Attack path summaries
- Risk profile summaries

Design Decisions:
-----------------
1. Summaries are size-limited to fit within LLM context
2. Most important information is prioritized
3. Output format is designed for LLM comprehension
4. Includes specific prompts/questions for the AI
"""

from typing import Optional
from ..model.schemas import (
    AttackPath, EnvironmentStats, RiskLevel
)
from ..model.graph_builder import ADGraph


class AnalysisSummarizer:
    """Creates summaries for AI reasoning.
    
    Usage:
        summarizer = AnalysisSummarizer(graph, paths)
        summary = summarizer.create_full_summary()
        
        # Or get specific summaries
        env_summary = summarizer.get_environment_summary()
        path_summary = summarizer.get_paths_summary(top_n=10)
    """
    
    def __init__(
        self,
        graph: ADGraph,
        attack_paths: list[AttackPath],
        environment_stats: Optional[EnvironmentStats] = None
    ):
        """Initialize the summarizer.
        
        Args:
            graph: ADGraph with environment data
            attack_paths: List of discovered attack paths
            environment_stats: Pre-computed environment stats (optional)
        """
        self.graph = graph
        self.attack_paths = attack_paths
        self.stats = environment_stats or graph.get_environment_stats()
    
    def create_full_summary(self, max_paths: int = 15) -> str:
        """Create a complete summary for AI analysis.
        
        Args:
            max_paths: Maximum number of paths to include
            
        Returns:
            Formatted summary string
        """
        sections = [
            self._create_header(),
            self.get_environment_summary(),
            self.get_paths_summary(top_n=max_paths),
            self._create_questions_section(),
        ]
        
        return "\n\n".join(sections)
    
    def _create_header(self) -> str:
        """Create summary header."""
        return """# Active Directory Security Analysis Summary

This summary contains key findings from the AD environment analysis.
Please analyze the attack paths and provide:
1. Risk assessment and prioritization
2. Detailed explanations of why each path is dangerous
3. Specific mitigation recommendations
"""
    
    def get_environment_summary(self) -> str:
        """Create environment statistics summary.
        
        Returns:
            Formatted environment summary
        """
        lines = [
            "## Environment Overview",
            "",
            f"- Total Users: {self.stats.total_users}",
            f"  - Enabled: {self.stats.enabled_users}",
            f"  - Disabled: {self.stats.disabled_users}",
            f"  - Kerberoastable: {self.stats.kerberoastable_users}",
            f"- Total Groups: {self.stats.total_groups}",
            f"- Total Computers: {self.stats.total_computers}",
            f"- Domain Controllers: {self.stats.dc_count}",
            f"- Domain Admin Accounts/Groups: {self.stats.domain_admin_count}",
            f"- Enterprise Admin Accounts/Groups: {self.stats.enterprise_admin_count}",
            f"- Unconstrained Delegation Systems: {self.stats.unconstrained_delegation_count}",
        ]
        
        # Add risk indicators
        lines.extend([
            "",
            "### Risk Indicators:",
        ])
        
        if self.stats.kerberoastable_users > 0:
            ratio = (self.stats.kerberoastable_users / max(1, self.stats.enabled_users)) * 100
            lines.append(f"- ⚠️ {self.stats.kerberoastable_users} Kerberoastable users ({ratio:.1f}% of enabled users)")
        
        if self.stats.unconstrained_delegation_count > 0:
            lines.append(f"- ⚠️ {self.stats.unconstrained_delegation_count} systems with unconstrained delegation")
        
        if self.stats.domain_admin_count > 5:
            lines.append(f"- ⚠️ High number of Domain Admin accounts ({self.stats.domain_admin_count})")
        
        return "\n".join(lines)
    
    def get_paths_summary(self, top_n: int = 10) -> str:
        """Create attack paths summary.
        
        Args:
            top_n: Number of top paths to include
            
        Returns:
            Formatted paths summary
        """
        lines = [
            "## Discovered Attack Paths",
            "",
        ]
        
        # Count by risk level
        critical = sum(1 for p in self.attack_paths if p.risk_level == RiskLevel.CRITICAL)
        high = sum(1 for p in self.attack_paths if p.risk_level == RiskLevel.HIGH)
        medium = sum(1 for p in self.attack_paths if p.risk_level == RiskLevel.MEDIUM)
        low = sum(1 for p in self.attack_paths if p.risk_level == RiskLevel.LOW)
        
        lines.extend([
            f"**Total Paths Found:** {len(self.attack_paths)}",
            f"- Critical: {critical}",
            f"- High: {high}",
            f"- Medium: {medium}",
            f"- Low: {low}",
            "",
            f"### Top {min(top_n, len(self.attack_paths))} Attack Paths:",
            "",
        ])
        
        # Sort by risk score
        sorted_paths = sorted(self.attack_paths, key=lambda p: p.risk_score, reverse=True)
        
        for i, path in enumerate(sorted_paths[:top_n], 1):
            lines.extend(self._format_path_summary(i, path))
            lines.append("")
        
        return "\n".join(lines)
    
    def _format_path_summary(self, index: int, path: AttackPath) -> list[str]:
        """Format a single path for the summary.
        
        Args:
            index: Path number
            path: AttackPath to format
            
        Returns:
            List of formatted lines
        """
        lines = [
            f"#### Path #{index} - {path.risk_level.value} Risk (Score: {path.risk_score:.1f})",
            f"**Target:** {path.privilege_gain}",
            f"**Steps:** {path.estimated_steps}",
            "",
            "**Attack Chain:**",
        ]
        
        # Add step-by-step breakdown
        lines.append("```")
        lines.append(path.raw_explanation)
        lines.append("```")
        
        # Add special notes
        notes = []
        if path.properties.get('from_authenticated_user'):
            notes.append("🔑 Starts from authenticated user")
        if path.properties.get('kerberoastable_start'):
            notes.append("🎯 Starts from Kerberoastable account")
        if path.properties.get('dcsync_path'):
            notes.append("⚠️ DCSync attack path")
        
        if notes:
            lines.append("")
            lines.append("**Notes:** " + " | ".join(notes))
        
        return lines
    
    def _create_questions_section(self) -> str:
        """Create questions for the AI to answer."""
        return """## Analysis Questions

Please provide analysis on:

1. **Risk Ranking**: Confirm or adjust the risk rankings of the attack paths. Which paths should be prioritized for remediation?

2. **Path Analysis**: For each critical/high-risk path:
   - Why is this path particularly dangerous?
   - What misconfigurations enable this attack chain?
   - What would an attacker need to exploit this path?

3. **Mitigation Recommendations**: For the top 5 paths, provide specific, actionable mitigations:
   - Which permissions should be removed?
   - What group memberships should be changed?
   - What security configurations should be applied?

4. **Overall Assessment**: Provide a high-level assessment of the AD security posture and top 3 immediate actions.

Please structure your response as JSON with the following format:
```json
{
  "overall_risk_assessment": "summary string",
  "top_immediate_actions": ["action1", "action2", "action3"],
  "path_analyses": [
    {
      "path_id": "path_id",
      "confirmed_risk_level": "Critical|High|Medium|Low",
      "risk_commentary": "why this path is dangerous",
      "exploitation_requirements": "what attacker needs",
      "mitigations": ["specific mitigation 1", "mitigation 2"]
    }
  ],
  "general_recommendations": ["recommendation1", "recommendation2"]
}
```
"""
    
    def get_path_detail_summary(self, path: AttackPath) -> str:
        """Create a detailed summary for a single path.
        
        Useful for getting AI analysis of a specific path.
        
        Args:
            path: AttackPath to summarize
            
        Returns:
            Detailed path summary
        """
        lines = [
            "# Attack Path Analysis Request",
            "",
            f"## Path Overview",
            f"- **ID:** {path.id}",
            f"- **Risk Score:** {path.risk_score:.1f}",
            f"- **Risk Level:** {path.risk_level.value}",
            f"- **Privilege Gained:** {path.privilege_gain}",
            f"- **Steps Required:** {path.estimated_steps}",
            "",
            "## Attack Chain",
            "",
            "```",
            path.raw_explanation,
            "```",
            "",
            "## Node Details",
        ]
        
        # Add details for each node in the path
        for i, node_id in enumerate(path.nodes):
            node = self.graph.get_node(node_id)
            if node:
                role = "START" if i == 0 else ("TARGET" if i == len(path.nodes) - 1 else "INTERMEDIATE")
                lines.extend([
                    f"",
                    f"### {i + 1}. {node.display_name} [{role}]",
                    f"- Type: {node.node_type.value}",
                ])
                
                # Add type-specific details
                if hasattr(node, 'enabled'):
                    lines.append(f"- Enabled: {node.enabled}")
                if hasattr(node, 'admin_count') and node.admin_count:
                    lines.append(f"- Admin Count: Protected")
                if hasattr(node, 'is_high_value') and node.is_high_value:
                    lines.append(f"- High Value Target: Yes")
                if hasattr(node, 'is_dc') and node.is_dc:
                    lines.append(f"- Domain Controller: Yes")
        
        lines.extend([
            "",
            "## Edge Details",
        ])
        
        # Add edge details
        for i, edge in enumerate(path.edges):
            source_name = self.graph.get_node_name(edge.source_id)
            target_name = self.graph.get_node_name(edge.target_id)
            lines.extend([
                f"",
                f"### Step {i + 1}: {edge.edge_type.value}",
                f"- From: {source_name}",
                f"- To: {target_name}",
            ])
            
            # Add edge property details if available
            if edge.properties:
                if edge.properties.get('inherited'):
                    lines.append(f"- Inherited: Yes")
        
        lines.extend([
            "",
            "## Questions",
            "",
            "1. What makes this attack path exploitable?",
            "2. What specific steps would an attacker take?",
            "3. What are the most effective mitigations?",
            "4. Are there any detection opportunities?",
        ])
        
        return "\n".join(lines)
    
    def create_mitigation_summary(self) -> str:
        """Create a summary focused on mitigations.
        
        Returns:
            Mitigation-focused summary
        """
        # Group paths by the edges they contain
        edge_type_counts = {}
        for path in self.attack_paths:
            for edge in path.edges:
                edge_type = edge.edge_type.value
                if edge_type not in edge_type_counts:
                    edge_type_counts[edge_type] = 0
                edge_type_counts[edge_type] += 1
        
        # Sort by frequency
        sorted_edges = sorted(edge_type_counts.items(), key=lambda x: x[1], reverse=True)
        
        lines = [
            "# Mitigation Priority Analysis",
            "",
            "## Most Common Attack Vectors",
            "",
            "The following relationship types appear most frequently in attack paths:",
            "",
        ]
        
        for edge_type, count in sorted_edges[:10]:
            lines.append(f"- **{edge_type}**: {count} occurrences")
        
        lines.extend([
            "",
            "## Recommended Mitigation Focus",
            "",
            "Based on the analysis, prioritize mitigations for:",
            "",
        ])
        
        # Add specific recommendations based on top edge types
        for edge_type, count in sorted_edges[:5]:
            recommendation = self._get_edge_mitigation(edge_type)
            if recommendation:
                lines.append(f"### {edge_type}")
                lines.append(f"- Occurrences: {count}")
                lines.append(f"- Recommendation: {recommendation}")
                lines.append("")
        
        return "\n".join(lines)
    
    def _get_edge_mitigation(self, edge_type: str) -> str:
        """Get mitigation recommendation for an edge type.
        
        Args:
            edge_type: Edge type string
            
        Returns:
            Mitigation recommendation
        """
        mitigations = {
            "MemberOf": "Review group memberships and apply least-privilege principles",
            "GenericAll": "Remove unnecessary full-control permissions",
            "GenericWrite": "Remove unnecessary write permissions, use delegated admin",
            "WriteDacl": "Remove ACL modification rights from non-admins",
            "WriteOwner": "Remove ownership modification rights",
            "ForceChangePassword": "Restrict password reset capabilities to help desk only",
            "AddMember": "Remove group modification rights, use PAM/PIM",
            "AdminTo": "Review local admin memberships, implement LAPS",
            "CanRDP": "Restrict RDP access, implement jump servers",
            "CanPSRemote": "Restrict PSRemoting, use JEA endpoints",
            "HasSession": "Implement credential hygiene, avoid admin logons to workstations",
            "GetChangesAll": "Remove DCSync rights from non-DCs",
            "ReadLAPSPassword": "Restrict LAPS read access",
            "AllowedToDelegate": "Review delegation settings, prefer constrained delegation",
            "AllowedToAct": "Review RBCD settings",
            "AddKeyCredentialLink": "Restrict msDS-KeyCredentialLink write access",
        }
        
        return mitigations.get(edge_type, "Review and apply least-privilege")

