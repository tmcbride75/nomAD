"""
HTML Export Module
==================

Exports analysis results as standalone HTML reports.

Features:
- Self-contained HTML with embedded styles
- Interactive path navigation
- Risk visualizations
- Suitable for sharing/archiving

Design Decisions:
-----------------
1. Single-file HTML for easy sharing
2. No external dependencies (CSS/JS inline)
3. Responsive design for various screens
4. Print-friendly styling
"""

from datetime import datetime
from pathlib import Path
from typing import Optional
import html

from ..model.schemas import AnalysisResult, AttackPath, RiskLevel


class HTMLExporter:
    """Exports analysis results to HTML format.
    
    Usage:
        exporter = HTMLExporter()
        
        html_path = exporter.export(result, "report.html")
    """
    
    # CSS styles for the report
    CSS = """
    :root {
        --bg-primary: #1a202c;
        --bg-secondary: #2d3748;
        --bg-tertiary: #4a5568;
        --text-primary: #e2e8f0;
        --text-secondary: #a0aec0;
        --accent: #ecc94b;
        --critical: #e53e3e;
        --high: #ed8936;
        --medium: #ecc94b;
        --low: #48bb78;
        --info: #4299e1;
    }
    
    * {
        box-sizing: border-box;
        margin: 0;
        padding: 0;
    }
    
    body {
        font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
        background-color: var(--bg-primary);
        color: var(--text-primary);
        line-height: 1.6;
        padding: 2rem;
    }
    
    .container {
        max-width: 1200px;
        margin: 0 auto;
    }
    
    h1, h2, h3 {
        margin-bottom: 1rem;
    }
    
    h1 {
        color: var(--accent);
        font-size: 2.5rem;
        border-bottom: 2px solid var(--accent);
        padding-bottom: 0.5rem;
    }
    
    h2 {
        color: var(--text-primary);
        font-size: 1.5rem;
        margin-top: 2rem;
    }
    
    .header {
        text-align: center;
        margin-bottom: 3rem;
    }
    
    .header .subtitle {
        color: var(--text-secondary);
        font-size: 1.1rem;
    }
    
    .summary-grid {
        display: grid;
        grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
        gap: 1rem;
        margin-bottom: 2rem;
    }
    
    .stat-card {
        background: var(--bg-secondary);
        padding: 1.5rem;
        border-radius: 8px;
        text-align: center;
    }
    
    .stat-card .number {
        font-size: 2.5rem;
        font-weight: bold;
        color: var(--accent);
    }
    
    .stat-card .label {
        color: var(--text-secondary);
        font-size: 0.9rem;
        text-transform: uppercase;
    }
    
    .stat-card.critical .number { color: var(--critical); }
    .stat-card.high .number { color: var(--high); }
    .stat-card.medium .number { color: var(--medium); }
    .stat-card.low .number { color: var(--low); }
    
    .path-card {
        background: var(--bg-secondary);
        border-radius: 8px;
        padding: 1.5rem;
        margin-bottom: 1rem;
        border-left: 4px solid var(--info);
    }
    
    .path-card.critical { border-left-color: var(--critical); }
    .path-card.high { border-left-color: var(--high); }
    .path-card.medium { border-left-color: var(--medium); }
    .path-card.low { border-left-color: var(--low); }
    
    .path-header {
        display: flex;
        justify-content: space-between;
        align-items: center;
        margin-bottom: 1rem;
    }
    
    .path-title {
        font-size: 1.2rem;
        font-weight: bold;
    }
    
    .risk-badge {
        padding: 0.25rem 0.75rem;
        border-radius: 4px;
        font-size: 0.85rem;
        font-weight: bold;
    }
    
    .risk-badge.critical { background: var(--critical); }
    .risk-badge.high { background: var(--high); color: #1a202c; }
    .risk-badge.medium { background: var(--medium); color: #1a202c; }
    .risk-badge.low { background: var(--low); color: #1a202c; }
    
    .path-chain {
        background: var(--bg-primary);
        padding: 1rem;
        border-radius: 4px;
        font-family: 'Consolas', 'Monaco', monospace;
        font-size: 0.9rem;
        white-space: pre-wrap;
        margin-top: 1rem;
    }
    
    .path-meta {
        display: flex;
        gap: 2rem;
        margin-top: 1rem;
        color: var(--text-secondary);
        font-size: 0.9rem;
    }
    
    .ai-commentary {
        background: var(--bg-tertiary);
        padding: 1rem;
        border-radius: 4px;
        margin-top: 1rem;
        font-style: italic;
    }
    
    .mitigations {
        margin-top: 1rem;
    }
    
    .mitigations h4 {
        color: var(--accent);
        margin-bottom: 0.5rem;
    }
    
    .mitigations ul {
        list-style-type: none;
        padding-left: 0;
    }
    
    .mitigations li {
        padding: 0.25rem 0;
        padding-left: 1.5rem;
        position: relative;
    }
    
    .mitigations li::before {
        content: "→";
        position: absolute;
        left: 0;
        color: var(--accent);
    }
    
    .environment-table {
        width: 100%;
        border-collapse: collapse;
        margin-top: 1rem;
    }
    
    .environment-table th,
    .environment-table td {
        padding: 0.75rem;
        text-align: left;
        border-bottom: 1px solid var(--bg-tertiary);
    }
    
    .environment-table th {
        color: var(--accent);
        font-weight: 600;
    }
    
    .footer {
        margin-top: 3rem;
        text-align: center;
        color: var(--text-secondary);
        font-size: 0.9rem;
        padding-top: 2rem;
        border-top: 1px solid var(--bg-tertiary);
    }
    
    @media print {
        body {
            background: white;
            color: black;
        }
        .path-card {
            page-break-inside: avoid;
        }
    }
    """
    
    def __init__(self, output_dir: str = "output"):
        """Initialize the HTML exporter.
        
        Args:
            output_dir: Directory for output files
        """
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
    
    def export(
        self,
        result: AnalysisResult,
        filename: str = "nomad_report.html"
    ) -> str:
        """Export analysis result to HTML.
        
        Args:
            result: AnalysisResult to export
            filename: Output filename
            
        Returns:
            Path to generated HTML file
        """
        output_path = self.output_dir / filename
        
        html_content = self._generate_html(result)
        
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        return str(output_path)
    
    def _generate_html(self, result: AnalysisResult) -> str:
        """Generate complete HTML document.
        
        Args:
            result: AnalysisResult to render
            
        Returns:
            HTML string
        """
        timestamp = result.metadata.get('timestamp', datetime.now().isoformat())
        
        sections = [
            self._generate_header(timestamp),
            self._generate_summary(result),
            self._generate_environment(result),
            self._generate_paths(result),
            self._generate_ai_findings(result),
            self._generate_footer(),
        ]
        
        body_content = "\n".join(sections)
        
        return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>nomAD Analysis Report</title>
    <style>
    {self.CSS}
    </style>
</head>
<body>
    <div class="container">
        {body_content}
    </div>
</body>
</html>"""
    
    def _generate_header(self, timestamp: str) -> str:
        """Generate report header."""
        return f"""
        <div class="header">
            <h1>nom<span style="color: #a16207;">AD</span></h1>
            <p class="subtitle">Active Directory Attack Path Analysis Report</p>
            <p class="subtitle">Generated: {html.escape(str(timestamp))}</p>
        </div>
        """
    
    def _generate_summary(self, result: AnalysisResult) -> str:
        """Generate summary statistics section."""
        return f"""
        <h2>📊 Summary</h2>
        <div class="summary-grid">
            <div class="stat-card">
                <div class="number">{result.total_paths}</div>
                <div class="label">Total Paths</div>
            </div>
            <div class="stat-card critical">
                <div class="number">{result.critical_paths}</div>
                <div class="label">Critical</div>
            </div>
            <div class="stat-card high">
                <div class="number">{result.high_paths}</div>
                <div class="label">High</div>
            </div>
            <div class="stat-card medium">
                <div class="number">{result.medium_paths}</div>
                <div class="label">Medium</div>
            </div>
            <div class="stat-card low">
                <div class="number">{result.low_paths}</div>
                <div class="label">Low</div>
            </div>
        </div>
        """
    
    def _generate_environment(self, result: AnalysisResult) -> str:
        """Generate environment statistics section."""
        if not result.environment_stats:
            return ""
        
        stats = result.environment_stats
        
        return f"""
        <h2>🏢 Environment Overview</h2>
        <table class="environment-table">
            <tr><th>Metric</th><th>Value</th></tr>
            <tr><td>Total Users</td><td>{stats.total_users}</td></tr>
            <tr><td>Enabled Users</td><td>{stats.enabled_users}</td></tr>
            <tr><td>Total Groups</td><td>{stats.total_groups}</td></tr>
            <tr><td>Total Computers</td><td>{stats.total_computers}</td></tr>
            <tr><td>Domain Controllers</td><td>{stats.dc_count}</td></tr>
            <tr><td>Domain Admin Accounts</td><td>{stats.domain_admin_count}</td></tr>
            <tr><td>Kerberoastable Users</td><td>{stats.kerberoastable_users}</td></tr>
            <tr><td>Unconstrained Delegation</td><td>{stats.unconstrained_delegation_count}</td></tr>
        </table>
        """
    
    def _generate_paths(self, result: AnalysisResult) -> str:
        """Generate attack paths section."""
        if not result.attack_paths:
            return "<h2>🎯 Attack Paths</h2><p>No attack paths discovered.</p>"
        
        paths_html = []
        for i, path in enumerate(result.attack_paths, 1):
            paths_html.append(self._generate_path_card(i, path))
        
        return f"""
        <h2>🎯 Attack Paths ({result.total_paths} found)</h2>
        {"".join(paths_html)}
        """
    
    def _generate_path_card(self, index: int, path: AttackPath) -> str:
        """Generate HTML for a single path card."""
        risk_class = path.risk_level.value.lower()
        
        # Escape explanation for HTML
        explanation = html.escape(path.raw_explanation)
        
        # AI commentary section
        ai_section = ""
        if path.ai_risk_commentary:
            ai_section = f"""
            <div class="ai-commentary">
                <strong>AI Analysis:</strong> {html.escape(path.ai_risk_commentary)}
            </div>
            """
        
        # Mitigations section
        mitigations_section = ""
        if path.ai_mitigations:
            mitigations_list = "".join(
                f"<li>{html.escape(m)}</li>" for m in path.ai_mitigations[:5]
            )
            mitigations_section = f"""
            <div class="mitigations">
                <h4>Recommended Mitigations</h4>
                <ul>{mitigations_list}</ul>
            </div>
            """
        
        # Check for special path types
        special_notes = []
        if path.properties.get('from_authenticated_user'):
            special_notes.append("🔑 From Authenticated User")
        if path.properties.get('kerberoastable_start'):
            special_notes.append("🎯 Kerberoastable Start")
        if path.properties.get('dcsync_path'):
            special_notes.append("⚠️ DCSync Path")
        
        notes_html = ""
        if special_notes:
            notes_html = f"<div style='margin-top: 0.5rem; color: var(--accent);'>{' | '.join(special_notes)}</div>"
        
        return f"""
        <div class="path-card {risk_class}">
            <div class="path-header">
                <span class="path-title">#{index}: {html.escape(path.privilege_gain)}</span>
                <span class="risk-badge {risk_class}">{path.risk_level.value} ({path.risk_score:.1f})</span>
            </div>
            <div class="path-meta">
                <span>Steps: {path.estimated_steps}</span>
                <span>ID: {path.id}</span>
            </div>
            {notes_html}
            <div class="path-chain">{explanation}</div>
            {ai_section}
            {mitigations_section}
        </div>
        """
    
    def _generate_ai_findings(self, result: AnalysisResult) -> str:
        """Generate AI findings section."""
        sections = []
        
        if result.ai_overall_findings:
            sections.append(f"""
            <h2>🤖 AI Analysis</h2>
            <div class="path-card">
                <p>{html.escape(result.ai_overall_findings)}</p>
            </div>
            """)
        
        if result.ai_mitigations_summary:
            mitigations_list = "".join(
                f"<li>{html.escape(m)}</li>" for m in result.ai_mitigations_summary
            )
            sections.append(f"""
            <h2>🛡️ Recommended Mitigations</h2>
            <div class="mitigations">
                <ul>{mitigations_list}</ul>
            </div>
            """)
        
        return "\n".join(sections)
    
    def _generate_footer(self) -> str:
        """Generate report footer."""
        return f"""
        <div class="footer">
            <p>Generated by nomAD - AI-Assisted Active Directory Attack Path Analysis</p>
            <p>This report is for authorized security assessment purposes only.</p>
        </div>
        """

