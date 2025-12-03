"""
GUI Bridge Module
=================

High-level interface for GUI integration.

This module provides the main entry points that the Streamlit GUI calls.
It orchestrates the entire analysis pipeline:
1. LDAP collection (if credentials provided)
2. BloodHound data loading (if files provided)
3. Graph building
4. Path discovery
5. Risk scoring
6. AI analysis (if enabled)
7. Report generation
8. Visualization creation

Design Decisions:
-----------------
1. Single entry point (run_analysis) for simplicity
2. Returns AnalysisResult which contains all data the GUI needs
3. Supports both LDAP collection and BloodHound file input
4. Progress updates via callback for real-time GUI updates
"""

import os
import json
import shutil
import subprocess
from pathlib import Path
from typing import Optional, Callable

from ..config import NomadConfig, LLMConfig, LDAPConfig, AnalysisConfig, OutputConfig
from ..ingestion.bloodhound_loader import BloodHoundLoader
from ..ingestion.ldap_loader import LDAPCollector, LDAP3_AVAILABLE
from ..model.graph_builder import ADGraph
from ..model.schemas import AnalysisResult, RiskLevel
from ..analysis.path_finder import AttackPathFinder
from ..analysis.risk_scoring import RiskScorer
from ..ai_engine.reasoner import AIReasoner
from ..reporting.report_builder import ReportBuilder
from ..reporting.export_html import HTMLExporter
from ..exploitation.executor import AttackExecutor


def sync_clock_with_dc(server_ip: str, log_func=print) -> bool:
    """Check clock sync status and remind user to sync if needed.
    
    NOTE: User should run these commands BEFORE starting nomAD:
        sudo timedatectl set-ntp false
        sudo ntpdate <DC_IP>
    
    Args:
        server_ip: IP of the Domain Controller
        log_func: Logging function
        
    Returns:
        True (always - just a reminder)
    """
    log_func("[*] Clock sync reminder for Kerberos operations:")
    log_func(f"    Run before starting: sudo timedatectl set-ntp false && sudo ntpdate {server_ip}")
    return True


def _sort_paths_by_dependency(paths: list, initial_user: str, log_func=None) -> list:
    """Sort attack paths by dependency order.
    
    Ensures paths are ordered so that:
    1. Paths from initial_user come first
    2. Subsequent paths start from targets we've already compromised
    
    Args:
        paths: List of AttackPath objects
        initial_user: The starting username (already owned)
        log_func: Optional logging function (unused, kept for compatibility)
        
    Returns:
        Sorted list of AttackPath objects
    """
    if not paths:
        return paths
    
    sorted_paths = []
    # Normalize initial user - handle various formats
    initial_lower = initial_user.lower().split('@')[0]  # Remove domain part
    owned_users = {initial_lower}
    
    remaining = list(paths)
    
    # Keep iterating until we've placed all paths or can't progress
    max_iterations = len(paths) * 3
    iterations = 0
    
    while remaining and iterations < max_iterations:
        iterations += 1
        added_this_round = False
        
        for path in remaining[:]:
            # Get source name and normalize it
            source_name = path.properties.get('source_name', '')
            source_lower = source_name.lower().split('@')[0] if source_name else ''
            
            target_name = path.properties.get('target_name', '')
            target_lower = target_name.lower().split('@')[0] if target_name else ''
            
            # Check if we can execute this path (source is owned)
            if source_lower in owned_users:
                sorted_paths.append(path)
                remaining.remove(path)
                
                # Add target to owned users
                if target_lower:
                    owned_users.add(target_lower)
                
                added_this_round = True
        
        if not added_this_round:
            break
    
    # Remaining paths require users we don't directly own yet
    sorted_paths.extend(remaining)
    
    return sorted_paths


def run_analysis(
    username: Optional[str] = None,
    password: Optional[str] = None,
    ntlm_hash: Optional[str] = None,
    domain: Optional[str] = None,
    server_ip: Optional[str] = None,
    input_files: Optional[list[str]] = None,
    output_dir: str = "output",
    config: Optional[dict] = None,
    progress_callback: Optional[Callable[[str], None]] = None,
    execute_attacks: bool = True,
    clean_output: bool = True
) -> AnalysisResult:
    """Main entry point for running AD analysis.
    
    This function orchestrates the entire analysis pipeline. It can work with:
    1. LDAP credentials to collect data live from a domain controller
    2. BloodHound/SharpHound JSON files
    3. Both (files are merged with LDAP data)
    
    Args:
        username: Domain username for LDAP collection
        password: Domain password for LDAP collection
        domain: Domain name (e.g., "corp.local")
        server_ip: Domain controller IP address
        input_files: List of BloodHound JSON file paths
        output_dir: Directory for output files
        config: Optional configuration dictionary
        progress_callback: Optional callback for progress updates
        
    Returns:
        AnalysisResult containing all findings, paths, and visualizations
        
    Example:
        # LDAP collection
        result = run_analysis(
            username="admin",
            password="Password123",
            domain="corp.local",
            server_ip="192.168.1.100"
        )
        
        # BloodHound files
        result = run_analysis(
            input_files=["users.json", "groups.json", "computers.json"]
        )
        
        # Both
        result = run_analysis(
            username="admin",
            password="Password123",
            domain="corp.local",
            server_ip="192.168.1.100",
            input_files=["additional_data.json"]
        )
    """
    
    def log(message: str):
        """Log message to callback if provided."""
        if progress_callback:
            progress_callback(message)
        print(message)
    
    # Build configuration
    nomad_config = _build_config(config, output_dir)
    
    # Clean output directory if requested (removes old results)
    output_path = Path(output_dir)
    if clean_output and output_path.exists():
        log("[*] Cleaning previous output...")
        for item in output_path.iterdir():
            if item.is_file():
                item.unlink()
            elif item.is_dir():
                shutil.rmtree(item)
    
    # Ensure output directory exists
    output_path.mkdir(parents=True, exist_ok=True)
    
    # Initialize graph
    graph = ADGraph()
    input_file_names = []
    
    # Check if we have something to work with
    has_ldap = username and (password or ntlm_hash) and domain and server_ip
    has_files = input_files and len(input_files) > 0
    
    if not has_ldap and not has_files:
        raise ValueError("Must provide either LDAP credentials (password or hash) or BloodHound files")
    
    # Step 0: Sync clock with DC (prevents Kerberos clock skew errors)
    if has_ldap and server_ip:
        sync_clock_with_dc(server_ip, log)
    
    # Step 1: LDAP Collection
    if has_ldap:
        log("[*] Starting LDAP data collection...")
        log(f"[*] Target: {server_ip}")
        log(f"[*] Domain: {domain}")
        log(f"[*] Authenticating as: {username}")
        
        if not LDAP3_AVAILABLE:
            log("[!] ldap3 library not available. Install with: pip install ldap3")
            log("[*] Falling back to BloodHound files only...")
        else:
            try:
                log(f"[*] Connecting to LDAP server {server_ip}:389...")
                collector = LDAPCollector(
                    server_ip=server_ip,
                    domain=domain,
                    username=username,
                    password=password,
                    ntlm_hash=ntlm_hash,
                    config=nomad_config.ldap,
                    verbose=True,
                    progress_callback=log  # Pass log function directly
                )
                
                log("[*] Starting AD enumeration...")
                ldap_graph = collector.collect()
                graph.merge(ldap_graph)
                
                log(f"[+] LDAP collection complete: {ldap_graph.node_count} nodes, {ldap_graph.edge_count} edges")
                
                # Export BloodHound-compatible JSON for future use
                bh_dir = Path(output_dir) / "bloodhound_export"
                exported_files = collector.export_bloodhound_json(str(bh_dir))
                log(f"[+] Exported BloodHound JSON to {bh_dir}")
                
                collector.disconnect()
                
            except Exception as e:
                log(f"[!] LDAP collection error: {e}")
                if not has_files:
                    raise
                log("[*] Continuing with BloodHound files...")
    
    # Step 2: Load BloodHound files
    if has_files:
        log(f"[*] Loading BloodHound data from {len(input_files)} file(s)...")
        
        loader = BloodHoundLoader(verbose=True)
        bh_graph = loader.load_files(input_files)
        graph.merge(bh_graph)
        
        input_file_names = [Path(f).name for f in input_files]
        log(f"[+] BloodHound data loaded: {bh_graph.node_count} nodes, {bh_graph.edge_count} edges")
    
    # Check if we have data
    if graph.node_count == 0:
        log("[!] No data loaded - graph is empty")
        return AnalysisResult(
            attack_paths=[],
            metadata={'error': 'No data loaded'}
        )
    
    log(f"[+] Total graph: {graph.node_count} nodes, {graph.edge_count} edges")
    
    # Step 3: Find attack paths
    log("[*] Discovering attack paths...")
    
    path_finder = AttackPathFinder(graph, nomad_config.analysis)
    
    # Determine starting points
    starting_user_id = None
    if has_ldap and username:
        # Try to find the authenticated user in the graph
        starting_user_id = graph.get_node_id_by_name(username)
        if starting_user_id:
            log(f"[+] Found authenticated user: {username}")
    
    # Find pivot chain from authenticated user only
    if starting_user_id:
        log(f"[*] Finding pivot chain from {username}...")
        attack_paths = path_finder.find_pivot_chain(starting_user_id)
        
        # Mark paths as from authenticated user
        for path in attack_paths:
            path.properties['from_authenticated_user'] = True
        
        # Sort paths by dependency order - ensure we can execute them in sequence
        attack_paths = _sort_paths_by_dependency(attack_paths, username, log)
    else:
        # No authenticated user - find from all enabled users
        attack_paths = path_finder.find_all_paths_to_high_value()
    
    log(f"[+] Found {len(attack_paths)} attack paths")
    
    # Show discovered paths
    if attack_paths:
        log("[*] Attack chain discovered:")
        for i, path in enumerate(attack_paths, 1):
            source = path.properties.get('source_name', '?')
            target = path.properties.get('target_name', '?')
            edge = path.properties.get('edge_type', '?')
            via = path.properties.get('intermediate_group', '') or path.properties.get('via_group', '')
            if via:
                log(f"    Step {i}: {source} → {target} [{edge}] (via {via})")
            else:
                log(f"    Step {i}: {source} → {target} [{edge}]")
    
    # Step 4: Score paths (but don't re-rank - keep dependency order)
    log("[*] Calculating risk scores...")
    
    scorer = RiskScorer(graph, nomad_config.analysis)
    attack_paths = scorer.score_paths(attack_paths)
    # NOTE: Don't call rank_paths() - it would destroy dependency order
    # attack_paths = scorer.rank_paths(attack_paths)
    
    # Count by risk level
    critical = sum(1 for p in attack_paths if p.risk_level == RiskLevel.CRITICAL)
    high = sum(1 for p in attack_paths if p.risk_level == RiskLevel.HIGH)
    medium = sum(1 for p in attack_paths if p.risk_level == RiskLevel.MEDIUM)
    low = sum(1 for p in attack_paths if p.risk_level == RiskLevel.LOW)
    
    log(f"[+] Risk distribution: Critical={critical}, High={high}, Medium={medium}, Low={low}")
    
    # Step 5: AI Analysis (if enabled)
    ai_findings = None
    ai_mitigations = []
    
    if nomad_config.llm.enabled and nomad_config.llm.api_key:
        log("[*] Running AI analysis...")
        
        try:
            reasoner = AIReasoner(nomad_config.llm)
            
            if reasoner.is_available:
                ai_result = reasoner.analyze_paths(
                    graph,
                    attack_paths,
                    graph.get_environment_stats()
                )
                
                # Enhance paths with AI commentary
                attack_paths = reasoner.enhance_paths(attack_paths, ai_result)
                
                ai_findings = ai_result.overall_assessment
                ai_mitigations = ai_result.general_recommendations
                
                log("[+] AI analysis complete")
            else:
                log("[*] AI not available - using rule-based analysis")
                
        except Exception as e:
            log(f"[!] AI analysis error: {e}")
            log("[*] Continuing with rule-based analysis...")
    else:
        log("[*] AI analysis disabled - using rule-based analysis only")
    
    # Step 6: Build report
    log("[*] Generating report and visualizations...")
    
    report_builder = ReportBuilder(graph, output_dir)
    
    result = report_builder.build_report(
        attack_paths=attack_paths,
        environment_stats=graph.get_environment_stats(),
        ai_overall_findings=ai_findings,
        ai_mitigations=ai_mitigations,
        generate_visualizations=True,
        input_files=input_file_names
    )
    
    # Step 7: Export HTML report
    html_exporter = HTMLExporter(output_dir)
    html_path = html_exporter.export(result)
    result.html_report_path = html_path
    
    log(f"[+] Report saved to {result.report_path}")
    log(f"[+] HTML report saved to {html_path}")
    log(f"[+] Analysis complete!")
    
    # Step 8: Execute attack chain if requested
    if execute_attacks and attack_paths and has_ldap:
        log("")
        log("[*] ============================================")
        log("[*] EXECUTING ATTACK CHAIN")
        log("[*] ============================================")
        log(f"[*] Target: {server_ip}")
        log(f"[*] Domain: {domain}")
        log(f"[*] Initial User: {username}")
        log(f"[*] Steps to execute: {len(attack_paths)}")
        log("")
        
        try:
            log("[*] Initializing attack executor...")
            executor = AttackExecutor(
                server_ip=server_ip,
                domain=domain,
                username=username,
                password=password,
                ntlm_hash=ntlm_hash,
                verbose=True,
                log_callback=log  # Pass log function for detailed output
            )
            
            log("[*] Starting attack chain execution...")
            exec_report = executor.execute_chain(attack_paths)
            
            # Log results
            log(f"[+] Execution complete!")
            log(f"[+] Users owned: {len(exec_report.owned_users)}")
            
            # Save credentials to file
            creds_file = Path(output_dir) / "compromised.txt"
            with open(creds_file, 'w') as f:
                f.write("# Compromised Credentials\n")
                f.write(f"# Domain: {domain}\n")
                f.write(f"# Generated by nomAD\n\n")
                for user in exec_report.owned_users:
                    pwd = executor.credentials.get(user.lower(), "N/A")
                    f.write(f"{user}:{pwd}\n")
                    log(f"    - {user}:{pwd}")
            
            log(f"[+] Credentials saved to: {creds_file}")
            
            # Save attack report JSON
            report_path = Path(output_dir) / "attack_report.json"
            with open(report_path, 'w') as f:
                import json
                json.dump(exec_report.to_dict(), f, indent=2)
            
            # Save markdown report
            md_path = Path(output_dir) / "attack_report.md"
            with open(md_path, 'w') as f:
                f.write(exec_report.to_markdown())
            
            # Log compromised accounts with NT hashes
            for user, cred in executor.credentials.items():
                if cred.startswith("[NT_HASH]"):
                    log(f"[+] Shadow Credentials: {user} compromised (NT hash obtained)")
            
            # Generate AI remediation advice
            if exec_report.owned_users and len(exec_report.owned_users) > 1:
                log("[*] Generating AI remediation advice...")
                
                # Build attack chain data for AI - use original paths for accurate description
                attack_chain_data = []
                for path in attack_paths:
                    source_name = path.properties.get('source_name', 'unknown')
                    target_name = path.properties.get('target_name', 'unknown')
                    edge_type = path.properties.get('edge_type', 'unknown')
                    intermediate_group = path.properties.get('intermediate_group', '')
                    via_group = path.properties.get('via_group', '')
                    permission_type = path.properties.get('permission_type', '')
                    
                    # Build clear description of what happened
                    if intermediate_group:
                        # Group escalation path
                        attack_chain_data.append({
                            'source': source_name,
                            'target': target_name,
                            'permission': f"{permission_type} (through {intermediate_group} membership)",
                            'method': f"User is member of {intermediate_group} which has {permission_type} over {target_name}",
                            'via_group': intermediate_group,
                            'attack_type': 'GroupEscalation'
                        })
                    elif edge_type in ['GenericWrite', 'GenericAll', 'ForceChangePassword']:
                        # Password change attack
                        attack_chain_data.append({
                            'source': source_name,
                            'target': target_name,
                            'permission': edge_type,
                            'method': f"Changed {target_name}'s password using {edge_type} permission",
                            'via_group': via_group or '',
                            'attack_type': 'PasswordChange'
                        })
                    else:
                        attack_chain_data.append({
                            'source': source_name,
                            'target': target_name,
                            'permission': edge_type,
                            'method': f"Exploited {edge_type} permission",
                            'via_group': via_group or '',
                            'attack_type': 'Other'
                        })
                
                # Get AI remediation
                ai_reasoner = AIReasoner(nomad_config.llm)
                remediation = ai_reasoner.generate_attack_chain_remediation(
                    attack_chains=attack_chain_data,
                    compromised_users=exec_report.owned_users,
                    domain=domain
                )
                
                # Save remediation to file
                remediation_path = Path(output_dir) / "remediation.json"
                with open(remediation_path, 'w') as f:
                    json.dump(remediation, f, indent=2)
                
                log(f"[+] Remediation advice saved to: {remediation_path}")
                
                # Also save as markdown for easy reading
                remediation_md = Path(output_dir) / "remediation.md"
                with open(remediation_md, 'w') as f:
                    f.write("# Attack Chain Remediation\n\n")
                    f.write(f"## Risk Level: {remediation.get('risk_level', 'Unknown')}\n\n")
                    f.write("## Attack Summary\n")
                    f.write(f"{remediation.get('attack_summary', 'N/A')}\n\n")
                    f.write("## Immediate Actions\n")
                    for action in remediation.get('immediate_actions', []):
                        f.write(f"- ⚠️ {action}\n")
                    f.write("\n## Remediation Steps\n")
                    for step in remediation.get('remediation_steps', []):
                        f.write(f"### Priority {step.get('priority', '?')}: {step.get('action', 'N/A')}\n")
                        f.write(f"*{step.get('reason', '')}*\n\n")
                
                result.metadata['remediation'] = remediation
            
            # Add execution info to result
            result.metadata['execution'] = exec_report.to_dict()
            
        except Exception as e:
            log(f"[!] Execution error: {e}")
            import traceback
            log(f"[!] {traceback.format_exc()}")
    
    return result


def get_attack_path_visual(
    path_id: str,
    output_dir: str = "output"
) -> Optional[str]:
    """Get the visualization file path for a specific attack path.
    
    Args:
        path_id: ID of the attack path
        output_dir: Directory where visualizations are stored
        
    Returns:
        Path to the visualization file, or None if not found
    """
    # Check for HTML visualization first
    html_path = Path(output_dir) / f"path_{path_id}.html"
    if html_path.exists():
        return str(html_path)
    
    # Check for PNG
    png_path = Path(output_dir) / f"path_{path_id}.png"
    if png_path.exists():
        return str(png_path)
    
    return None


def _build_config(config_dict: Optional[dict], output_dir: str) -> NomadConfig:
    """Build NomadConfig from dictionary.
    
    Args:
        config_dict: Configuration dictionary
        output_dir: Output directory
        
    Returns:
        NomadConfig instance
    """
    if config_dict:
        return NomadConfig.from_dict(config_dict)
    
    # Build default config with output_dir
    return NomadConfig(
        llm=LLMConfig(
            enabled=True,
            api_key=os.environ.get("OPENAI_API_KEY")
        ),
        ldap=LDAPConfig(),
        analysis=AnalysisConfig(),
        output=OutputConfig(output_dir=output_dir)
    )


# Additional helper functions for the GUI

def validate_ldap_connection(
    server_ip: str,
    domain: str,
    username: str,
    password: str
) -> tuple[bool, str]:
    """Validate LDAP connection before running full analysis.
    
    Args:
        server_ip: Domain controller IP
        domain: Domain name
        username: Username
        password: Password
        
    Returns:
        Tuple of (success, message)
    """
    if not LDAP3_AVAILABLE:
        return False, "ldap3 library not installed"
    
    try:
        collector = LDAPCollector(
            server_ip=server_ip,
            domain=domain,
            username=username,
            password=password,
            verbose=False
        )
        
        if collector.connect():
            collector.disconnect()
            return True, "Connection successful"
        else:
            return False, "Connection failed"
            
    except Exception as e:
        return False, str(e)


def get_analysis_preview(
    graph: ADGraph
) -> dict:
    """Get a quick preview of what analysis will find.
    
    Useful for showing the user what's in the data before running full analysis.
    
    Args:
        graph: ADGraph with loaded data
        
    Returns:
        Dictionary with preview statistics
    """
    stats = graph.get_environment_stats()
    
    hvt = graph.get_high_value_targets()
    da = graph.get_domain_admins()
    dc = graph.get_domain_controllers()
    
    return {
        'total_nodes': graph.node_count,
        'total_edges': graph.edge_count,
        'users': stats.total_users,
        'groups': stats.total_groups,
        'computers': stats.total_computers,
        'domain_admins': len(da),
        'domain_controllers': len(dc),
        'high_value_targets': len(hvt),
        'kerberoastable': stats.kerberoastable_users,
        'unconstrained_delegation': stats.unconstrained_delegation_count,
    }

