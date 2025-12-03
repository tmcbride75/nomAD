import streamlit as st
import json
import subprocess
import threading
from pathlib import Path
import time
import sys
import os
import pandas as pd
from queue import Queue

# Add nomad package to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from nomad.gui_integration.bridge import run_analysis, get_attack_path_visual
from nomad.model.schemas import RiskLevel

# Page config
st.set_page_config(
    page_title="nomAD",
    page_icon="🔐",
    layout="wide",
    initial_sidebar_state="collapsed"
)

# Custom CSS for styling
st.markdown("""
<style>
    .stApp {
        background-color: #1f2937;
    }
    .main-header {
        font-size: 3rem;
        font-weight: bold;
        margin-bottom: 0.5rem;
    }
    .nom-text {
        color: white;
    }
    .ad-text {
        color: #a16207;
    }
    .subtitle {
        color: #9ca3af;
        margin-bottom: 2rem;
    }
    .terminal-output {
        background-color: #000000;
        color: #e5e7eb;
        padding: 1rem;
        border-radius: 0.5rem;
        font-family: monospace;
        font-size: 0.875rem;
        height: 400px;
        overflow-y: auto;
    }
    .success-line {
        color: #4ade80;
    }
    .warning-line {
        color: #facc15;
    }
    .info-line {
        color: #60a5fa;
    }
    .compromised-card {
        background-color: #1f2937;
        border: 1px solid #374151;
        border-radius: 0.5rem;
        padding: 1rem;
        margin-bottom: 0.5rem;
    }
    .compromised-card:hover {
        border-color: #a16207;
    }
    div[data-testid="stHorizontalBlock"] {
        gap: 1rem;
    }
    .stTabs [data-baseweb="tab-list"] {
        gap: 0.5rem;
        background-color: #1f2937;
    }
    .stTabs [data-baseweb="tab"] {
        background-color: transparent;
        color: #9ca3af;
        border-bottom: 2px solid transparent;
        padding: 0.75rem 1.5rem;
    }
    .stTabs [aria-selected="true"] {
        background-color: #854d0e;
        color: white;
        border-bottom: 2px solid #a16207;
    }
</style>
""", unsafe_allow_html=True)

# Initialize session state
if 'terminal_output' not in st.session_state:
    st.session_state.terminal_output = []
if 'is_running' not in st.session_state:
    st.session_state.is_running = False
if 'attack_data' not in st.session_state:
    st.session_state.attack_data = {'nodes': [], 'edges': []}
if 'compromised_accounts' not in st.session_state:
    st.session_state.compromised_accounts = []
if 'analysis_result' not in st.session_state:
    st.session_state.analysis_result = None
if 'selected_path' not in st.session_state:
    st.session_state.selected_path = None
if 'output_queue' not in st.session_state:
    st.session_state.output_queue = Queue()
if 'analysis_error' not in st.session_state:
    st.session_state.analysis_error = None

# Header
st.markdown('<div class="main-header"><span class="nom-text">nom</span><span class="ad-text">AD</span></div>', unsafe_allow_html=True)
st.markdown('<div class="subtitle">AI-Driven Active Directory Enumeration & Exploitation Framework</div>', unsafe_allow_html=True)

# Tabs
tab1, tab2, tab3, tab4, tab5, tab6 = st.tabs(["Configuration", "Terminal Output", "Full Chain", "Attack Chains", "Compromised", "Remediation"])

# Configuration Tab
with tab1:
    st.markdown("### Target Configuration")
    
    col1, col2 = st.columns(2)
    
    with col1:
        username = st.text_input("Username", placeholder="username", value=st.session_state.get('username', ''))
        ip = st.text_input("Target IP", placeholder="192.168.1.100", value=st.session_state.get('ip', ''))
    
    with col2:
        domain = st.text_input("Domain Name", placeholder="example.local", value=st.session_state.get('domain', ''))
    
    st.markdown("<br>", unsafe_allow_html=True)
    
    # Authentication options
    st.markdown("### Authentication")
    auth_type = st.radio(
        "Authentication Method",
        ["Password", "NTLM Hash (Pass-the-Hash)"],
        horizontal=True,
        help="Choose authentication method - Password or NTLM hash"
    )
    
    if auth_type == "Password":
        password = st.text_input("Password", type="password", placeholder="••••••••", value=st.session_state.get('password', ''))
        ntlm_hash = None
    else:
        password = None
        ntlm_hash = st.text_input("NTLM Hash", placeholder="aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0", 
                                   value=st.session_state.get('ntlm_hash', ''),
                                   help="Format: LM:NT or just NT hash")
    
    st.markdown("<br>", unsafe_allow_html=True)
    
    # Execution options
    col_opt1, col_opt2 = st.columns(2)
    with col_opt1:
        execute_attacks = st.checkbox("Execute Attack Chain", value=True, 
                                      help="Automatically exploit discovered attack paths")
    with col_opt2:
        clean_output = st.checkbox("Clean Previous Output", value=True,
                                   help="Remove previous results before running")
    
    st.markdown("<br>", unsafe_allow_html=True)
    
    col_btn1, col_btn2, col_btn3 = st.columns([1, 1, 4])
    
    with col_btn1:
        has_creds = username and (password or ntlm_hash) and domain and ip
        can_start = has_creds
        start_button = st.button("Start Analysis", type="primary", disabled=st.session_state.is_running or not can_start, use_container_width=True)
    
    with col_btn2:
        if st.session_state.is_running:
            stop_button = st.button("Stop", type="secondary", use_container_width=True)
            if stop_button:
                st.session_state.is_running = False
                st.session_state.terminal_output.append("[!] Enumeration stopped by user")
                st.rerun()
    
    if start_button:
        st.session_state.is_running = True
        st.session_state.terminal_output = []
        st.session_state.analysis_result = None
        st.session_state.analysis_error = None  # Clear previous errors
        
        # Store credentials in session state
        st.session_state['username'] = username
        st.session_state['password'] = password if password else None
        st.session_state['ntlm_hash'] = ntlm_hash if ntlm_hash else None
        st.session_state['domain'] = domain
        st.session_state['ip'] = ip
        
        # Add initial messages
        st.session_state.terminal_output.append("[+] Initializing nomAD framework...")
        if ntlm_hash:
            st.session_state.terminal_output.append("[*] Using Pass-the-Hash authentication")
        
        # Store parameters and get queue reference before thread starts
        analysis_params = {
            'username': username if username else None,
            'password': password if password else None,
            'ntlm_hash': ntlm_hash if ntlm_hash else None,
            'domain': domain if domain else None,
            'server_ip': ip if ip else None,
            'output_dir': "output",
            'execute_attacks': execute_attacks,
            'clean_output': clean_output
        }
        st.session_state['analysis_params'] = analysis_params
        
        # Get queue reference before thread starts (thread-safe)
        output_queue = st.session_state.output_queue
        
        def run_analysis_backend():
            """Background thread function - uses queue for thread-safe communication."""
            try:
                # Use captured params and queue
                params = analysis_params
                
                # Create progress callback that sends to queue
                def progress_callback(message):
                    output_queue.put(("log", message))
                
                # Run actual analysis with progress callback for verbose output
                result = run_analysis(
                    username=params.get('username'),
                    password=params.get('password'),
                    ntlm_hash=params.get('ntlm_hash'),
                    domain=params.get('domain'),
                    server_ip=params.get('server_ip'),
                    output_dir=params.get('output_dir', 'output'),
                    execute_attacks=params.get('execute_attacks', True),
                    clean_output=params.get('clean_output', True),
                    progress_callback=progress_callback  # Pass callback for verbose output
                )
                
                # Send result via queue
                output_queue.put(("result", result))
                
                # Signal completion
                output_queue.put(("complete", None))
                
            except Exception as e:
                import traceback
                error_msg = f"[!] Error: {str(e)}"
                output_queue.put(("log", error_msg))
                output_queue.put(("log", f"[!] {traceback.format_exc()}"))
                output_queue.put(("error", str(e)))
                output_queue.put(("complete", None))
        
        thread = threading.Thread(target=run_analysis_backend, daemon=True)
        thread.start()
        st.session_state['analysis_thread'] = thread
        st.rerun()

# Terminal Output Tab
with tab2:
    st.markdown("### Terminal Output")
    
    if st.session_state.is_running:
        st.info("🔄 Analysis in progress...")
        
        # Process messages from queue (thread-safe)
        output_queue = st.session_state.output_queue
        while not output_queue.empty():
            try:
                msg_type, message = output_queue.get_nowait()
                if msg_type == "complete":
                    st.session_state.is_running = False
                elif msg_type == "log":
                    st.session_state.terminal_output.append(message)
                elif msg_type == "result":
                    st.session_state.analysis_result = message
                    # Store the result but don't create SVG visualization here
                    # The visualization will be shown from the actual path visualizations
                    st.session_state.attack_data = {'nodes': [], 'edges': []}
                elif msg_type == "error":
                    st.session_state.analysis_error = message
            except Exception as e:
                # Handle case where queue item is not a tuple (backward compatibility)
                try:
                    message = output_queue.get_nowait()
                    if isinstance(message, str):
                        if message == "__COMPLETE__":
                            st.session_state.is_running = False
                        else:
                            st.session_state.terminal_output.append(message)
                except:
                    break
                break
    
    # Display terminal output
    terminal_html = '<div class="terminal-output">'
    if not st.session_state.terminal_output:
        terminal_html += '<span style="color: #6b7280;">Waiting for execution...</span>'
    else:
        for line in st.session_state.terminal_output:
            if line.startswith('[+]'):
                terminal_html += f'<div class="success-line">{line}</div>'
            elif line.startswith('[!]'):
                terminal_html += f'<div class="warning-line">{line}</div>'
            elif line.startswith('[*]'):
                terminal_html += f'<div class="info-line">{line}</div>'
            else:
                terminal_html += f'<div>{line}</div>'
    terminal_html += '</div>'
    
    st.markdown(terminal_html, unsafe_allow_html=True)
    
    # Show error if any
    if st.session_state.get('analysis_error'):
        st.error(f"Analysis error: {st.session_state.analysis_error}")
    
    # Auto-refresh while running
    if st.session_state.is_running:
        time.sleep(0.5)
        st.rerun()

# Full Chain Tab - Shows unified attack chain
with tab3:
    st.markdown("### Complete Attack Chain")
    
    if st.session_state.analysis_result:
        result = st.session_state.analysis_result
        
        # Summary bar
        col1, col2, col3 = st.columns(3)
        with col1:
            st.metric("Total Pivots", result.total_paths)
        with col2:
            total_users = len(set(n for p in result.attack_paths for n in p.nodes)) if result.attack_paths else 0
            st.metric("Users in Chain", total_users)
        with col3:
            st.metric("Risk Level", "High" if result.high_paths > 0 else "Medium")
        
        # Show unified chain visualization
        if "unified_chain" in result.visualization_paths:
            chain_path = result.visualization_paths["unified_chain"]
            script_dir = Path(__file__).parent
            possible_paths = [
                Path(chain_path),
                script_dir / chain_path,
                Path("output") / Path(chain_path).name,
                script_dir / "output" / Path(chain_path).name,
                Path("/home/kali/Desktop/nomAD2") / chain_path,
            ]
            
            chain_file = None
            for p in possible_paths:
                if p.exists():
                    chain_file = p
                    break
            
            if chain_file and str(chain_file).endswith('.html'):
                try:
                    with open(chain_file, 'r', encoding='utf-8') as f:
                        html_content = f.read()
                    st.components.v1.html(html_content, height=600, scrolling=True)
                except Exception as e:
                    st.error(f"Error loading chain visualization: {e}")
            else:
                st.info("Run analysis to generate the attack chain visualization")
        else:
            st.info("Run analysis to generate the attack chain visualization")
        
        # Chain summary text
        if result.attack_paths:
            st.markdown("---")
            st.markdown("### Chain Summary")
            
            # Build proper attack flow from paths
            chain_steps = []
            for i, path in enumerate(result.attack_paths, 1):
                source_name = path.properties.get('source_name', 'Unknown')
                target_name = path.properties.get('target_name', 'Unknown')
                edge_type = path.properties.get('edge_type', 'Unknown')
                intermediate_group = path.properties.get('intermediate_group', '')
                permission_type = path.properties.get('permission_type', '')
                
                # Build step description - show intermediate group if present
                if intermediate_group:
                    # This is a group escalation path
                    step_text = f"**Step {i}:** `{source_name}` → [MemberOf] → **{intermediate_group}** → [{permission_type}] → `{target_name}`"
                else:
                    step_text = f"**Step {i}:** `{source_name}` → [{edge_type}] → `{target_name}`"
                
                chain_steps.append(step_text)
            
            # Display steps
            for step in chain_steps:
                st.markdown(step)
            
            # Show compact chain view
            st.markdown("---")
            st.markdown("**Attack Flow:**")
            
            # Build compact flow including intermediate groups: A → B → DirMgmt → DA
            seen_in_flow = []
            for path in result.attack_paths:
                source = path.properties.get('source_name', '')
                intermediate = path.properties.get('intermediate_group', '')
                target = path.properties.get('target_name', '')
                
                if source and source not in seen_in_flow:
                    seen_in_flow.append(source)
                if intermediate and intermediate not in seen_in_flow:
                    seen_in_flow.append(intermediate)
                if target and target not in seen_in_flow:
                    seen_in_flow.append(target)
            
            if seen_in_flow:
                flow_text = " → ".join([f"`{n}`" for n in seen_in_flow])
                st.markdown(flow_text)
    else:
        st.info("Run analysis from the Configuration tab to see the complete attack chain")

# Attack Chains Tab - Individual paths
with tab4:
    st.markdown("### Individual Attack Paths")
    
    if st.session_state.analysis_result:
        result = st.session_state.analysis_result
        
        # Summary stats
        col1, col2, col3, col4, col5 = st.columns(5)
        with col1:
            st.metric("Total Paths", result.total_paths)
        with col2:
            st.metric("Critical", result.critical_paths, delta=None, delta_color="inverse")
        with col3:
            st.metric("High", result.high_paths)
        with col4:
            st.metric("Medium", result.medium_paths)
        with col5:
            st.metric("Low", result.low_paths)
        
        st.markdown("<br>", unsafe_allow_html=True)
        
        # Individual path selector
        if result.attack_paths:
            # Build path options
            path_options = []
            for i, p in enumerate(result.attack_paths):
                prefix = "[Auth] " if p.properties.get('from_authenticated_user', False) else ""
                path_options.append(f"{prefix}Path #{i+1}: {p.privilege_gain} ({p.risk_level.value})")
            
            selected_idx = st.selectbox("Select Attack Path", range(len(path_options)), 
                                       format_func=lambda x: path_options[x], key="path_selector")
            selected_path = result.attack_paths[selected_idx]
            st.session_state.selected_path = selected_path
            
            # Show if this path starts from authenticated user
            if selected_path.properties.get('from_authenticated_user', False):
                st.success("This path starts from your authenticated user account")
            
            # Display path details
            st.markdown("---")
            col1, col2 = st.columns(2)
            with col1:
                st.metric("Risk Score", f"{selected_path.risk_score:.1f}", 
                         delta=f"{selected_path.risk_level.value}", delta_color="inverse")
            with col2:
                st.metric("Steps", selected_path.estimated_steps)
            
            st.markdown(f"**Privilege Gained:** {selected_path.privilege_gain}")
            st.markdown(f"**Attack Path:**")
            st.code(selected_path.raw_explanation, language=None)
            
            if selected_path.ai_risk_commentary:
                st.markdown(f"**AI Commentary:** {selected_path.ai_risk_commentary}")
            if selected_path.ai_explanation:
                st.markdown(f"**AI Explanation:** {selected_path.ai_explanation}")
            if selected_path.ai_mitigations:
                st.markdown("**Mitigations:**")
                for mitigation in selected_path.ai_mitigations:
                    st.markdown(f"- {mitigation}")
            
            # Show visualization if available
            st.markdown("---")
            st.markdown("### Visualization")
            if selected_path.id in result.visualization_paths:
                vis_path = result.visualization_paths[selected_path.id]
                
                # Try multiple locations to find the file
                script_dir = Path(__file__).parent
                possible_paths = [
                    Path(vis_path),                          # As-is
                    script_dir / vis_path,                   # Relative to script
                    Path("output") / Path(vis_path).name,    # In output folder
                    script_dir / "output" / Path(vis_path).name,  # Script's output folder
                    Path("/home/kali/Desktop/nomAD2") / vis_path,  # Absolute fallback
                ]
                
                actual_file = None
                for p in possible_paths:
                    if p.exists():
                        actual_file = p
                        break
                
                if actual_file:
                    if str(actual_file).endswith('.html'):
                        # For HTML, read and display inline
                        try:
                            with open(actual_file, 'r', encoding='utf-8') as f:
                                html_content = f.read()
                            st.components.v1.html(html_content, height=600, scrolling=True)
                        except Exception as e:
                            st.error(f"Error loading HTML visualization: {e}")
                    else:
                        # For images (PNG, SVG, etc.)
                        try:
                            st.image(str(actual_file), use_container_width=True)
                        except Exception as e:
                            st.error(f"Error loading image: {e}")
                else:
                    st.warning(f"Visualization file not found: {vis_path}")
                    st.info(f"Path ID: {selected_path.id}")
                    st.info(f"Searched: {[str(p) for p in possible_paths]}")
                    # Show which files actually exist
                    existing = [str(p) for p in possible_paths if p.exists()]
                    st.info(f"Existing: {existing}")
            else:
                # Fallback: Show attack path as formatted text
                st.warning(f"No visualization path for ID: {selected_path.id}")
                st.info(f"Available IDs: {list(result.visualization_paths.keys())}")
                st.markdown("**Attack Path:**")
                st.code(selected_path.raw_explanation, language=None)
    
    if not st.session_state.analysis_result:
        st.info("No attack chain data available. Run analysis first.")
    # Legacy SVG visualization removed - using actual path visualizations instead

# Compromised Tab
with tab5:
    st.markdown("### Compromised Credentials")
    
    # Read credentials from compromised.txt if it exists
    # Try multiple locations
    script_dir = Path(__file__).parent
    possible_cred_files = [
        Path("output/compromised.txt"),
        script_dir / "output" / "compromised.txt",
        Path("/home/kali/Desktop/nomAD2/output/compromised.txt"),
    ]
    
    compromised_file = None
    for f in possible_cred_files:
        if f.exists():
            compromised_file = f
            break
    
    credentials = []
    
    if compromised_file and compromised_file.exists():
        with open(compromised_file, 'r') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#') and ':' in line:
                    parts = line.split(':', 1)
                    if len(parts) == 2:
                        credentials.append({
                            'username': parts[0],
                            'password': parts[1]
                        })
    
    if credentials:
        st.success(f"{len(credentials)} accounts compromised")
        
        # Separate credentials by type
        passwords = []
        nt_hashes = []
        tgs_hashes = []
        
        for cred in credentials:
            if cred['password'].startswith('[NT_HASH]'):
                nt_hashes.append({
                    'username': cred['username'],
                    'hash': cred['password'].replace('[NT_HASH]', '')
                })
            elif cred['password'].startswith('[TGS_HASH]'):
                tgs_hashes.append({
                    'username': cred['username'],
                    'file': cred['password'].replace('[TGS_HASH]', '')
                })
            else:
                passwords.append(cred)
        
        # Display plaintext passwords
        if passwords:
            st.markdown("#### Plaintext Passwords")
            for cred in passwords:
                st.markdown(f'''
                <div class="compromised-card">
                    <div style="display: flex; align-items: center; gap: 0.75rem; margin-bottom: 0.5rem;">
                        <span style="color: #fbbf24; font-weight: 600; font-size: 1.125rem;">{cred['username']}</span>
                    </div>
                    <div style="display: flex; align-items: center; gap: 0.5rem;">
                        <span style="color: #9ca3af;">Password:</span>
                        <span style="color: #4ade80; font-family: monospace; font-size: 0.875rem; background: #1f2937; padding: 0.25rem 0.5rem; border-radius: 0.25rem;">{cred['password']}</span>
                    </div>
                </div>
                ''', unsafe_allow_html=True)
        
        # Display NT hashes (can be used for Pass-the-Hash)
        if nt_hashes:
            st.markdown("#### NT Hashes (Pass-the-Hash)")
            st.info("Use with: `evil-winrm -i <IP> -u <user> -H <hash>`")
            for cred in nt_hashes:
                st.markdown(f'''
                <div class="compromised-card" style="border-left: 3px solid #8b5cf6;">
                    <div style="display: flex; align-items: center; gap: 0.75rem; margin-bottom: 0.5rem;">
                        <span style="color: #fbbf24; font-weight: 600; font-size: 1.125rem;">{cred['username']}</span>
                        <span style="background: #8b5cf6; color: white; font-size: 0.75rem; padding: 0.125rem 0.5rem; border-radius: 0.25rem;">NT Hash</span>
                    </div>
                    <div style="display: flex; align-items: center; gap: 0.5rem;">
                        <span style="color: #9ca3af;">Hash:</span>
                        <span style="color: #a78bfa; font-family: monospace; font-size: 0.875rem; background: #1f2937; padding: 0.25rem 0.5rem; border-radius: 0.25rem;">{cred['hash']}</span>
                    </div>
                    <div style="margin-top: 0.5rem; font-size: 0.75rem; color: #6b7280;">
                        <code style="background: #374151; padding: 0.25rem 0.5rem; border-radius: 0.25rem;">evil-winrm -i &lt;IP&gt; -u {cred['username']} -H {cred['hash']}</code>
                    </div>
                </div>
                ''', unsafe_allow_html=True)
        
        # Display TGS hashes (need cracking)
        if tgs_hashes:
            st.markdown("#### TGS Hashes (Requires Cracking)")
            st.warning("These hashes need to be cracked with hashcat/john")
            for cred in tgs_hashes:
                st.markdown(f'''
                <div class="compromised-card" style="border-left: 3px solid #f59e0b;">
                    <div style="display: flex; align-items: center; gap: 0.75rem; margin-bottom: 0.5rem;">
                        <span style="color: #fbbf24; font-weight: 600; font-size: 1.125rem;">{cred['username']}</span>
                        <span style="background: #f59e0b; color: black; font-size: 0.75rem; padding: 0.125rem 0.5rem; border-radius: 0.25rem;">TGS Hash</span>
                    </div>
                    <div style="display: flex; align-items: center; gap: 0.5rem;">
                        <span style="color: #9ca3af;">File:</span>
                        <span style="color: #fbbf24; font-family: monospace; font-size: 0.875rem;">{cred['file']}</span>
                    </div>
                    <div style="margin-top: 0.5rem; font-size: 0.75rem; color: #6b7280;">
                        <code style="background: #374151; padding: 0.25rem 0.5rem; border-radius: 0.25rem;">hashcat -m 13100 {cred['file']} wordlist.txt</code>
                    </div>
                </div>
                ''', unsafe_allow_html=True)
        
        st.markdown("<br>", unsafe_allow_html=True)
        
        # Build formatted output
        output_lines = ["# Compromised Credentials"]
        
        if passwords:
            output_lines.append("\n## Plaintext Passwords")
            for c in passwords:
                output_lines.append(f"{c['username']}:{c['password']}")
        
        if nt_hashes:
            output_lines.append("\n## NT Hashes (Pass-the-Hash)")
            for c in nt_hashes:
                output_lines.append(f"{c['username']}:{c['hash']}")
        
        if tgs_hashes:
            output_lines.append("\n## TGS Hashes (Kerberoast - needs cracking)")
            for c in tgs_hashes:
                output_lines.append(f"{c['username']}:{c['file']}")
        
        all_creds = "\n".join(output_lines)
        
        # Copy all button
        st.download_button(
            label="Download All Credentials",
            data=all_creds,
            file_name="compromised_credentials.txt",
            mime="text/plain"
        )
        
        # Show as code block for easy copying
        st.markdown("### Quick Copy")
        st.code(all_creds, language=None)
    else:
        st.info("No compromised credentials yet. Run analysis with execution enabled to exploit the attack chain.")
        st.markdown("""
        **To compromise accounts:**
        ```bash
        python3 -m nomad -s <IP> -d <domain> -u <user> -p <pass> -o output --execute
        ```
        """)
    
    st.markdown("---")
    
    # Also show attack paths summary
    if st.session_state.analysis_result:
        result = st.session_state.analysis_result
        
        st.markdown("### Attack Paths Summary")
        
        # Download buttons
        if result.report_path and Path(result.report_path).exists():
            with open(result.report_path, 'r') as f:
                st.download_button(
                    label="Download JSON Report",
                    data=f.read(),
                    file_name="nomad_results.json",
                    mime="application/json"
                )
        
        # Show all attack paths in a table
        if result.attack_paths:
            paths_data = []
            for i, path in enumerate(result.attack_paths, 1):
                auth_indicator = "Yes" if path.properties.get('from_authenticated_user', False) else "No"
                paths_data.append({
                    'Rank': i,
                    'From Auth User': auth_indicator,
                    'Privilege Gained': path.privilege_gain,
                    'Risk Level': path.risk_level.value,
                    'Risk Score': f"{path.risk_score:.1f}",
                    'Steps': path.estimated_steps,
                    'Path': path.raw_explanation
                })
            
            df = pd.DataFrame(paths_data)
            st.dataframe(df, use_container_width=True, hide_index=True)

# Remediation Tab
with tab6:
    st.markdown("### Security Remediation Report")
    
    # Check for remediation file
    remediation_file = Path("output/remediation.json")
    remediation_md = Path("output/remediation.md")
    
    if remediation_file.exists():
        try:
            with open(remediation_file, 'r') as f:
                remediation = json.load(f)
            
            # Risk Level Banner
            risk_level = remediation.get('risk_level', 'Unknown')
            risk_colors = {
                'Critical': '#dc2626',
                'High': '#ea580c', 
                'Medium': '#ca8a04',
                'Low': '#16a34a'
            }
            risk_color = risk_colors.get(risk_level, '#6b7280')
            
            st.markdown(f'''
            <div style="border-left: 4px solid {risk_color}; padding: 0.75rem 1rem; margin-bottom: 1.5rem; background: #111827;">
                <span style="color: #9ca3af; font-size: 0.75rem; text-transform: uppercase; letter-spacing: 0.05em;">Risk Assessment</span>
                <div style="color: {risk_color}; font-weight: 600; font-size: 1.25rem; margin-top: 0.25rem;">{risk_level}</div>
            </div>
            ''', unsafe_allow_html=True)
            
            # Attack Summary
            st.markdown('<p style="color: #9ca3af; font-size: 0.75rem; text-transform: uppercase; letter-spacing: 0.05em; margin-bottom: 0.5rem;">Attack Summary</p>', unsafe_allow_html=True)
            st.markdown(f'''
            <div style="background: #111827; border: 1px solid #374151; padding: 1rem; border-radius: 0.375rem; margin-bottom: 1rem; color: #e5e7eb; line-height: 1.6;">
                {remediation.get('attack_summary', 'No summary available.')}
            </div>
            ''', unsafe_allow_html=True)
            
            # Impact and Root Cause (if present)
            if remediation.get('attack_impact') or remediation.get('root_cause'):
                col_impact, col_cause = st.columns(2)
                
                with col_impact:
                    if remediation.get('attack_impact'):
                        st.markdown('<p style="color: #9ca3af; font-size: 0.75rem; text-transform: uppercase; letter-spacing: 0.05em; margin-bottom: 0.5rem;">Potential Impact</p>', unsafe_allow_html=True)
                        st.markdown(f'''
                        <div style="background: #1f1010; border: 1px solid #7f1d1d; padding: 1rem; border-radius: 0.375rem; margin-bottom: 1rem; color: #fca5a5; line-height: 1.5; font-size: 0.9rem;">
                            {remediation.get('attack_impact')}
                        </div>
                        ''', unsafe_allow_html=True)
                
                with col_cause:
                    if remediation.get('root_cause'):
                        st.markdown('<p style="color: #9ca3af; font-size: 0.75rem; text-transform: uppercase; letter-spacing: 0.05em; margin-bottom: 0.5rem;">Root Cause</p>', unsafe_allow_html=True)
                        st.markdown(f'''
                        <div style="background: #1a1a10; border: 1px solid #78350f; padding: 1rem; border-radius: 0.375rem; margin-bottom: 1rem; color: #fcd34d; line-height: 1.5; font-size: 0.9rem;">
                            {remediation.get('root_cause')}
                        </div>
                        ''', unsafe_allow_html=True)
            
            st.markdown("---")
            
            # Immediate Actions
            st.markdown('<p style="color: #f87171; font-size: 0.875rem; text-transform: uppercase; letter-spacing: 0.05em; margin-bottom: 0.75rem; font-weight: 600;">Immediate Actions Required</p>', unsafe_allow_html=True)
            for i, action in enumerate(remediation.get('immediate_actions', []), 1):
                st.markdown(f'''
                <div style="background: #1f0f0f; border: 1px solid #7f1d1d; padding: 0.75rem 1rem; margin-bottom: 0.5rem; border-radius: 0.25rem;">
                    <span style="color: #f87171; font-weight: 600;">{i}.</span>
                    <span style="color: #fca5a5; margin-left: 0.5rem;">{action}</span>
                </div>
                ''', unsafe_allow_html=True)
            
            st.markdown("<br>", unsafe_allow_html=True)
            
            # Two column layout for remediation and prevention
            col_left, col_right = st.columns([1, 1])
            
            with col_left:
                # Remediation Steps
                st.markdown('<p style="color: #9ca3af; font-size: 0.75rem; text-transform: uppercase; letter-spacing: 0.05em; margin-bottom: 0.75rem;">Prioritized Remediation Steps</p>', unsafe_allow_html=True)
                for step in remediation.get('remediation_steps', []):
                    priority = step.get('priority', '?')
                    command = step.get('command_example', '')
                    
                    st.markdown(f'''
                    <div style="background: #1f2937; border: 1px solid #374151; padding: 0.75rem 1rem; margin-bottom: 0.5rem; border-radius: 0.25rem;">
                        <div style="display: flex; align-items: baseline; gap: 0.5rem;">
                            <span style="background: #374151; color: #e5e7eb; font-size: 0.7rem; padding: 0.125rem 0.375rem; border-radius: 0.125rem;">P{priority}</span>
                            <span style="color: #e5e7eb; font-weight: 500;">{step.get('action', 'N/A')}</span>
                        </div>
                        <div style="color: #9ca3af; font-size: 0.8rem; margin-top: 0.375rem; margin-left: 2.5rem;">
                            {step.get('reason', '')}
                        </div>
                        {"<div style='background: #111827; color: #60a5fa; font-family: monospace; font-size: 0.75rem; padding: 0.5rem; margin-top: 0.5rem; margin-left: 2.5rem; border-radius: 0.25rem; overflow-x: auto;'>" + command + "</div>" if command else ""}
                    </div>
                    ''', unsafe_allow_html=True)
            
            with col_right:
                # Prevention Measures
                if remediation.get('prevention_measures'):
                    st.markdown('<p style="color: #9ca3af; font-size: 0.75rem; text-transform: uppercase; letter-spacing: 0.05em; margin-bottom: 0.75rem;">Long-term Prevention</p>', unsafe_allow_html=True)
                    for measure in remediation.get('prevention_measures', []):
                        st.markdown(f'''
                        <div style="background: #0f1f0f; border: 1px solid #166534; padding: 0.625rem 1rem; margin-bottom: 0.375rem; border-radius: 0.25rem; color: #86efac; font-size: 0.875rem;">
                            • {measure}
                        </div>
                        ''', unsafe_allow_html=True)
                
                # Detection Recommendations
                if remediation.get('detection_recommendations'):
                    st.markdown('<p style="color: #9ca3af; font-size: 0.75rem; text-transform: uppercase; letter-spacing: 0.05em; margin-bottom: 0.75rem; margin-top: 1rem;">Detection & Monitoring</p>', unsafe_allow_html=True)
                    for rec in remediation.get('detection_recommendations', []):
                        st.markdown(f'''
                        <div style="background: #0f0f1f; border: 1px solid #1e40af; padding: 0.625rem 1rem; margin-bottom: 0.375rem; border-radius: 0.25rem; color: #93c5fd; font-size: 0.875rem;">
                            • {rec}
                        </div>
                        ''', unsafe_allow_html=True)
            
            # Download buttons
            st.markdown("<br>", unsafe_allow_html=True)
            col1, col2, col3 = st.columns([1, 1, 2])
            with col1:
                st.download_button(
                    label="Export JSON",
                    data=json.dumps(remediation, indent=2),
                    file_name="remediation.json",
                    mime="application/json"
                )
            with col2:
                if remediation_md.exists():
                    with open(remediation_md, 'r') as f:
                        st.download_button(
                            label="Export Markdown",
                            data=f.read(),
                            file_name="remediation.md",
                            mime="text/markdown"
                        )
        
        except Exception as e:
            st.error(f"Error loading remediation: {e}")
    
    else:
        st.markdown('''
        <div style="background: #111827; border: 1px solid #374151; padding: 2rem; border-radius: 0.5rem; text-align: center;">
            <p style="color: #9ca3af; margin-bottom: 1rem;">No remediation data available</p>
            <p style="color: #6b7280; font-size: 0.875rem;">Run analysis with attack execution enabled to generate remediation recommendations.</p>
        </div>
        ''', unsafe_allow_html=True)
