#!/usr/bin/env python3
"""
nomAD - AI-Assisted Active Directory Attack-Path Analysis Tool
==============================================================

Command-line interface for running AD security analysis.

Usage:
    # Basic analysis
    python -m nomad -u admin -p Password123 -d corp.local -s 192.168.1.100
    
    # With attack execution
    python -m nomad -u admin -p Password123 -d corp.local -s 192.168.1.100 --execute
    
    # With NTLM hash (Pass-the-Hash)
    python -m nomad -u admin --ntlm-hash aad3b435b51404ee:31d6cfe0d16ae931 -d corp.local -s 192.168.1.100

Options:
    --username, -u      Domain username
    --password, -p      Domain password  
    --ntlm-hash         NTLM hash for Pass-the-Hash authentication
    --domain, -d        Domain name (e.g., corp.local)
    --server, -s        Domain controller IP address
    --output, -o        Output directory (default: ./output)
    --execute           Execute attack chain
    --no-ai             Disable AI analysis
    --verbose, -v       Verbose output

Environment Variables:
    OPENAI_API_KEY      API key for OpenAI (for AI analysis)
    ANTHROPIC_API_KEY   API key for Anthropic (alternative)

Author: nomAD Research Project
"""

import argparse
import sys
import os
import json
from pathlib import Path

from .gui_integration.bridge import run_analysis, sync_clock_with_dc
from .reporting.report_builder import generate_text_report
from .exploitation.executor import AttackExecutor


def main():
    """Main CLI entry point."""
    parser = argparse.ArgumentParser(
        description="nomAD - AI-Assisted Active Directory Attack-Path Analysis",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Basic analysis
  %(prog)s -u admin -p Password123 -d corp.local -s 192.168.1.100
  
  # With attack execution
  %(prog)s -u admin -p Password123 -d corp.local -s 192.168.1.100 --execute
  
  # Pass-the-Hash authentication
  %(prog)s -u admin --ntlm-hash 31d6cfe0d16ae931b73c59d7e0c089c0 -d corp.local -s 192.168.1.100
  
  # Custom output directory
  %(prog)s -u admin -p Password123 -d corp.local -s 192.168.1.100 -o ./results
        """
    )
    
    # LDAP options
    ldap_group = parser.add_argument_group("LDAP Collection")
    ldap_group.add_argument(
        "-u", "--username",
        help="Domain username for LDAP authentication"
    )
    ldap_group.add_argument(
        "-p", "--password",
        help="Domain password for LDAP authentication"
    )
    ldap_group.add_argument(
        "--ntlm-hash",
        dest="ntlm_hash",
        help="NTLM hash for Pass-the-Hash authentication (instead of password)"
    )
    ldap_group.add_argument(
        "-d", "--domain",
        help="Domain name (e.g., corp.local)"
    )
    ldap_group.add_argument(
        "-s", "--server",
        help="Domain controller IP address or hostname"
    )
    
    # Output options
    output_group = parser.add_argument_group("Output")
    output_group.add_argument(
        "-o", "--output",
        default="output",
        help="Output directory for results (default: ./output)"
    )
    
    # Analysis options
    analysis_group = parser.add_argument_group("Analysis Options")
    analysis_group.add_argument(
        "--no-ai",
        action="store_true",
        help="Disable AI analysis (use rule-based only)"
    )
    analysis_group.add_argument(
        "--max-paths",
        type=int,
        default=100,
        help="Maximum attack paths to discover (default: 100)"
    )
    analysis_group.add_argument(
        "--execute",
        action="store_true",
        help="Execute the attack chain (DANGER: modifies AD passwords)"
    )
    
    # General options
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Enable verbose output"
    )
    parser.add_argument(
        "--version",
        action="version",
        version="nomAD 1.0.0"
    )
    
    args = parser.parse_args()
    
    # Validate inputs - require LDAP credentials
    has_ldap = args.username and (args.password or getattr(args, 'ntlm_hash', None)) and args.domain and args.server
    
    if not has_ldap:
        parser.error("Must provide LDAP credentials: -u (username), -p (password) or --ntlm-hash, -d (domain), -s (server)")
    
    # Build configuration
    config = {
        "llm": {
            "enabled": not args.no_ai,
        },
        "analysis": {
            "max_total_paths": args.max_paths,
        },
        "output": {
            "output_dir": args.output,
        },
        "verbose": args.verbose,
    }
    
    # Print banner
    print_banner()
    
    # Run analysis
    try:
        print(f"\n{'='*60}")
        print("Starting Analysis")
        print(f"{'='*60}\n")
        
        result = run_analysis(
            username=args.username,
            password=args.password,
            domain=args.domain,
            server_ip=args.server,
            ntlm_hash=args.ntlm_hash,
            output_dir=args.output,
            config=config,
            progress_callback=lambda msg: print(msg) if args.verbose else None
        )
        
        # Print summary
        print(f"\n{'='*60}")
        print("Analysis Complete")
        print(f"{'='*60}\n")
        
        print(f"Total Attack Paths: {result.total_paths}")
        print(f"  - Critical: {result.critical_paths}")
        print(f"  - High: {result.high_paths}")
        print(f"  - Medium: {result.medium_paths}")
        print(f"  - Low: {result.low_paths}")
        
        # Show the pivot chain
        if result.attack_paths:
            print("\n=== Pivot Chain ===")
            for i, path in enumerate(result.attack_paths, 1):
                print(f"{i}. {path.raw_explanation}")
        
        print(f"\nResults saved to:")
        print(f"  - JSON: {result.report_path}")
        if result.html_report_path:
            print(f"  - HTML: {result.html_report_path}")
        
        # Execute attack chain if requested
        if args.execute and has_ldap and result.attack_paths:
            print(f"\n{'='*60}")
            print("EXECUTING ATTACK CHAIN")
            print(f"{'='*60}")
            print("[!] WARNING: This will modify Active Directory!")
            
            executor = AttackExecutor(
                server_ip=args.server,
                domain=args.domain,
                username=args.username,
                password=args.password,
                verbose=True
            )
            
            attack_report = executor.execute_chain(result.attack_paths)
            
            # Save execution report
            report_path = Path(args.output) / "attack_report.json"
            with open(report_path, 'w') as f:
                json.dump(attack_report.to_dict(), f, indent=2)
            print(f"\n[+] Attack report saved to: {report_path}")
            
            # Save markdown report
            md_path = Path(args.output) / "attack_report.md"
            with open(md_path, 'w') as f:
                f.write(attack_report.to_markdown())
            print(f"[+] Markdown report saved to: {md_path}")
            
            # Save and print credentials
            if attack_report.owned_users:
                # Save to compromised.txt
                creds_path = Path(args.output) / "compromised.txt"
                with open(creds_path, 'w') as f:
                    f.write("# Compromised Credentials\n")
                    f.write(f"# Domain: {args.domain}\n")
                    f.write(f"# Generated by nomAD\n\n")
                    for user in attack_report.owned_users:
                        pwd = executor.credentials.get(user.lower(), "N/A")
                        f.write(f"{user}:{pwd}\n")
                print(f"[+] Credentials saved to: {creds_path}")
                
                print(f"\n{'='*60}")
                print("COMPROMISED CREDENTIALS")
                print(f"{'='*60}")
                for user in attack_report.owned_users:
                    pwd = executor.credentials.get(user.lower(), "N/A")
                    print(f"  {user}:{pwd}")
        
        # Print text report if verbose
        if args.verbose:
            print(f"\n{'='*60}")
            print(generate_text_report(result))
        
        return 0
        
    except Exception as e:
        print(f"\n[!] Error: {e}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        return 1


def print_banner():
    """Print the nomAD banner."""
    banner = r"""
                          _    ____  
  _ __   ___  _ __ ___   / \  |  _ \ 
 | '_ \ / _ \| '_ ` _ \ / _ \ | | | |
 | | | | (_) | | | | | / ___ \| |_| |
 |_| |_|\___/|_| |_| |_/_/   \_\____/ 
                                      
  AI-Assisted Active Directory Attack-Path Analysis
  Research Project - Educational Use Only
    """
    print(banner)


if __name__ == "__main__":
    sys.exit(main())

