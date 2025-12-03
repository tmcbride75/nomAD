# nomAD

**AI-Assisted Active Directory Attack-Path Analysis & Exploitation Tool**

nomAD is a Python-based security assessment tool that automatically discovers and exploits Active Directory attack paths. It combines LDAP enumeration, graph-based path analysis, and AI-powered remediation recommendations.

## Features

- **Live LDAP Collection** - Enumerate users, groups, computers, OUs, GPOs, and ACLs directly from Active Directory
- **Attack Path Discovery** - Automatically find privilege escalation chains using graph analysis
- **Automated Exploitation** - Execute discovered attack paths (password changes, group membership modifications, Shadow Credentials)
- **AI-Powered Analysis** - Get detailed remediation recommendations using OpenAI/Anthropic APIs
- **Interactive Visualization** - View attack chains in an interactive graph format
- **Dual Interface** - Use via CLI or Streamlit web GUI

## Installation

### Prerequisites

- Python 3.10+
- Kali Linux recommended (includes required tools)
- Network access to target Active Directory domain

### Setup

```bash
# Clone the repository
git clone https://github.com/yourusername/nomAD.git
cd nomAD

# Install Python dependencies
pip install -r requirements.txt

# Required system tools for exploitation
sudo apt install samba-common-bin  # For net rpc commands
pip install certipy-ad             # For Shadow Credentials attacks
```

### Optional: AI Integration

To enable AI-powered analysis, set your API key:

```bash
export OPENAI_API_KEY="your-api-key"
# or
export ANTHROPIC_API_KEY="your-api-key"
```

## Usage

### Web GUI (Recommended)

```bash
streamlit run nomad-streamlit.py
```

Then open http://localhost:8501 in your browser.

### Command Line

```bash
# Basic analysis (no exploitation)
python -m nomad -u <username> -p <password> -d <domain> -s <dc-ip>

# Analysis with attack execution
python -m nomad -u <username> -p <password> -d <domain> -s <dc-ip> --execute

# Using NTLM hash instead of password
python -m nomad -u <username> --ntlm-hash <hash> -d <domain> -s <dc-ip> --execute
```

### CLI Options

| Option | Description |
|--------|-------------|
| `-u, --username` | Domain username |
| `-p, --password` | Password |
| `--ntlm-hash` | NTLM hash (alternative to password) |
| `-d, --domain` | Domain name (e.g., corp.local) |
| `-s, --server` | Domain Controller IP |
| `-o, --output` | Output directory (default: output) |
| `--execute` | Execute discovered attack paths |
| `--clean-output` | Clear output directory before run |

## Pre-Run Checklist

Before running nomAD, ensure:

1. **Clock Synchronization** (prevents Kerberos errors):
   ```bash
   sudo timedatectl set-ntp false
   sudo ntpdate <DC-IP>
   ```

2. **Network Connectivity** to the Domain Controller on ports 389 (LDAP) and 445 (SMB)

3. **Valid Credentials** for a domain user account

## Output

nomAD generates several output files:

| File | Description |
|------|-------------|
| `nomad_results.json` | Full analysis results |
| `nomad_report.html` | HTML report |
| `attack_chain.html` | Interactive attack path visualization |
| `compromised.txt` | Credentials of compromised accounts |
| `remediation.json` | AI-generated remediation advice |
| `bloodhound_export/` | BloodHound-compatible JSON files |

## Architecture

```
nomAD/
├── nomad/
│   ├── ingestion/       # LDAP collection & BloodHound parsing
│   ├── model/           # Graph data structures
│   ├── analysis/        # Path finding & risk scoring
│   ├── exploitation/    # Attack execution modules
│   ├── ai_engine/       # LLM integration
│   ├── reporting/       # Visualization & reports
│   └── gui_integration/ # Streamlit bridge
├── nomad-streamlit.py   # Web GUI
└── requirements.txt
```

## Supported Attack Techniques

- **Password Changes** - Via GenericAll, GenericWrite, ForceChangePassword
- **Group Membership** - Add self to privileged groups
- **Shadow Credentials** - msDS-KeyCredentialLink manipulation for NT hash recovery
- **Kerberoasting** - Service account hash extraction (fallback)

## Legal Disclaimer

**This tool is intended for authorized security assessments only.**

- Only use on systems you own or have explicit written permission to test
- Unauthorized access to computer systems is illegal
- The authors are not responsible for misuse of this tool

## Acknowledgments

- [BloodHound](https://github.com/BloodHoundAD/BloodHound) - Inspiration for AD attack path analysis
- [Impacket](https://github.com/fortra/impacket) - Network protocol implementations
- [Certipy](https://github.com/ly4k/Certipy) - AD CS tools
