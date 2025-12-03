"""
nomAD Configuration Module
==========================

Centralized configuration management for the nomAD framework.
Supports environment variables for sensitive data (API keys, credentials).

Design Decision:
- Configuration is a singleton dataclass that can be passed through the pipeline
- AI features can be toggled on/off without affecting deterministic analysis
- Output paths are configurable for flexibility in different environments
"""

import os
from dataclasses import dataclass, field
from typing import Optional
from pathlib import Path


@dataclass
class LLMConfig:
    """Configuration for the AI/LLM reasoning layer.
    
    Attributes:
        enabled: Whether to use AI-enhanced analysis
        provider: LLM provider (openai, anthropic, local)
        model: Specific model to use (e.g., gpt-4, claude-3-sonnet)
        api_key: API key (loaded from environment if not provided)
        temperature: LLM temperature for response variability
        max_tokens: Maximum tokens in LLM response
    """
    enabled: bool = True
    provider: str = "openai"
    model: str = "gpt-4o-mini"
    api_key: Optional[str] = None
    api_base: Optional[str] = None
    temperature: float = 0.3
    max_tokens: int = 4096
    
    def __post_init__(self):
        """Load API key from environment if not explicitly provided."""
        if self.api_key is None:
            if self.provider == "openai":
                self.api_key = os.environ.get("OPENAI_API_KEY")
            elif self.provider == "anthropic":
                self.api_key = os.environ.get("ANTHROPIC_API_KEY")
        
        # Check for custom API base
        if self.api_base is None:
            self.api_base = os.environ.get("LLM_API_BASE")


@dataclass
class LDAPConfig:
    """Configuration for LDAP data collection.
    
    Attributes:
        use_ssl: Whether to use LDAPS (port 636) vs LDAP (port 389)
        page_size: Page size for LDAP queries
        timeout: Connection timeout in seconds
    """
    use_ssl: bool = False
    port: Optional[int] = None  # Auto-detect based on use_ssl
    page_size: int = 1000
    timeout: int = 30
    
    def __post_init__(self):
        if self.port is None:
            self.port = 636 if self.use_ssl else 389


@dataclass
class AnalysisConfig:
    """Configuration for attack path analysis.
    
    Attributes:
        max_path_length: Maximum length of attack paths to consider
        max_paths_per_target: Maximum paths to return per high-value target
        high_value_targets: List of group names considered high-value
        include_indirect_paths: Whether to include multi-hop indirect paths
    """
    max_path_length: int = 10
    max_paths_per_target: int = 20
    max_total_paths: int = 100
    high_value_targets: list = field(default_factory=lambda: [
        "Domain Admins",
        "Enterprise Admins", 
        "Administrators",
        "Schema Admins",
        "Account Operators",
        "Backup Operators",
        "Server Operators",
        "Print Operators",
        "DnsAdmins",
        "Group Policy Creator Owners"
    ])
    include_indirect_paths: bool = True
    
    # Edge weights for path cost calculation (lower = more exploitable)
    edge_weights: dict = field(default_factory=lambda: {
        "MemberOf": 0.1,           # Trivial - group membership
        "HasSession": 0.5,         # Medium - requires session access
        "AdminTo": 0.3,            # Easy - direct admin
        "CanRDP": 0.4,             # Medium - RDP access
        "CanPSRemote": 0.4,        # Medium - PSRemote access
        "ExecuteDCOM": 0.5,        # Medium - DCOM execution
        "GenericAll": 0.2,         # Easy - full control
        "GenericWrite": 0.3,       # Easy - write access
        "WriteOwner": 0.3,         # Easy - can take ownership
        "WriteDacl": 0.3,          # Easy - can modify ACL
        "ForceChangePassword": 0.3, # Easy - password reset
        "AddMember": 0.2,          # Easy - group modification
        "AllExtendedRights": 0.3,  # Medium - extended rights
        "Owns": 0.1,               # Trivial - ownership
        "Contains": 0.1,           # Trivial - container membership
        "GetChanges": 0.6,         # Hard - DCSync prep
        "GetChangesAll": 0.6,      # Hard - DCSync prep
        "ReadLAPSPassword": 0.3,   # Easy - LAPS read
        "ReadGMSAPassword": 0.3,   # Easy - GMSA read
        "AllowedToDelegate": 0.5,  # Medium - delegation
        "AllowedToAct": 0.5,       # Medium - RBCD
        "SQLAdmin": 0.4,           # Medium - SQL admin
        "HasSIDHistory": 0.2,      # Easy - SID history
        "TrustedBy": 0.4,          # Medium - trust relationship
    })


@dataclass
class OutputConfig:
    """Configuration for output and reporting.
    
    Attributes:
        output_dir: Directory for output files
        generate_html: Whether to generate HTML reports
        generate_json: Whether to generate JSON reports
        visualization_format: Format for visualizations (png, svg, html)
    """
    output_dir: str = "output"
    generate_html: bool = True
    generate_json: bool = True
    visualization_format: str = "html"  # png, svg, or html (interactive)
    
    def __post_init__(self):
        """Ensure output directory exists."""
        Path(self.output_dir).mkdir(parents=True, exist_ok=True)


@dataclass  
class NomadConfig:
    """Main configuration container for nomAD framework.
    
    Design Decision:
    This aggregates all sub-configurations into a single object that can be
    passed through the analysis pipeline. Each module can extract the
    configuration it needs.
    
    Usage:
        config = NomadConfig()  # Uses all defaults
        config = NomadConfig(llm=LLMConfig(enabled=False))  # Disable AI
    """
    llm: LLMConfig = field(default_factory=LLMConfig)
    ldap: LDAPConfig = field(default_factory=LDAPConfig)
    analysis: AnalysisConfig = field(default_factory=AnalysisConfig)
    output: OutputConfig = field(default_factory=OutputConfig)
    
    # Verbosity level for logging
    verbose: bool = True
    debug: bool = False
    
    @classmethod
    def from_dict(cls, config_dict: dict) -> "NomadConfig":
        """Create configuration from a dictionary.
        
        Useful for loading from JSON/YAML files or GUI inputs.
        """
        llm_config = LLMConfig(**config_dict.get("llm", {}))
        ldap_config = LDAPConfig(**config_dict.get("ldap", {}))
        analysis_config = AnalysisConfig(**config_dict.get("analysis", {}))
        output_config = OutputConfig(**config_dict.get("output", {}))
        
        return cls(
            llm=llm_config,
            ldap=ldap_config,
            analysis=analysis_config,
            output=output_config,
            verbose=config_dict.get("verbose", True),
            debug=config_dict.get("debug", False)
        )
    
    def to_dict(self) -> dict:
        """Convert configuration to dictionary for serialization."""
        from dataclasses import asdict
        return asdict(self)


# Default global configuration instance
_default_config: Optional[NomadConfig] = None


def get_config() -> NomadConfig:
    """Get the global configuration instance."""
    global _default_config
    if _default_config is None:
        _default_config = NomadConfig()
    return _default_config


def set_config(config: NomadConfig) -> None:
    """Set the global configuration instance."""
    global _default_config
    _default_config = config

