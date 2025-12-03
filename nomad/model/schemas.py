"""
nomAD Data Schemas
==================

Typed dataclasses representing Active Directory entities and relationships.

Design Decisions:
-----------------
1. All AD objects inherit from ADNode for common attributes (sid, dn, name)
2. NodeType and EdgeType enums provide type safety and easy serialization
3. AttackPath is the primary unit of analysis output
4. AnalysisResult aggregates all findings for the GUI

Schema Hierarchy:
- ADNode (base)
  - User
  - Group
  - Computer
  - Domain
  - OU
  - GPO
  
- ADEdge: Represents relationships between nodes
- AttackPath: A discovered privilege escalation chain
- AnalysisResult: Complete analysis output container
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional, Any
from datetime import datetime
import uuid


class NodeType(Enum):
    """Types of Active Directory objects.
    
    Maps to BloodHound node types for compatibility.
    """
    USER = "User"
    GROUP = "Group"
    COMPUTER = "Computer"
    DOMAIN = "Domain"
    OU = "OU"
    GPO = "GPO"
    CONTAINER = "Container"
    UNKNOWN = "Unknown"


class EdgeType(Enum):
    """Types of relationships/edges in the AD graph.
    
    Comprehensive list covering:
    - Group membership (MemberOf)
    - Session relationships (HasSession)
    - Administrative access (AdminTo, CanRDP, CanPSRemote)
    - ACL-based permissions (GenericAll, GenericWrite, etc.)
    - Special permissions (DCSync, LAPS, GMSA)
    - Delegation (AllowedToDelegate, AllowedToAct)
    - Trust relationships
    
    Each edge type has different exploitation implications.
    """
    # Group membership
    MEMBER_OF = "MemberOf"
    
    # Session-based
    HAS_SESSION = "HasSession"
    
    # Administrative access
    ADMIN_TO = "AdminTo"
    CAN_RDP = "CanRDP"
    CAN_PSREMOTE = "CanPSRemote"
    EXECUTE_DCOM = "ExecuteDCOM"
    SQL_ADMIN = "SQLAdmin"
    
    # ACL-based permissions
    GENERIC_ALL = "GenericAll"
    GENERIC_WRITE = "GenericWrite"
    WRITE_OWNER = "WriteOwner"
    WRITE_DACL = "WriteDacl"
    FORCE_CHANGE_PASSWORD = "ForceChangePassword"
    ADD_MEMBER = "AddMember"
    ALL_EXTENDED_RIGHTS = "AllExtendedRights"
    ADD_KEY_CREDENTIAL_LINK = "AddKeyCredentialLink"
    ADD_SELF = "AddSelf"
    
    # Ownership
    OWNS = "Owns"
    
    # Container/OU relationships
    CONTAINS = "Contains"
    GP_LINK = "GPLink"
    
    # DCSync permissions
    GET_CHANGES = "GetChanges"
    GET_CHANGES_ALL = "GetChangesAll"
    
    # Special credential access
    READ_LAPS_PASSWORD = "ReadLAPSPassword"
    READ_GMSA_PASSWORD = "ReadGMSAPassword"
    
    # Delegation
    ALLOWED_TO_DELEGATE = "AllowedToDelegate"
    ALLOWED_TO_ACT = "AllowedToAct"
    
    # SID History
    HAS_SID_HISTORY = "HasSIDHistory"
    
    # Trust relationships
    TRUSTED_BY = "TrustedBy"
    TRUSTS = "Trusts"
    
    # Other
    SYNC_LAPS_PASSWORD = "SyncLAPSPassword"
    WRITE_ACCOUNT_RESTRICTIONS = "WriteAccountRestrictions"
    UNKNOWN = "Unknown"
    
    @classmethod
    def from_string(cls, s: str) -> "EdgeType":
        """Convert string to EdgeType, handling various formats."""
        # Normalize the string
        normalized = s.strip()
        
        # Direct match attempt
        for edge_type in cls:
            if edge_type.value.lower() == normalized.lower():
                return edge_type
        
        # Common aliases
        aliases = {
            "member": cls.MEMBER_OF,
            "memberof": cls.MEMBER_OF,
            "hassession": cls.HAS_SESSION,
            "session": cls.HAS_SESSION,
            "adminto": cls.ADMIN_TO,
            "localadmin": cls.ADMIN_TO,
            "rdp": cls.CAN_RDP,
            "canrdp": cls.CAN_RDP,
            "psremote": cls.CAN_PSREMOTE,
            "canpsremote": cls.CAN_PSREMOTE,
            "dcom": cls.EXECUTE_DCOM,
            "executedcom": cls.EXECUTE_DCOM,
            "all": cls.GENERIC_ALL,
            "genericall": cls.GENERIC_ALL,
            "write": cls.GENERIC_WRITE,
            "genericwrite": cls.GENERIC_WRITE,
            "owner": cls.WRITE_OWNER,
            "writeowner": cls.WRITE_OWNER,
            "dacl": cls.WRITE_DACL,
            "writedacl": cls.WRITE_DACL,
            "forcechangepassword": cls.FORCE_CHANGE_PASSWORD,
            "resetpassword": cls.FORCE_CHANGE_PASSWORD,
            "addmember": cls.ADD_MEMBER,
            "extendedright": cls.ALL_EXTENDED_RIGHTS,
            "allextendedrights": cls.ALL_EXTENDED_RIGHTS,
            "owns": cls.OWNS,
            "getchanges": cls.GET_CHANGES,
            "getchangesall": cls.GET_CHANGES_ALL,
            "dcsync": cls.GET_CHANGES_ALL,
            "laps": cls.READ_LAPS_PASSWORD,
            "readlapspassword": cls.READ_LAPS_PASSWORD,
            "gmsa": cls.READ_GMSA_PASSWORD,
            "readgmsapassword": cls.READ_GMSA_PASSWORD,
            "delegate": cls.ALLOWED_TO_DELEGATE,
            "allowedtodelegate": cls.ALLOWED_TO_DELEGATE,
            "rbcd": cls.ALLOWED_TO_ACT,
            "allowedtoact": cls.ALLOWED_TO_ACT,
            "sidhistory": cls.HAS_SID_HISTORY,
            "hassidhistory": cls.HAS_SID_HISTORY,
            "trust": cls.TRUSTED_BY,
            "trustedby": cls.TRUSTED_BY,
            "contains": cls.CONTAINS,
            "gplink": cls.GP_LINK,
            "addkeycredentiallink": cls.ADD_KEY_CREDENTIAL_LINK,
            "shadowcredentials": cls.ADD_KEY_CREDENTIAL_LINK,
        }
        
        if normalized.lower() in aliases:
            return aliases[normalized.lower()]
        
        return cls.UNKNOWN


class RiskLevel(Enum):
    """Risk severity levels for attack paths."""
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    INFO = "Info"
    
    @classmethod
    def from_score(cls, score: float) -> "RiskLevel":
        """Convert numeric score (0-100) to risk level."""
        if score >= 80:
            return cls.CRITICAL
        elif score >= 60:
            return cls.HIGH
        elif score >= 40:
            return cls.MEDIUM
        elif score >= 20:
            return cls.LOW
        else:
            return cls.INFO


@dataclass
class ADNode:
    """Base class for all Active Directory objects.
    
    Attributes:
        object_id: Unique identifier (typically SID or GUID)
        name: Human-readable name (sAMAccountName or CN)
        distinguished_name: Full LDAP DN
        domain: Domain the object belongs to
        node_type: Type of AD object
        properties: Additional properties from BloodHound/LDAP
        
    Design Decision:
        Using object_id as the primary key allows consistent identification
        across different data sources (BloodHound uses SID, LDAP uses DN).
    """
    object_id: str
    name: str
    distinguished_name: Optional[str] = None
    domain: Optional[str] = None
    node_type: NodeType = NodeType.UNKNOWN
    properties: dict = field(default_factory=dict)
    
    def __hash__(self):
        return hash(self.object_id)
    
    def __eq__(self, other):
        if isinstance(other, ADNode):
            return self.object_id == other.object_id
        return False
    
    @property
    def display_name(self) -> str:
        """Return a display-friendly name."""
        if self.domain:
            return f"{self.name}@{self.domain}"
        return self.name


@dataclass
class User(ADNode):
    """Active Directory User object.
    
    Additional Attributes:
        enabled: Whether the account is enabled
        admin_count: Whether AdminCount=1 (protected user)
        sensitive: Whether marked as sensitive (cannot be delegated)
        password_never_expires: Whether password is set to never expire
        password_not_required: Whether password is not required
        is_domain_admin: Whether user is member of Domain Admins
        is_enterprise_admin: Whether user is member of Enterprise Admins
        spn_count: Number of SPNs (Kerberoastable if > 0)
        last_logon: Last logon timestamp
    """
    enabled: bool = True
    admin_count: bool = False
    sensitive: bool = False
    password_never_expires: bool = False
    password_not_required: bool = False
    is_domain_admin: bool = False
    is_enterprise_admin: bool = False
    spn_count: int = 0
    last_logon: Optional[datetime] = None
    
    def __post_init__(self):
        self.node_type = NodeType.USER
    
    @property
    def is_kerberoastable(self) -> bool:
        """Check if user has SPNs and can be Kerberoasted."""
        return self.spn_count > 0 and self.enabled
    
    @property
    def is_high_value(self) -> bool:
        """Check if user is a high-value target."""
        return self.is_domain_admin or self.is_enterprise_admin or self.admin_count


@dataclass
class Group(ADNode):
    """Active Directory Group object.
    
    Additional Attributes:
        admin_count: Whether AdminCount=1 (protected group)
        is_high_value: Whether this is a high-value target group
        member_count: Number of direct members
    """
    admin_count: bool = False
    is_high_value: bool = False
    member_count: int = 0
    
    def __post_init__(self):
        self.node_type = NodeType.GROUP


@dataclass
class Computer(ADNode):
    """Active Directory Computer object.
    
    Additional Attributes:
        enabled: Whether the account is enabled
        os: Operating system version
        is_dc: Whether this is a Domain Controller
        is_unconstrained: Whether unconstrained delegation is enabled
        has_laps: Whether LAPS is deployed
        allowed_to_delegate: List of SPNs the computer can delegate to
    """
    enabled: bool = True
    os: Optional[str] = None
    is_dc: bool = False
    is_unconstrained: bool = False
    has_laps: bool = False
    allowed_to_delegate: list = field(default_factory=list)
    
    def __post_init__(self):
        self.node_type = NodeType.COMPUTER
    
    @property
    def is_high_value(self) -> bool:
        """Check if computer is a high-value target."""
        return self.is_dc or self.is_unconstrained


@dataclass
class Domain(ADNode):
    """Active Directory Domain object.
    
    Additional Attributes:
        functional_level: Domain functional level
        trust_relationships: List of trusted domains
    """
    functional_level: Optional[str] = None
    trust_relationships: list = field(default_factory=list)
    
    def __post_init__(self):
        self.node_type = NodeType.DOMAIN


@dataclass
class OU(ADNode):
    """Active Directory Organizational Unit object.
    
    Additional Attributes:
        block_inheritance: Whether GPO inheritance is blocked
        linked_gpos: List of linked GPO DNs
    """
    block_inheritance: bool = False
    linked_gpos: list = field(default_factory=list)
    
    def __post_init__(self):
        self.node_type = NodeType.OU


@dataclass
class GPO(ADNode):
    """Active Directory Group Policy Object.
    
    Additional Attributes:
        gpc_path: Path to the GPT in SYSVOL
        enabled: Whether the GPO is enabled
    """
    gpc_path: Optional[str] = None
    enabled: bool = True
    
    def __post_init__(self):
        self.node_type = NodeType.GPO


@dataclass
class ADEdge:
    """Represents a relationship between two AD objects.
    
    Attributes:
        source_id: Object ID of the source node
        target_id: Object ID of the target node
        edge_type: Type of relationship
        properties: Additional edge properties (e.g., inheritance info)
        
    Design Decision:
        Edges are directional. For example, MemberOf goes from User -> Group.
        The direction represents the "flow" of privilege or relationship.
    """
    source_id: str
    target_id: str
    edge_type: EdgeType
    properties: dict = field(default_factory=dict)
    
    def __hash__(self):
        return hash((self.source_id, self.target_id, self.edge_type))
    
    def __eq__(self, other):
        if isinstance(other, ADEdge):
            return (self.source_id == other.source_id and 
                    self.target_id == other.target_id and 
                    self.edge_type == other.edge_type)
        return False
    
    @property
    def description(self) -> str:
        """Human-readable description of the edge."""
        return f"{self.source_id} --[{self.edge_type.value}]--> {self.target_id}"


@dataclass
class AttackPath:
    """Represents a discovered attack path (privilege escalation chain).
    
    This is the primary unit of analysis output. Each path represents a
    sequence of steps an attacker could take from a starting point to
    reach a high-value target.
    
    Attributes:
        id: Unique path identifier
        nodes: Ordered list of node IDs along the path
        edges: Ordered list of edge objects connecting the nodes
        estimated_steps: Number of discrete attack steps
        privilege_gain: Description of what privilege is gained
        risk_score: Numeric risk score (0-100)
        risk_level: Categorical risk level
        raw_explanation: Auto-generated text explanation
        ai_risk_commentary: AI-generated risk commentary (if enabled)
        ai_explanation: AI-generated detailed explanation (if enabled)
        ai_mitigations: AI-suggested mitigations (if enabled)
        properties: Additional metadata
    """
    id: str
    nodes: list  # List of node IDs (strings)
    edges: list  # List of ADEdge objects
    estimated_steps: int
    privilege_gain: str
    risk_score: float = 0.0
    risk_level: RiskLevel = RiskLevel.LOW
    raw_explanation: str = ""
    ai_risk_commentary: Optional[str] = None
    ai_explanation: Optional[str] = None
    ai_mitigations: list = field(default_factory=list)
    properties: dict = field(default_factory=dict)
    
    def __post_init__(self):
        if not self.id:
            self.id = str(uuid.uuid4())[:8]
        if not self.risk_level or self.risk_level == RiskLevel.LOW:
            self.risk_level = RiskLevel.from_score(self.risk_score)
    
    def to_dict(self) -> dict:
        """Convert to dictionary for JSON serialization."""
        return {
            "id": self.id,
            "nodes": self.nodes,
            "edges": [{"source": e.source_id, "target": e.target_id, 
                      "type": e.edge_type.value} for e in self.edges],
            "estimated_steps": self.estimated_steps,
            "privilege_gain": self.privilege_gain,
            "risk_score": self.risk_score,
            "risk_level": self.risk_level.value,
            "raw_explanation": self.raw_explanation,
            "ai_risk_commentary": self.ai_risk_commentary,
            "ai_explanation": self.ai_explanation,
            "ai_mitigations": self.ai_mitigations,
            "properties": self.properties
        }


@dataclass
class EnvironmentStats:
    """Statistics about the AD environment.
    
    Used by the AI reasoning layer to understand the environment context.
    """
    total_users: int = 0
    total_groups: int = 0
    total_computers: int = 0
    total_domains: int = 0
    domain_admin_count: int = 0
    enterprise_admin_count: int = 0
    dc_count: int = 0
    kerberoastable_users: int = 0
    unconstrained_delegation_count: int = 0
    enabled_users: int = 0
    disabled_users: int = 0
    
    def to_dict(self) -> dict:
        """Convert to dictionary for serialization."""
        return {
            "total_users": self.total_users,
            "total_groups": self.total_groups,
            "total_computers": self.total_computers,
            "total_domains": self.total_domains,
            "domain_admin_count": self.domain_admin_count,
            "enterprise_admin_count": self.enterprise_admin_count,
            "dc_count": self.dc_count,
            "kerberoastable_users": self.kerberoastable_users,
            "unconstrained_delegation_count": self.unconstrained_delegation_count,
            "enabled_users": self.enabled_users,
            "disabled_users": self.disabled_users
        }


@dataclass
class AnalysisResult:
    """Complete analysis result container for GUI consumption.
    
    This is the main output object returned by the analysis pipeline.
    Contains all information needed for display and reporting.
    
    Attributes:
        attack_paths: List of discovered attack paths
        environment_stats: Statistics about the AD environment
        visualization_paths: Dict mapping path IDs to visualization file paths
        report_path: Path to generated JSON report
        html_report_path: Path to generated HTML report
        total_paths: Total number of paths found
        critical_paths: Count of critical risk paths
        high_paths: Count of high risk paths
        medium_paths: Count of medium risk paths
        low_paths: Count of low risk paths
        ai_overall_findings: AI-generated overall findings (if enabled)
        ai_mitigations_summary: AI-generated mitigations summary (if enabled)
        metadata: Additional metadata (timestamp, input files, etc.)
    """
    attack_paths: list = field(default_factory=list)  # List of AttackPath
    environment_stats: Optional[EnvironmentStats] = None
    visualization_paths: dict = field(default_factory=dict)  # path_id -> file_path
    report_path: Optional[str] = None
    html_report_path: Optional[str] = None
    total_paths: int = 0
    critical_paths: int = 0
    high_paths: int = 0
    medium_paths: int = 0
    low_paths: int = 0
    ai_overall_findings: Optional[str] = None
    ai_mitigations_summary: list = field(default_factory=list)
    metadata: dict = field(default_factory=dict)
    
    def __post_init__(self):
        """Calculate path counts from attack_paths list."""
        if self.attack_paths and self.total_paths == 0:
            self.total_paths = len(self.attack_paths)
            self.critical_paths = sum(1 for p in self.attack_paths if p.risk_level == RiskLevel.CRITICAL)
            self.high_paths = sum(1 for p in self.attack_paths if p.risk_level == RiskLevel.HIGH)
            self.medium_paths = sum(1 for p in self.attack_paths if p.risk_level == RiskLevel.MEDIUM)
            self.low_paths = sum(1 for p in self.attack_paths if p.risk_level == RiskLevel.LOW)
    
    def to_dict(self) -> dict:
        """Convert to dictionary for JSON serialization."""
        return {
            "attack_paths": [p.to_dict() for p in self.attack_paths],
            "environment_stats": self.environment_stats.to_dict() if self.environment_stats else None,
            "visualization_paths": self.visualization_paths,
            "report_path": self.report_path,
            "html_report_path": self.html_report_path,
            "total_paths": self.total_paths,
            "critical_paths": self.critical_paths,
            "high_paths": self.high_paths,
            "medium_paths": self.medium_paths,
            "low_paths": self.low_paths,
            "ai_overall_findings": self.ai_overall_findings,
            "ai_mitigations_summary": self.ai_mitigations_summary,
            "metadata": self.metadata
        }

