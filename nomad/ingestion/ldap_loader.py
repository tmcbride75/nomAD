"""
LDAP Collector Module
=====================

Live collection of Active Directory data via LDAP.

Features:
- Collects users, groups, computers, OUs, GPOs
- Enumerates ACLs for attack path analysis
- Supports LDAP (389) and LDAPS (636)
- Handles large environments with paging

Design Decisions:
-----------------
1. Uses ldap3 library for cross-platform LDAP support
2. ACL enumeration parses ntSecurityDescriptor for permissions
3. Supports both anonymous and authenticated binds
4. Includes BloodHound-compatible JSON export

Security Consideration:
This module performs read-only operations. No modifications are made to the AD.
"""

import struct
from datetime import datetime
from typing import Optional, Callable
import json
import os

# LDAP library
try:
    from ldap3 import (
        Server, Connection, ALL, SUBTREE, BASE,
        NTLM, SIMPLE, SASL, KERBEROS,
        ALL_ATTRIBUTES, ALL_OPERATIONAL_ATTRIBUTES
    )
    from ldap3.core.exceptions import LDAPException
    from ldap3.protocol.microsoft import security_descriptor_control
    LDAP3_AVAILABLE = True
except ImportError:
    LDAP3_AVAILABLE = False
    security_descriptor_control = None

from ..model.schemas import (
    User, Group, Computer, Domain, OU, GPO,
    ADNode, ADEdge, NodeType, EdgeType
)
from ..model.graph_builder import ADGraph
from ..config import LDAPConfig


# Well-known SIDs
WELL_KNOWN_SIDS = {
    'S-1-0-0': 'Null Authority',
    'S-1-1-0': 'Everyone',
    'S-1-2-0': 'Local',
    'S-1-2-1': 'Console Logon',
    'S-1-3-0': 'Creator Owner',
    'S-1-3-1': 'Creator Group',
    'S-1-5-1': 'Dialup',
    'S-1-5-2': 'Network',
    'S-1-5-3': 'Batch',
    'S-1-5-4': 'Interactive',
    'S-1-5-6': 'Service',
    'S-1-5-7': 'Anonymous',
    'S-1-5-9': 'Enterprise Domain Controllers',
    'S-1-5-10': 'Principal Self',
    'S-1-5-11': 'Authenticated Users',
    'S-1-5-18': 'Local System',
    'S-1-5-19': 'NT Authority Local Service',
    'S-1-5-20': 'NT Authority Network Service',
    'S-1-5-32-544': 'Administrators',
    'S-1-5-32-545': 'Users',
    'S-1-5-32-546': 'Guests',
    'S-1-5-32-548': 'Account Operators',
    'S-1-5-32-549': 'Server Operators',
    'S-1-5-32-550': 'Print Operators',
    'S-1-5-32-551': 'Backup Operators',
    'S-1-5-32-552': 'Replicators',
    'S-1-5-32-554': 'Builtin\\Pre-Windows 2000 Compatible Access',
    'S-1-5-32-555': 'Builtin\\Remote Desktop Users',
    'S-1-5-32-556': 'Builtin\\Network Configuration Operators',
    'S-1-5-32-557': 'Builtin\\Incoming Forest Trust Builders',
    'S-1-5-32-558': 'Builtin\\Performance Monitor Users',
    'S-1-5-32-559': 'Builtin\\Performance Log Users',
    'S-1-5-32-560': 'Builtin\\Windows Authorization Access Group',
    'S-1-5-32-561': 'Builtin\\Terminal Server License Servers',
    'S-1-5-32-562': 'Builtin\\Distributed COM Users',
    'S-1-5-32-568': 'Builtin\\IIS_IUSRS',
    'S-1-5-32-569': 'Builtin\\Cryptographic Operators',
    'S-1-5-32-573': 'Builtin\\Event Log Readers',
    'S-1-5-32-574': 'Builtin\\Certificate Service DCOM Access',
    'S-1-5-32-575': 'Builtin\\RDS Remote Access Servers',
    'S-1-5-32-576': 'Builtin\\RDS Endpoint Servers',
    'S-1-5-32-577': 'Builtin\\RDS Management Servers',
    'S-1-5-32-578': 'Builtin\\Hyper-V Administrators',
    'S-1-5-32-579': 'Builtin\\Access Control Assistance Operators',
    'S-1-5-32-580': 'Builtin\\Remote Management Users',
}

# Domain-relative RIDs for well-known groups
DOMAIN_RIDS = {
    500: 'Administrator',
    501: 'Guest',
    502: 'krbtgt',
    512: 'Domain Admins',
    513: 'Domain Users',
    514: 'Domain Guests',
    515: 'Domain Computers',
    516: 'Domain Controllers',
    517: 'Cert Publishers',
    518: 'Schema Admins',
    519: 'Enterprise Admins',
    520: 'Group Policy Creator Owners',
    521: 'Read-only Domain Controllers',
    522: 'Cloneable Domain Controllers',
    525: 'Protected Users',
    526: 'Key Admins',
    527: 'Enterprise Key Admins',
    553: 'RAS and IAS Servers',
    571: 'Allowed RODC Password Replication Group',
    572: 'Denied RODC Password Replication Group',
}

# Extended rights GUIDs
EXTENDED_RIGHTS = {
    '00299570-246d-11d0-a768-00aa006e0529': 'User-Force-Change-Password',
    '1131f6aa-9c07-11d1-f79f-00c04fc2dcd2': 'DS-Replication-Get-Changes',
    '1131f6ad-9c07-11d1-f79f-00c04fc2dcd2': 'DS-Replication-Get-Changes-All',
    '89e95b76-444d-4c62-991a-0facbeda640c': 'DS-Replication-Get-Changes-In-Filtered-Set',
    '00000000-0000-0000-0000-000000000000': 'All-Extended-Rights',
    '5b47d60f-6090-40b2-9f37-2a4de88f3063': 'ms-DS-Key-Credential-Link',
}

# Property set GUIDs for ACL parsing
PROPERTY_SETS = {
    '4c164200-20c0-11d0-a768-00aa006e0529': 'User-Account-Restrictions',
    '5f202010-79a5-11d0-9020-00c04fc2d4cf': 'User-Logon',
    'bc0ac240-79a9-11d0-9020-00c04fc2d4cf': 'Membership',
}


class LDAPCollector:
    """Collector for Active Directory data via LDAP.
    
    Usage:
        collector = LDAPCollector(
            server_ip="192.168.1.100",
            domain="corp.local",
            username="user",
            password="password"
        )
        graph = collector.collect()
    
    The collector performs read-only queries and enumerates:
    - User accounts
    - Groups and memberships
    - Computer accounts
    - OUs and GPOs
    - ACLs/DACLs for permission analysis
    """
    
    def __init__(
        self,
        server_ip: str,
        domain: str,
        username: Optional[str] = None,
        password: Optional[str] = None,
        ntlm_hash: Optional[str] = None,
        config: Optional[LDAPConfig] = None,
        verbose: bool = True,
        progress_callback: Optional[Callable[[str], None]] = None
    ):
        """Initialize the LDAP collector.
        
        Args:
            server_ip: IP address or hostname of the domain controller
            domain: Domain name (e.g., "corp.local")
            username: Username for authentication (domain\\user or user@domain)
            password: Password for authentication
            ntlm_hash: NTLM hash for Pass-the-Hash (format: LM:NT or just NT)
            config: LDAPConfig object for connection settings
            verbose: Whether to print progress messages
            progress_callback: Optional callback for progress updates
        """
        if not LDAP3_AVAILABLE:
            raise ImportError("ldap3 library is required. Install with: pip install ldap3")
        
        self.server_ip = server_ip
        self.domain = domain
        self.username = username
        self.password = password
        self.ntlm_hash = ntlm_hash
        self.config = config or LDAPConfig()
        self.verbose = verbose
        self.progress_callback = progress_callback
        
        # Connection state
        self.connection: Optional[Connection] = None
        self.base_dn: str = ""
        self.domain_sid: str = ""
        
        # Graph to populate
        self.graph = ADGraph()
        
        # Cache for SID lookups
        self._sid_cache: dict[str, str] = {}      # SID -> name
        self._dn_to_sid_cache: dict[str, str] = {} # DN -> SID
        
        # Derive base DN from domain
        self.base_dn = ",".join([f"DC={part}" for part in domain.split(".")])
    
    def _log(self, message: str) -> None:
        """Log a message to console and/or callback."""
        if self.verbose:
            print(message)
        if self.progress_callback:
            self.progress_callback(message)
    
    def connect(self) -> bool:
        """Establish connection to the LDAP server.
        
        Returns:
            True if connection successful, False otherwise
        """
        try:
            # Create server object
            port = self.config.port or (636 if self.config.use_ssl else 389)
            server = Server(
                self.server_ip,
                port=port,
                use_ssl=self.config.use_ssl,
                get_info=ALL,
                connect_timeout=self.config.timeout
            )
            
            # Determine authentication method
            if self.username and (self.password or self.ntlm_hash):
                # Format username for NTLM
                if '\\' not in self.username and '@' not in self.username:
                    # Add domain prefix for NTLM
                    ntlm_user = f"{self.domain.split('.')[0].upper()}\\{self.username}"
                else:
                    ntlm_user = self.username
                
                # Determine credential to use (hash or password)
                if self.ntlm_hash:
                    # Pass-the-Hash: use the hash as password for NTLM auth
                    # Format should be LM:NT or just NT hash
                    auth_credential = self.ntlm_hash
                    auth_type_str = "Pass-the-Hash"
                else:
                    auth_credential = self.password
                    auth_type_str = "Password"
                
                self._log(f"[*] Connecting to {self.server_ip}:{port} as {ntlm_user} ({auth_type_str})")
                
                # Try NTLM first
                try:
                    self.connection = Connection(
                        server,
                        user=ntlm_user,
                        password=auth_credential,
                        authentication=NTLM,
                        auto_bind=True,
                        receive_timeout=self.config.timeout
                    )
                except Exception as ntlm_error:
                    if not self.ntlm_hash:
                        self._log(f"[*] NTLM auth failed, trying simple bind...")
                        # Fallback to simple bind (only for password auth)
                        self.connection = Connection(
                            server,
                            user=self.username if '@' in self.username else f"{self.username}@{self.domain}",
                            password=self.password,
                            authentication=SIMPLE,
                            auto_bind=True,
                            receive_timeout=self.config.timeout
                        )
                    else:
                        raise ntlm_error
            else:
                # Anonymous bind
                self._log(f"[*] Connecting anonymously to {self.server_ip}:{port}")
                self.connection = Connection(
                    server,
                    auto_bind=True,
                    receive_timeout=self.config.timeout
                )
            
            self._log(f"[+] Connected successfully to {self.server_ip}")
            
            # Get domain SID
            self._get_domain_sid()
            
            return True
            
        except Exception as e:
            self._log(f"[!] Connection failed: {e}")
            return False
    
    def _get_domain_sid(self) -> None:
        """Retrieve the domain SID."""
        try:
            self.connection.search(
                search_base=self.base_dn,
                search_filter="(objectClass=domain)",
                search_scope=BASE,
                attributes=['objectSid']
            )
            
            if self.connection.entries:
                sid_bytes = self.connection.entries[0].objectSid.raw_values[0]
                self.domain_sid = self._convert_sid(sid_bytes)
                self._log(f"[+] Domain SID: {self.domain_sid}")
        except Exception as e:
            self._log(f"[!] Could not retrieve domain SID: {e}")
    
    def _convert_sid(self, sid_bytes: bytes) -> str:
        """Convert binary SID to string format.
        
        Args:
            sid_bytes: Binary SID data
            
        Returns:
            String SID (e.g., "S-1-5-21-...")
        """
        if not sid_bytes:
            return ""
        
        try:
            # SID structure:
            # Byte 0: Revision
            # Byte 1: Number of sub-authorities
            # Bytes 2-7: Identifier authority (big-endian)
            # Remaining: Sub-authorities (little-endian 32-bit)
            
            revision = sid_bytes[0]
            sub_auth_count = sid_bytes[1]
            
            # Identifier authority (6 bytes, big-endian)
            id_auth = int.from_bytes(sid_bytes[2:8], 'big')
            
            # Sub-authorities (4 bytes each, little-endian)
            sub_auths = []
            for i in range(sub_auth_count):
                offset = 8 + (i * 4)
                sub_auth = struct.unpack('<I', sid_bytes[offset:offset + 4])[0]
                sub_auths.append(sub_auth)
            
            # Build SID string
            sid = f"S-{revision}-{id_auth}"
            for sub_auth in sub_auths:
                sid += f"-{sub_auth}"
            
            return sid
            
        except Exception as e:
            return ""
    
    def collect(self) -> ADGraph:
        """Perform full AD collection.
        
        Returns:
            ADGraph populated with collected data
        """
        self.graph = ADGraph()
        
        if not self.connection:
            if not self.connect():
                raise ConnectionError("Failed to connect to LDAP server")
        
        self._log("[*] Starting AD enumeration...")
        
        # Collect in order of dependency
        # IMPORTANT: Groups must be collected BEFORE users so that 
        # group SIDs are in cache when processing user memberships
        self._collect_domain()
        self._collect_groups()  # Groups first - populates SID cache
        self._collect_users()   # Users second - can resolve group SIDs
        self._collect_computers()
        self._collect_ous()
        self._collect_gpos()
        
        # Enumerate ACLs (most important for attack paths)
        self._collect_acls()
        
        # Post-process: ensure group memberships are properly linked
        self._process_group_memberships()
        
        self._log(f"[+] Collection complete: {self.graph.node_count} nodes, {self.graph.edge_count} edges")
        
        return self.graph
    
    def _add_implicit_memberships(self) -> None:
        """Add implicit group memberships for all users.
        
        In Active Directory, all authenticated users are implicitly members of:
        - Authenticated Users (S-1-5-11)
        - Everyone (S-1-1-0) - but we skip this as it's too broad
        - Domain Users (domain-specific RID 513)
        
        This is critical for attack path discovery because ACLs granted to
        these groups apply to all users.
        """
        self._log("[*] Adding implicit group memberships...")
        
        # Well-known SIDs for implicit membership
        authenticated_users = 'S-1-5-11'
        domain_users = f'{self.domain_sid}-513' if self.domain_sid else None
        
        edge_count = 0
        
        # Get all users
        for user in self.graph.get_nodes_by_type(NodeType.USER):
            user_id = user.object_id
            
            # Add edge: User -> Authenticated Users
            if authenticated_users:
                edge = ADEdge(
                    source_id=user_id,
                    target_id=authenticated_users,
                    edge_type=EdgeType.MEMBER_OF,
                    properties={'implicit': True}
                )
                self.graph.add_edge(edge)
                edge_count += 1
            
            # Add edge: User -> Domain Users
            if domain_users:
                edge = ADEdge(
                    source_id=user_id,
                    target_id=domain_users,
                    edge_type=EdgeType.MEMBER_OF,
                    properties={'implicit': True}
                )
                self.graph.add_edge(edge)
                edge_count += 1
        
        self._log(f"[+] Added {edge_count} implicit membership edges")
    
    def _process_group_memberships(self) -> None:
        """Post-process to ensure group memberships are linked correctly.
        
        This iterates through groups and ensures all member relationships
        are properly added to the graph.
        """
        self._log("[*] Processing group memberships...")
        
        edge_count = 0
        
        # First, build a set of all group SIDs for validation
        group_sids = set()
        try:
            self.connection.search(
                search_base=self.base_dn,
                search_filter="(objectClass=group)",
                search_scope=SUBTREE,
                attributes=['objectSid'],
                paged_size=self.config.page_size
            )
            
            for entry in self.connection.entries:
                attrs = entry.entry_attributes_as_dict
                sid_list = attrs.get('objectSid', [])
                if sid_list:
                    sid_bytes = sid_list[0]
                    if isinstance(sid_bytes, bytes):
                        group_sid = self._convert_sid(sid_bytes)
                        if group_sid:
                            group_sids.add(group_sid)
            
            # Also add well-known group SIDs
            group_sids.add('S-1-5-32-544')  # Administrators
            group_sids.add('S-1-5-32-545')  # Users
            group_sids.add('S-1-5-32-546')  # Guests
            
            self._log(f"[*] Found {len(group_sids)} groups for membership validation")
            
        except Exception as e:
            self._log(f"[!] Error building group list: {e}")
        
        try:
            # Query all groups again for member attribute
            self.connection.search(
                search_base=self.base_dn,
                search_filter="(objectClass=group)",
                search_scope=SUBTREE,
                attributes=['objectSid', 'sAMAccountName', 'member', 'memberOf'],
                paged_size=self.config.page_size
            )
            
            for entry in self.connection.entries:
                try:
                    attrs = entry.entry_attributes_as_dict
                    
                    # Get group SID
                    sid_list = attrs.get('objectSid', [])
                    if sid_list:
                        sid_bytes = sid_list[0]
                        if isinstance(sid_bytes, bytes):
                            group_id = self._convert_sid(sid_bytes)
                        else:
                            group_id = str(entry.entry_dn)
                    else:
                        group_id = str(entry.entry_dn)
                    
                    # Process members - these are objects IN this group
                    members = attrs.get('member', [])
                    for member_dn in members:
                        member_id = self._dn_to_sid(str(member_dn))
                        if member_id and member_id != group_id:
                            # Only create edge if target is actually a group
                            if group_id in group_sids or 'S-1-5-32-' in group_id:
                                edge = ADEdge(
                                    source_id=member_id,
                                    target_id=group_id,
                                    edge_type=EdgeType.MEMBER_OF
                                )
                                self.graph.add_edge(edge)
                                edge_count += 1
                    
                    # Process memberOf (group nesting) - this group is IN another group
                    parent_groups = attrs.get('memberOf', [])
                    for parent_dn in parent_groups:
                        parent_id = self._dn_to_sid(str(parent_dn))
                        if parent_id and parent_id != group_id:
                            # Only create edge if target is actually a group
                            if parent_id in group_sids or 'S-1-5-32-' in parent_id:
                                edge = ADEdge(
                                    source_id=group_id,
                                    target_id=parent_id,
                                    edge_type=EdgeType.MEMBER_OF
                                )
                                self.graph.add_edge(edge)
                                edge_count += 1
                            
                except Exception as e:
                    pass
            
            self._log(f"[+] Added {edge_count} membership edges")
            
        except Exception as e:
            self._log(f"[!] Error processing memberships: {e}")
    
    def _collect_domain(self) -> None:
        """Collect domain object."""
        self._log("[*] Collecting domain information...")
        
        try:
            self.connection.search(
                search_base=self.base_dn,
                search_filter="(objectClass=domain)",
                search_scope=BASE,
                attributes=['*']
            )
            
            for entry in self.connection.entries:
                attrs = entry.entry_attributes_as_dict
                
                # Safely get functional level
                fl_list = attrs.get('msDS-Behavior-Version', [])
                functional_level = fl_list[0] if fl_list else None
                
                # Safely get dc and whenCreated
                dc_list = attrs.get('dc', [])
                when_created_list = attrs.get('whenCreated', [])
                
                domain = Domain(
                    object_id=self.domain_sid or self.base_dn,
                    name=self.domain,
                    domain=self.domain,
                    distinguished_name=str(entry.entry_dn),
                    functional_level=str(functional_level) if functional_level else None,
                    properties={
                        'dc': list(dc_list),
                        'whenCreated': str(when_created_list[0]) if when_created_list else '',
                    }
                )
                self.graph.add_node(domain)
                
        except Exception as e:
            self._log(f"[!] Error collecting domain: {e}")
    
    def _collect_users(self) -> None:
        """Collect user objects."""
        self._log("[*] Collecting users...")
        
        count = 0
        
        # Try multiple LDAP filters as different environments may require different queries
        ldap_filters = [
            "(&(objectClass=user)(objectCategory=person))",
            "(objectClass=user)",
            "(&(objectClass=user)(!(objectClass=computer)))",
            "(sAMAccountType=805306368)",  # User account type
        ]
        
        user_attributes = [
            'objectSid', 'sAMAccountName', 'distinguishedName', 'cn', 'name',
            'userAccountControl', 'adminCount', 'memberOf',
            'servicePrincipalName', 'pwdLastSet', 'lastLogon',
            'description', 'displayName', 'mail', 'userPrincipalName',
            'msDS-AllowedToDelegateTo'
        ]
        
        entries_found = []
        
        for ldap_filter in ldap_filters:
            try:
                self.connection.search(
                    search_base=self.base_dn,
                    search_filter=ldap_filter,
                    search_scope=SUBTREE,
                    attributes=user_attributes,
                    paged_size=self.config.page_size
                )
                
                if self.connection.entries:
                    entries_found = list(self.connection.entries)
                    self._log(f"[*] Found {len(entries_found)} entries with filter: {ldap_filter}")
                    break
            except Exception as e:
                self._log(f"[*] Filter '{ldap_filter}' failed: {e}")
                continue
        
        if not entries_found:
            self._log("[!] No user entries found with any filter")
            return
        
        try:
            for entry in entries_found:
                try:
                    attrs = entry.entry_attributes_as_dict
                    
                    # Get SID - safely handle empty lists
                    sid_list = attrs.get('objectSid', [])
                    if sid_list:
                        sid_bytes = sid_list[0]
                        if isinstance(sid_bytes, bytes):
                            object_id = self._convert_sid(sid_bytes)
                        else:
                            object_id = str(sid_bytes) if sid_bytes else str(entry.entry_dn)
                    else:
                        object_id = str(entry.entry_dn)
                    
                    # Safely get name
                    name_list = attrs.get('sAMAccountName', [])
                    name = name_list[0] if name_list else ""
                    
                    if not name:
                        # Skip entries without a name
                        continue
                    
                    # Parse userAccountControl - safely
                    uac_list = attrs.get('userAccountControl', [])
                    uac = int(uac_list[0]) if uac_list and uac_list[0] else 0
                    enabled = not (uac & 0x02)  # ACCOUNTDISABLE flag
                    pwd_never_expires = bool(uac & 0x10000)  # DONT_EXPIRE_PASSWD
                    pwd_not_required = bool(uac & 0x20)  # PASSWD_NOTREQD
                    sensitive = bool(uac & 0x100000)  # NOT_DELEGATED
                    
                    # SPNs
                    spns = attrs.get('servicePrincipalName', [])
                    
                    # Check for DA/EA membership
                    member_of = attrs.get('memberOf', [])
                    is_da = any('Domain Admins' in str(g) for g in member_of)
                    is_ea = any('Enterprise Admins' in str(g) for g in member_of)
                    
                    # Safely get adminCount
                    admin_count_list = attrs.get('adminCount', [])
                    admin_count = bool(admin_count_list[0]) if admin_count_list and admin_count_list[0] else False
                    
                    # Safely get description, displayName, mail
                    desc_list = attrs.get('description', [])
                    display_list = attrs.get('displayName', [])
                    mail_list = attrs.get('mail', [])
                    
                    user = User(
                        object_id=object_id,
                        name=name,
                        domain=self.domain,
                        distinguished_name=str(entry.entry_dn),
                        enabled=enabled,
                        admin_count=admin_count,
                        sensitive=sensitive,
                        password_never_expires=pwd_never_expires,
                        password_not_required=pwd_not_required,
                        is_domain_admin=is_da,
                        is_enterprise_admin=is_ea,
                        spn_count=len(spns) if spns else 0,
                        properties={
                            'description': desc_list[0] if desc_list else '',
                            'displayName': display_list[0] if display_list else '',
                            'mail': mail_list[0] if mail_list else '',
                            'serviceprincipalnames': list(spns),
                        }
                    )
                    
                    self.graph.add_node(user)
                    self._sid_cache[object_id] = name
                    # Cache DN -> SID mapping
                    self._dn_to_sid_cache[str(entry.entry_dn).lower()] = object_id
                    
                    # Process group memberships
                    for group_dn in member_of:
                        group_id = self._dn_to_sid(str(group_dn))
                        if group_id:
                            edge = ADEdge(
                                source_id=object_id,
                                target_id=group_id,
                                edge_type=EdgeType.MEMBER_OF
                            )
                            self.graph.add_edge(edge)
                    
                    count += 1
                    
                except Exception as e:
                    if self.verbose:
                        self._log(f"[!] Error processing user entry: {e}")
            
            self._log(f"[+] Collected {count} users")
            
        except Exception as e:
            self._log(f"[!] Error collecting users: {e}")
    
    def _collect_groups(self) -> None:
        """Collect group objects."""
        self._log("[*] Collecting groups...")
        
        count = 0
        try:
            self.connection.search(
                search_base=self.base_dn,
                search_filter="(objectClass=group)",
                search_scope=SUBTREE,
                attributes=[
                    'objectSid', 'sAMAccountName', 'distinguishedName',
                    'adminCount', 'member', 'description', 'memberOf',
                    'nTSecurityDescriptor'
                ],
                paged_size=self.config.page_size
            )
            
            for entry in self.connection.entries:
                try:
                    attrs = entry.entry_attributes_as_dict
                    
                    # Get SID - safely handle empty lists
                    sid_list = attrs.get('objectSid', [])
                    if sid_list:
                        sid_bytes = sid_list[0]
                        if isinstance(sid_bytes, bytes):
                            object_id = self._convert_sid(sid_bytes)
                        else:
                            object_id = str(sid_bytes) if sid_bytes else str(entry.entry_dn)
                    else:
                        object_id = str(entry.entry_dn)
                    
                    # Safely get name
                    name_list = attrs.get('sAMAccountName', [])
                    name = name_list[0] if name_list else ""
                    
                    if not name:
                        # Try to extract name from DN
                        dn = str(entry.entry_dn)
                        if 'CN=' in dn:
                            name = dn.split('CN=')[1].split(',')[0]
                        else:
                            continue  # Skip entries without a name
                    
                    # Check if high-value target
                    hvt_names = [
                        "domain admins", "enterprise admins", "administrators",
                        "schema admins", "account operators", "backup operators",
                        "server operators", "print operators", "dnsadmins",
                        "group policy creator owners"
                    ]
                    is_high_value = any(hvt in name.lower() for hvt in hvt_names)
                    
                    members = attrs.get('member', [])
                    
                    # Safely get adminCount and description
                    admin_count_list = attrs.get('adminCount', [])
                    admin_count = bool(admin_count_list[0]) if admin_count_list and admin_count_list[0] else False
                    
                    desc_list = attrs.get('description', [])
                    
                    group = Group(
                        object_id=object_id,
                        name=name,
                        domain=self.domain,
                        distinguished_name=str(entry.entry_dn),
                        admin_count=admin_count,
                        is_high_value=is_high_value,
                        member_count=len(members) if members else 0,
                        properties={
                            'description': desc_list[0] if desc_list else '',
                        }
                    )
                    
                    self.graph.add_node(group)
                    self._sid_cache[object_id] = name
                    # Also cache DN -> SID mapping for membership resolution
                    self._dn_to_sid_cache[str(entry.entry_dn).lower()] = object_id
                    
                    # Process members
                    for member_dn in members:
                        member_id = self._dn_to_sid(str(member_dn))
                        if member_id:
                            edge = ADEdge(
                                source_id=member_id,
                                target_id=object_id,
                                edge_type=EdgeType.MEMBER_OF
                            )
                            self.graph.add_edge(edge)
                    
                    count += 1
                    
                except Exception as e:
                    if self.verbose:
                        self._log(f"[!] Error processing group entry: {e}")
            
            self._log(f"[+] Collected {count} groups")
            
        except Exception as e:
            self._log(f"[!] Error collecting groups: {e}")
    
    def _collect_computers(self) -> None:
        """Collect computer objects."""
        self._log("[*] Collecting computers...")
        
        count = 0
        try:
            # Note: ms-Mcs-AdmPwd (LAPS) may not be available, so we query basic attributes first
            self.connection.search(
                search_base=self.base_dn,
                search_filter="(objectClass=computer)",
                search_scope=SUBTREE,
                attributes=[
                    'objectSid', 'sAMAccountName', 'distinguishedName',
                    'userAccountControl', 'operatingSystem', 'operatingSystemVersion',
                    'dNSHostName', 'servicePrincipalName', 'memberOf',
                    'msDS-AllowedToDelegateTo', 'nTSecurityDescriptor', 'primaryGroupID'
                ],
                paged_size=self.config.page_size
            )
            
            for entry in self.connection.entries:
                try:
                    attrs = entry.entry_attributes_as_dict
                    
                    # Get SID - safely handle empty lists
                    sid_list = attrs.get('objectSid', [])
                    if sid_list:
                        sid_bytes = sid_list[0]
                        if isinstance(sid_bytes, bytes):
                            object_id = self._convert_sid(sid_bytes)
                        else:
                            object_id = str(sid_bytes) if sid_bytes else str(entry.entry_dn)
                    else:
                        object_id = str(entry.entry_dn)
                    
                    # Safely get name
                    name_list = attrs.get('sAMAccountName', [])
                    name = name_list[0] if name_list else ""
                    
                    if not name:
                        # Try to extract from DN
                        dn = str(entry.entry_dn)
                        if 'CN=' in dn:
                            name = dn.split('CN=')[1].split(',')[0]
                        else:
                            continue
                    
                    if name.endswith('$'):
                        name = name[:-1]  # Remove trailing $
                    
                    # Parse UAC - safely
                    uac_list = attrs.get('userAccountControl', [])
                    uac = int(uac_list[0]) if uac_list and uac_list[0] else 0
                    enabled = not (uac & 0x02)
                    is_unconstrained = bool(uac & 0x80000)  # TRUSTED_FOR_DELEGATION
                    
                    # Check if DC (primary group 516) - safely
                    pg_list = attrs.get('primaryGroupID', [])
                    primary_group_id = int(pg_list[0]) if pg_list and pg_list[0] else 0
                    member_of = attrs.get('memberOf', [])
                    is_dc = (primary_group_id == 516) or any(
                        'Domain Controllers' in str(g) for g in member_of
                    )
                    
                    # LAPS - we don't query ms-Mcs-AdmPwd directly as it may not exist
                    has_laps = False
                    
                    # Delegation targets
                    allowed_to_delegate = attrs.get('msDS-AllowedToDelegateTo', [])
                    
                    # Safely get OS info
                    os_list = attrs.get('operatingSystem', [])
                    os_ver_list = attrs.get('operatingSystemVersion', [])
                    dns_list = attrs.get('dNSHostName', [])
                    
                    computer = Computer(
                        object_id=object_id,
                        name=name,
                        domain=self.domain,
                        distinguished_name=str(entry.entry_dn),
                        enabled=enabled,
                        os=os_list[0] if os_list else '',
                        is_dc=is_dc,
                        is_unconstrained=is_unconstrained,
                        has_laps=has_laps,
                        allowed_to_delegate=list(allowed_to_delegate) if allowed_to_delegate else [],
                        properties={
                            'dnsHostName': dns_list[0] if dns_list else '',
                            'osVersion': os_ver_list[0] if os_ver_list else '',
                        }
                    )
                    
                    self.graph.add_node(computer)
                    self._sid_cache[object_id] = name
                    # Cache DN -> SID mapping
                    self._dn_to_sid_cache[str(entry.entry_dn).lower()] = object_id
                    
                    count += 1
                    
                except Exception as e:
                    if self.verbose:
                        self._log(f"[!] Error processing computer entry: {e}")
            
            self._log(f"[+] Collected {count} computers")
            
        except Exception as e:
            self._log(f"[!] Error collecting computers: {e}")
    
    def _collect_ous(self) -> None:
        """Collect organizational unit objects."""
        self._log("[*] Collecting OUs...")
        
        count = 0
        try:
            self.connection.search(
                search_base=self.base_dn,
                search_filter="(objectClass=organizationalUnit)",
                search_scope=SUBTREE,
                attributes=[
                    'distinguishedName', 'name', 'ou', 'description',
                    'gpLink', 'gPOptions', 'nTSecurityDescriptor'
                ],
                paged_size=self.config.page_size
            )
            
            for entry in self.connection.entries:
                try:
                    attrs = entry.entry_attributes_as_dict
                    
                    dn = str(entry.entry_dn)
                    
                    # Safely get name - try 'name' first, then 'ou'
                    name_list = attrs.get('name', [])
                    ou_list = attrs.get('ou', [])
                    name = ''
                    if name_list:
                        name = name_list[0]
                    elif ou_list:
                        name = ou_list[0]
                    else:
                        # Extract from DN
                        if 'OU=' in dn:
                            name = dn.split('OU=')[1].split(',')[0]
                        else:
                            name = dn
                    
                    # Use DN as ID for OUs (no SID)
                    object_id = dn
                    
                    # Check for inheritance blocking - safely
                    gp_options_list = attrs.get('gPOptions', [])
                    gp_options = int(gp_options_list[0]) if gp_options_list and gp_options_list[0] else 0
                    block_inheritance = bool(gp_options & 0x01)
                    
                    # Parse GPO links - safely
                    gp_link_list = attrs.get('gpLink', [])
                    gp_link = gp_link_list[0] if gp_link_list else ''
                    linked_gpos = self._parse_gp_link(gp_link) if gp_link else []
                    
                    # Safely get description
                    desc_list = attrs.get('description', [])
                    
                    ou = OU(
                        object_id=object_id,
                        name=name,
                        domain=self.domain,
                        distinguished_name=dn,
                        block_inheritance=block_inheritance,
                        linked_gpos=linked_gpos,
                        properties={
                            'description': desc_list[0] if desc_list else '',
                        }
                    )
                    
                    self.graph.add_node(ou)
                    count += 1
                    
                except Exception as e:
                    if self.verbose:
                        self._log(f"[!] Error processing OU entry: {e}")
            
            self._log(f"[+] Collected {count} OUs")
            
        except Exception as e:
            self._log(f"[!] Error collecting OUs: {e}")
    
    def _collect_gpos(self) -> None:
        """Collect Group Policy Objects."""
        self._log("[*] Collecting GPOs...")
        
        count = 0
        try:
            self.connection.search(
                search_base=self.base_dn,
                search_filter="(objectClass=groupPolicyContainer)",
                search_scope=SUBTREE,
                attributes=[
                    'distinguishedName', 'displayName', 'name', 'cn',
                    'gPCFileSysPath', 'flags', 'nTSecurityDescriptor'
                ],
                paged_size=self.config.page_size
            )
            
            for entry in self.connection.entries:
                try:
                    attrs = entry.entry_attributes_as_dict
                    
                    dn = str(entry.entry_dn)
                    
                    # Safely get name - try displayName, then name, then cn
                    display_name_list = attrs.get('displayName', [])
                    name_list = attrs.get('name', [])
                    cn_list = attrs.get('cn', [])
                    
                    if display_name_list:
                        name = display_name_list[0]
                    elif name_list:
                        name = name_list[0]
                    elif cn_list:
                        name = cn_list[0]
                    else:
                        # Extract from DN
                        if 'CN=' in dn:
                            name = dn.split('CN=')[1].split(',')[0]
                        else:
                            name = dn
                    
                    # Use DN or GUID as ID
                    object_id = dn
                    
                    # Check enabled status - safely
                    flags_list = attrs.get('flags', [])
                    flags = int(flags_list[0]) if flags_list and flags_list[0] else 0
                    enabled = not (flags & 0x03)  # Both user and computer disabled
                    
                    # Safely get gPCFileSysPath
                    gpc_list = attrs.get('gPCFileSysPath', [])
                    
                    gpo = GPO(
                        object_id=object_id,
                        name=name,
                        domain=self.domain,
                        distinguished_name=dn,
                        gpc_path=gpc_list[0] if gpc_list else '',
                        enabled=enabled,
                        properties={}
                    )
                    
                    self.graph.add_node(gpo)
                    count += 1
                    
                except Exception as e:
                    if self.verbose:
                        self._log(f"[!] Error processing GPO entry: {e}")
            
            self._log(f"[+] Collected {count} GPOs")
            
        except Exception as e:
            self._log(f"[!] Error collecting GPOs: {e}")
    
    def _collect_acls(self) -> None:
        """Collect ACLs for attack path analysis.
        
        This is the most important collection for attack path discovery.
        We enumerate permissions on high-value objects.
        
        Note: Reading nTSecurityDescriptor requires the SD_FLAGS control.
        """
        self._log("[*] Collecting ACLs (this may take a while)...")
        
        acl_count = 0
        
        # SD_FLAGS control to request DACL
        # OWNER_SECURITY_INFORMATION = 1, GROUP_SECURITY_INFORMATION = 2, 
        # DACL_SECURITY_INFORMATION = 4, SACL_SECURITY_INFORMATION = 8
        sd_controls = None
        try:
            if security_descriptor_control:
                sd_controls = security_descriptor_control(sdflags=0x07)  # Owner + Group + DACL
                self._log(f"[*] Created SD control: {type(sd_controls)}")
        except Exception as e:
            self._log(f"[*] Could not create SD control: {e}")
        
        # Objects to enumerate ACLs on
        try:
            # First, enumerate ACLs on domain object
            acl_count += self._enumerate_object_acl_with_control(self.base_dn, sd_controls)
            
            # Enumerate ACLs on users, groups, computers
            for filter_str, object_type in [
                ("(&(objectClass=user)(objectCategory=person))", "users"),
                ("(objectClass=group)", "groups"),
                ("(objectClass=computer)", "computers"),
            ]:
                self._log(f"[*] Enumerating ACLs on {object_type}...")
                
                try:
                    # Query with SD control
                    # Note: sd_controls from ldap3 is already a list
                    self.connection.search(
                        search_base=self.base_dn,
                        search_filter=filter_str,
                        search_scope=SUBTREE,
                        attributes=['distinguishedName', 'nTSecurityDescriptor', 'objectSid'],
                        controls=sd_controls,
                        paged_size=self.config.page_size
                    )
                    
                    for entry in self.connection.entries:
                        try:
                            dn = str(entry.entry_dn)
                            attrs = entry.entry_attributes_as_dict
                            
                            # Get object SID for target
                            # Note: objectSid can come back as bytes OR string depending on the control
                            sid_list = attrs.get('objectSid', [])
                            target_sid = None
                            if sid_list:
                                sid_value = sid_list[0]
                                if isinstance(sid_value, bytes):
                                    target_sid = self._convert_sid(sid_value)
                                elif isinstance(sid_value, str) and sid_value.startswith('S-'):
                                    # SID already in string format
                                    target_sid = sid_value
                            
                            # Fallback to DN lookup if SID not obtained
                            if not target_sid:
                                target_sid = self._dn_to_sid(dn) or dn
                            
                            # Parse security descriptor
                            sd_list = attrs.get('nTSecurityDescriptor', [])
                            if sd_list and sd_list[0]:
                                sd_bytes = sd_list[0]
                                if isinstance(sd_bytes, bytes):
                                    edges = self._parse_security_descriptor(sd_bytes, target_sid)
                                    for edge in edges:
                                        self.graph.add_edge(edge)
                                        acl_count += 1
                                        
                        except Exception as e:
                            if self.verbose:
                                self._log(f"[!] ACL parse error: {e}")
                                
                except Exception as e:
                    self._log(f"[!] Error querying {object_type} ACLs: {e}")
            
            self._log(f"[+] Collected {acl_count} ACL entries")
            
        except Exception as e:
            self._log(f"[!] Error collecting ACLs: {e}")
    
    def _enumerate_object_acl_with_control(self, dn: str, sd_controls) -> int:
        """Enumerate ACLs on a specific object with SD control.
        
        Args:
            dn: Distinguished name of the object
            sd_controls: Security descriptor control list
            
        Returns:
            Number of ACL entries found
        """
        count = 0
        try:
            self.connection.search(
                search_base=dn,
                search_filter="(objectClass=*)",
                search_scope=BASE,
                attributes=['nTSecurityDescriptor', 'objectSid'],
                controls=sd_controls
            )
            
            if self.connection.entries:
                entry = self.connection.entries[0]
                attrs = entry.entry_attributes_as_dict
                
                # Get object SID
                # Note: objectSid can come back as bytes OR string depending on the control
                sid_list = attrs.get('objectSid', [])
                target_sid = None
                if sid_list:
                    sid_value = sid_list[0]
                    if isinstance(sid_value, bytes):
                        target_sid = self._convert_sid(sid_value)
                    elif isinstance(sid_value, str) and sid_value.startswith('S-'):
                        target_sid = sid_value
                
                if not target_sid:
                    target_sid = self._dn_to_sid(dn) or dn
                
                # Parse security descriptor
                sd_list = attrs.get('nTSecurityDescriptor', [])
                if sd_list and sd_list[0]:
                    sd_bytes = sd_list[0]
                    if isinstance(sd_bytes, bytes):
                        edges = self._parse_security_descriptor(sd_bytes, target_sid)
                        for edge in edges:
                            self.graph.add_edge(edge)
                            count += 1
                        
        except Exception as e:
            if self.verbose:
                self._log(f"[!] Error enumerating ACL on {dn}: {e}")
        
        return count
    
    def _parse_security_descriptor(self, sd_bytes: bytes, target_id: str) -> list[ADEdge]:
        """Parse Windows Security Descriptor and extract ACEs.
        
        This is a simplified parser that extracts the most relevant
        permissions for attack path analysis.
        
        Args:
            sd_bytes: Raw security descriptor bytes
            target_id: SID of the object being protected
            
        Returns:
            List of ADEdge objects representing permissions
        """
        edges = []
        
        if not sd_bytes or len(sd_bytes) < 20:
            return edges
        
        try:
            # Security Descriptor structure:
            # Byte 0: Revision
            # Byte 1: Sbz1
            # Bytes 2-3: Control (little-endian)
            # Bytes 4-7: Owner offset
            # Bytes 8-11: Group offset
            # Bytes 12-15: SACL offset
            # Bytes 16-19: DACL offset
            
            control = struct.unpack('<H', sd_bytes[2:4])[0]
            owner_offset = struct.unpack('<I', sd_bytes[4:8])[0]
            dacl_offset = struct.unpack('<I', sd_bytes[16:20])[0]
            
            # Extract owner SID if present
            if owner_offset > 0 and owner_offset < len(sd_bytes):
                owner_sid = self._convert_sid(sd_bytes[owner_offset:])
                if owner_sid and owner_sid != target_id:
                    # Owner has implicit full control
                    edges.append(ADEdge(
                        source_id=owner_sid,
                        target_id=target_id,
                        edge_type=EdgeType.OWNS,
                        properties={'implicit': True}
                    ))
            
            # Check if DACL is present
            if not (control & 0x0004) or dacl_offset == 0:  # SE_DACL_PRESENT
                return edges
            
            # Parse DACL
            if dacl_offset >= len(sd_bytes):
                return edges
                
            dacl = sd_bytes[dacl_offset:]
            
            if len(dacl) < 8:
                return edges
            
            # ACL structure:
            # Byte 0: AclRevision
            # Byte 1: Sbz1
            # Bytes 2-3: AclSize
            # Bytes 4-5: AceCount
            # Bytes 6-7: Sbz2
            
            ace_count = struct.unpack('<H', dacl[4:6])[0]
            
            # Parse ACEs
            ace_offset = 8
            for _ in range(ace_count):
                if ace_offset + 4 > len(dacl):
                    break
                
                # ACE Header:
                # Byte 0: AceType
                # Byte 1: AceFlags
                # Bytes 2-3: AceSize
                
                ace_type = dacl[ace_offset]
                ace_flags = dacl[ace_offset + 1]
                ace_size = struct.unpack('<H', dacl[ace_offset + 2:ace_offset + 4])[0]
                
                if ace_size == 0 or ace_offset + ace_size > len(dacl):
                    break
                
                ace_data = dacl[ace_offset:ace_offset + ace_size]
                
                # Process access allowed ACEs (types 0, 5)
                # Type 0: ACCESS_ALLOWED_ACE_TYPE
                # Type 5: ACCESS_ALLOWED_OBJECT_ACE_TYPE
                if ace_type in (0, 5):
                    edge = self._parse_ace(ace_data, ace_type, target_id)
                    if edge:
                        edges.append(edge)
                
                ace_offset += ace_size
                
        except Exception as e:
            if self.verbose:
                self._log(f"[!] SD parse error: {e}")
        
        return edges
    
    def _parse_ace(self, ace_data: bytes, ace_type: int, target_id: str) -> Optional[ADEdge]:
        """Parse a single ACE and return an edge if relevant.
        
        Args:
            ace_data: Raw ACE bytes
            ace_type: Type of ACE (0=allowed, 5=object allowed)
            target_id: SID of the protected object
            
        Returns:
            ADEdge if the ACE grants exploitable permissions, None otherwise
        """
        try:
            if ace_type == 0:  # ACCESS_ALLOWED_ACE
                # Bytes 4-7: Access mask
                # Remaining: SID
                if len(ace_data) < 8:
                    return None
                
                access_mask = struct.unpack('<I', ace_data[4:8])[0]
                principal_sid = self._convert_sid(ace_data[8:])
                
                # Map access rights to edge types
                edge_type = self._access_mask_to_edge_type(access_mask)
                
                if edge_type and principal_sid and principal_sid != target_id:
                    return ADEdge(
                        source_id=principal_sid,
                        target_id=target_id,
                        edge_type=edge_type,
                        properties={'access_mask': access_mask}
                    )
                    
            elif ace_type == 5:  # ACCESS_ALLOWED_OBJECT_ACE
                # Bytes 4-7: Access mask
                # Bytes 8-11: Flags
                # Optional: Object type GUID (16 bytes)
                # Optional: Inherited object type GUID (16 bytes)
                # Remaining: SID
                
                if len(ace_data) < 12:
                    return None
                
                access_mask = struct.unpack('<I', ace_data[4:8])[0]
                flags = struct.unpack('<I', ace_data[8:12])[0]
                
                sid_offset = 12
                object_type_guid = None
                
                # Check for object type GUID
                if flags & 0x01:  # ACE_OBJECT_TYPE_PRESENT
                    if len(ace_data) >= sid_offset + 16:
                        object_type_guid = self._format_guid(ace_data[sid_offset:sid_offset + 16])
                        sid_offset += 16
                
                # Check for inherited object type GUID
                if flags & 0x02:  # ACE_INHERITED_OBJECT_TYPE_PRESENT
                    sid_offset += 16
                
                if sid_offset < len(ace_data):
                    principal_sid = self._convert_sid(ace_data[sid_offset:])
                else:
                    return None
                
                # Map to edge type based on object type GUID
                edge_type = self._object_ace_to_edge_type(access_mask, object_type_guid)
                
                if edge_type and principal_sid and principal_sid != target_id:
                    return ADEdge(
                        source_id=principal_sid,
                        target_id=target_id,
                        edge_type=edge_type,
                        properties={
                            'access_mask': access_mask,
                            'object_type': object_type_guid
                        }
                    )
                    
        except Exception as e:
            pass
        
        return None
    
    def _access_mask_to_edge_type(self, access_mask: int) -> Optional[EdgeType]:
        """Convert access mask to edge type.
        
        Args:
            access_mask: Windows access mask value
            
        Returns:
            EdgeType if exploitable permission, None otherwise
        """
        # Standard access rights
        DELETE = 0x00010000
        READ_CONTROL = 0x00020000
        WRITE_DAC = 0x00040000
        WRITE_OWNER = 0x00080000
        SYNCHRONIZE = 0x00100000
        
        # Generic access rights
        GENERIC_READ = 0x80000000
        GENERIC_WRITE = 0x40000000
        GENERIC_EXECUTE = 0x20000000
        GENERIC_ALL = 0x10000000
        
        # AD-specific rights
        ADS_RIGHT_DS_CREATE_CHILD = 0x00000001
        ADS_RIGHT_DS_DELETE_CHILD = 0x00000002
        ADS_RIGHT_ACTRL_DS_LIST = 0x00000004
        ADS_RIGHT_DS_SELF = 0x00000008            # Validated write (AddSelf)
        ADS_RIGHT_DS_READ_PROP = 0x00000010
        ADS_RIGHT_DS_WRITE_PROP = 0x00000020      # Write property
        ADS_RIGHT_DS_DELETE_TREE = 0x00000040
        ADS_RIGHT_DS_LIST_OBJECT = 0x00000080
        ADS_RIGHT_DS_CONTROL_ACCESS = 0x00000100  # Extended right / property set
        
        # Check in order of severity
        if access_mask & GENERIC_ALL:
            return EdgeType.GENERIC_ALL
        
        # Full control mask (common pattern for GenericAll)
        if access_mask == 0x000F01FF:
            return EdgeType.GENERIC_ALL
        
        if access_mask & WRITE_OWNER:
            return EdgeType.WRITE_OWNER
        
        if access_mask & WRITE_DAC:
            return EdgeType.WRITE_DACL
        
        if access_mask & GENERIC_WRITE:
            return EdgeType.GENERIC_WRITE
        
        # Write property is dangerous
        if access_mask & ADS_RIGHT_DS_WRITE_PROP:
            return EdgeType.GENERIC_WRITE
        
        # Extended rights (control access) - could be many things
        if access_mask & ADS_RIGHT_DS_CONTROL_ACCESS:
            return EdgeType.ALL_EXTENDED_RIGHTS
        
        # Self rights (validated writes like AddSelf to groups)
        if access_mask & ADS_RIGHT_DS_SELF:
            return EdgeType.ADD_SELF
        
        return None
    
    def _object_ace_to_edge_type(self, access_mask: int, object_type: Optional[str]) -> Optional[EdgeType]:
        """Convert object ACE to edge type based on object type GUID.
        
        Args:
            access_mask: Windows access mask value
            object_type: GUID of the object type (right/property)
            
        Returns:
            EdgeType if exploitable permission, None otherwise
        """
        if not object_type:
            return self._access_mask_to_edge_type(access_mask)
        
        object_type_lower = object_type.lower()
        
        # Extended Rights GUIDs
        GUID_MAP = {
            # User-Force-Change-Password
            '00299570-246d-11d0-a768-00aa006e0529': EdgeType.FORCE_CHANGE_PASSWORD,
            # DS-Replication-Get-Changes
            '1131f6aa-9c07-11d1-f79f-00c04fc2dcd2': EdgeType.GET_CHANGES,
            # DS-Replication-Get-Changes-All (DCSync)
            '1131f6ad-9c07-11d1-f79f-00c04fc2dcd2': EdgeType.GET_CHANGES_ALL,
            # DS-Replication-Get-Changes-In-Filtered-Set
            '89e95b76-444d-4c62-991a-0facbeda640c': EdgeType.GET_CHANGES,
            # All Extended Rights (null GUID)
            '00000000-0000-0000-0000-000000000000': EdgeType.ALL_EXTENDED_RIGHTS,
            # ms-DS-Key-Credential-Link (Shadow Credentials)
            '5b47d60f-6090-40b2-9f37-2a4de88f3063': EdgeType.ADD_KEY_CREDENTIAL_LINK,
            # Member attribute
            'bf9679c0-0de6-11d0-a285-00aa003049e2': EdgeType.ADD_MEMBER,
            # User-Account-Restrictions property set
            '4c164200-20c0-11d0-a768-00aa006e0529': EdgeType.WRITE_ACCOUNT_RESTRICTIONS,
            # Service-Principal-Name
            'f3a64788-5306-11d1-a9c5-0000f80367c1': EdgeType.GENERIC_WRITE,
            # msDS-AllowedToActOnBehalfOfOtherIdentity (RBCD)
            '3f78c3e5-f79a-46bd-a0b8-9d18116ddc79': EdgeType.ALLOWED_TO_ACT,
            # msDS-GroupMSAMembership
            '888eedd6-ce04-df40-b462-b8a50e41ba38': EdgeType.READ_GMSA_PASSWORD,
            # User-Logon property set
            '5f202010-79a5-11d0-9020-00c04fc2d4cf': EdgeType.GENERIC_WRITE,
            # Personal-Information property set
            '77b5b886-944a-11d1-aebd-0000f80367c1': EdgeType.GENERIC_WRITE,
            # Public-Information property set
            'e48d0154-bcf8-11d1-8702-00c04fb96050': EdgeType.GENERIC_WRITE,
        }
        
        # Check GUID map
        if object_type_lower in GUID_MAP:
            return GUID_MAP[object_type_lower]
        
        # Check access mask for write property or control access
        ADS_RIGHT_DS_WRITE_PROP = 0x00000020
        ADS_RIGHT_DS_CONTROL_ACCESS = 0x00000100
        
        if access_mask & ADS_RIGHT_DS_CONTROL_ACCESS:
            # Unknown extended right - still might be exploitable
            return EdgeType.ALL_EXTENDED_RIGHTS
        
        if access_mask & ADS_RIGHT_DS_WRITE_PROP:
            # Unknown property write - could be dangerous
            return EdgeType.GENERIC_WRITE
        
        # Fall back to access mask
        return self._access_mask_to_edge_type(access_mask)
    
    def _format_guid(self, guid_bytes: bytes) -> str:
        """Format GUID bytes as string.
        
        Args:
            guid_bytes: 16 bytes of GUID data
            
        Returns:
            GUID string (e.g., "00299570-246d-11d0-a768-00aa006e0529")
        """
        if len(guid_bytes) != 16:
            return ""
        
        # GUID is stored with mixed endianness:
        # First 3 components are little-endian, last 2 are big-endian
        data1 = struct.unpack('<I', guid_bytes[0:4])[0]
        data2 = struct.unpack('<H', guid_bytes[4:6])[0]
        data3 = struct.unpack('<H', guid_bytes[6:8])[0]
        data4 = guid_bytes[8:10].hex()
        data5 = guid_bytes[10:16].hex()
        
        return f"{data1:08x}-{data2:04x}-{data3:04x}-{data4}-{data5}"
    
    def _dn_to_sid(self, dn: str) -> Optional[str]:
        """Look up SID for a DN.
        
        Args:
            dn: Distinguished name
            
        Returns:
            SID string or the DN if lookup fails
        """
        if not dn:
            return None
        
        dn_lower = dn.lower()
        
        # Check DN cache first (fastest)
        if dn_lower in self._dn_to_sid_cache:
            return self._dn_to_sid_cache[dn_lower]
        
        # Extract CN from DN for name-based matching
        cn_match = None
        if 'CN=' in dn:
            # Extract the first CN value (the object's name)
            cn_match = dn.split('CN=')[1].split(',')[0].lower()
            
        # Check name cache - require exact CN match
        for sid, name in self._sid_cache.items():
            if name and cn_match:
                # Exact match on CN
                if name.lower() == cn_match:
                    # Cache this mapping for future
                    self._dn_to_sid_cache[dn_lower] = sid
                    return sid
        
        # Try to look up via LDAP
        try:
            self.connection.search(
                search_base=dn,
                search_filter="(objectClass=*)",
                search_scope=BASE,
                attributes=['objectSid']
            )
            
            if self.connection.entries:
                attrs = self.connection.entries[0].entry_attributes_as_dict
                sid_list = attrs.get('objectSid', [])
                if sid_list:
                    sid_value = sid_list[0]
                    if isinstance(sid_value, bytes):
                        sid = self._convert_sid(sid_value)
                    elif isinstance(sid_value, str) and sid_value.startswith('S-'):
                        sid = sid_value
                    else:
                        sid = None
                    
                    if sid:
                        # Cache this for future lookups
                        self._dn_to_sid_cache[dn_lower] = sid
                        if cn_match:
                            self._sid_cache[sid] = cn_match
                        return sid
        except:
            pass
        
        # Return DN as fallback (for objects without SIDs like OUs)
        return dn
    
    def _parse_gp_link(self, gp_link: str) -> list[str]:
        """Parse gpLink attribute to extract linked GPO DNs.
        
        Args:
            gp_link: gpLink attribute value
            
        Returns:
            List of GPO DNs
        """
        if not gp_link:
            return []
        
        gpos = []
        # Format: [LDAP://DN;options][LDAP://DN;options]...
        parts = gp_link.split('][')
        for part in parts:
            part = part.strip('[]')
            if ';' in part:
                dn_part = part.split(';')[0]
                if dn_part.upper().startswith('LDAP://'):
                    gpos.append(dn_part[7:])  # Remove "LDAP://"
        
        return gpos
    
    def export_bloodhound_json(self, output_dir: str) -> list[str]:
        """Export collected data as BloodHound-compatible JSON.
        
        Args:
            output_dir: Directory to write JSON files
            
        Returns:
            List of created file paths
        """
        os.makedirs(output_dir, exist_ok=True)
        files = []
        
        # Export users
        users_data = {
            "meta": {"type": "users", "count": 0, "version": 5},
            "data": []
        }
        
        for user in self.graph.get_nodes_by_type(NodeType.USER):
            if isinstance(user, User):
                users_data["data"].append({
                    "ObjectIdentifier": user.object_id,
                    "Properties": {
                        "name": f"{user.name}@{user.domain}".upper(),
                        "domain": user.domain.upper(),
                        "objectid": user.object_id,
                        "distinguishedname": user.distinguished_name,
                        "enabled": user.enabled,
                        "admincount": user.admin_count,
                        "hasspn": user.spn_count > 0,
                    },
                    "Aces": [],
                    "MemberOf": []
                })
        
        users_data["meta"]["count"] = len(users_data["data"])
        users_file = os.path.join(output_dir, "users.json")
        with open(users_file, 'w') as f:
            json.dump(users_data, f, indent=2)
        files.append(users_file)
        
        # Export groups
        groups_data = {
            "meta": {"type": "groups", "count": 0, "version": 5},
            "data": []
        }
        
        for group in self.graph.get_nodes_by_type(NodeType.GROUP):
            if isinstance(group, Group):
                groups_data["data"].append({
                    "ObjectIdentifier": group.object_id,
                    "Properties": {
                        "name": f"{group.name}@{group.domain}".upper(),
                        "domain": group.domain.upper(),
                        "objectid": group.object_id,
                        "distinguishedname": group.distinguished_name,
                        "admincount": group.admin_count,
                        "highvalue": group.is_high_value,
                    },
                    "Members": [],
                    "Aces": []
                })
        
        groups_data["meta"]["count"] = len(groups_data["data"])
        groups_file = os.path.join(output_dir, "groups.json")
        with open(groups_file, 'w') as f:
            json.dump(groups_data, f, indent=2)
        files.append(groups_file)
        
        # Export computers
        computers_data = {
            "meta": {"type": "computers", "count": 0, "version": 5},
            "data": []
        }
        
        for computer in self.graph.get_nodes_by_type(NodeType.COMPUTER):
            if isinstance(computer, Computer):
                computers_data["data"].append({
                    "ObjectIdentifier": computer.object_id,
                    "Properties": {
                        "name": f"{computer.name}.{computer.domain}".upper(),
                        "domain": computer.domain.upper(),
                        "objectid": computer.object_id,
                        "distinguishedname": computer.distinguished_name,
                        "enabled": computer.enabled,
                        "operatingsystem": computer.os,
                        "isdc": computer.is_dc,
                        "unconstraineddelegation": computer.is_unconstrained,
                        "haslaps": computer.has_laps,
                    },
                    "LocalAdmins": [],
                    "Sessions": [],
                    "Aces": []
                })
        
        computers_data["meta"]["count"] = len(computers_data["data"])
        computers_file = os.path.join(output_dir, "computers.json")
        with open(computers_file, 'w') as f:
            json.dump(computers_data, f, indent=2)
        files.append(computers_file)
        
        self._log(f"[+] Exported BloodHound JSON to {output_dir}")
        return files
    
    def disconnect(self) -> None:
        """Close the LDAP connection."""
        if self.connection:
            try:
                self.connection.unbind()
            except:
                pass
            self.connection = None

