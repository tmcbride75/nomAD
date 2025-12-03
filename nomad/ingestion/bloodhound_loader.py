"""
BloodHound/SharpHound JSON Loader
=================================

Parses BloodHound-compatible JSON files and builds an ADGraph.

Supported Formats:
- SharpHound v2/v3 JSON exports (users.json, groups.json, etc.)
- BloodHound CE JSON format
- Combined/zipped SharpHound exports

Design Decisions:
-----------------
1. Handles both individual JSON files and combined exports
2. Maps BloodHound node types to our schema
3. Processes ACL relationships for attack path analysis
4. Normalizes SIDs and object identifiers across formats
"""

import json
import zipfile
import os
from pathlib import Path
from typing import Optional
from datetime import datetime

from ..model.schemas import (
    User, Group, Computer, Domain, OU, GPO,
    ADNode, ADEdge, NodeType, EdgeType
)
from ..model.graph_builder import ADGraph


class BloodHoundLoader:
    """Loader for BloodHound/SharpHound JSON data.
    
    Usage:
        loader = BloodHoundLoader()
        graph = loader.load_files(["users.json", "groups.json", ...])
        
        # Or load a zip file
        graph = loader.load_zip("sharphound_output.zip")
    
    The loader handles various BloodHound JSON formats and normalizes
    them into the nomAD graph model.
    """
    
    def __init__(self, verbose: bool = False):
        """Initialize the BloodHound loader.
        
        Args:
            verbose: Whether to print progress messages
        """
        self.verbose = verbose
        self.graph = ADGraph()
        self._domain_sids: dict[str, str] = {}  # domain -> domain SID
    
    def load_files(self, file_paths: list[str]) -> ADGraph:
        """Load multiple BloodHound JSON files.
        
        Args:
            file_paths: List of paths to JSON files
            
        Returns:
            ADGraph populated with the loaded data
        """
        self.graph = ADGraph()
        
        for file_path in file_paths:
            self._load_file(file_path)
        
        return self.graph
    
    def load_zip(self, zip_path: str) -> ADGraph:
        """Load a SharpHound zip archive.
        
        Args:
            zip_path: Path to the zip file
            
        Returns:
            ADGraph populated with the loaded data
        """
        self.graph = ADGraph()
        
        with zipfile.ZipFile(zip_path, 'r') as zf:
            for name in zf.namelist():
                if name.endswith('.json'):
                    if self.verbose:
                        print(f"[*] Loading {name} from zip...")
                    
                    with zf.open(name) as f:
                        data = json.load(f)
                        self._process_json(data, name)
        
        return self.graph
    
    def _load_file(self, file_path: str) -> None:
        """Load a single JSON file.
        
        Args:
            file_path: Path to the JSON file
        """
        path = Path(file_path)
        
        if not path.exists():
            if self.verbose:
                print(f"[!] File not found: {file_path}")
            return
        
        if self.verbose:
            print(f"[*] Loading {path.name}...")
        
        if path.suffix == '.zip':
            # Handle zip files
            with zipfile.ZipFile(path, 'r') as zf:
                for name in zf.namelist():
                    if name.endswith('.json'):
                        with zf.open(name) as f:
                            data = json.load(f)
                            self._process_json(data, name)
        else:
            # Handle JSON files
            with open(path, 'r', encoding='utf-8') as f:
                data = json.load(f)
                self._process_json(data, path.name)
    
    def _process_json(self, data: dict, filename: str) -> None:
        """Process JSON data based on its content type.
        
        BloodHound JSON can contain:
        - "users" key for user data
        - "groups" key for group data
        - "computers" key for computer data
        - "data" key with a "type" field
        - Direct array of objects
        
        Args:
            data: Parsed JSON data
            filename: Original filename (for type hints)
        """
        # Handle BloodHound CE format (has meta and data keys)
        if isinstance(data, dict) and 'data' in data and 'meta' in data:
            meta_type = data.get('meta', {}).get('type', '').lower()
            items = data.get('data', [])
            
            if meta_type == 'users' or 'users' in filename.lower():
                self._process_users(items)
            elif meta_type == 'groups' or 'groups' in filename.lower():
                self._process_groups(items)
            elif meta_type == 'computers' or 'computers' in filename.lower():
                self._process_computers(items)
            elif meta_type == 'domains' or 'domains' in filename.lower():
                self._process_domains(items)
            elif meta_type == 'gpos' or 'gpos' in filename.lower():
                self._process_gpos(items)
            elif meta_type == 'ous' or 'ous' in filename.lower():
                self._process_ous(items)
            else:
                # Try to detect type from data
                self._process_generic(items)
            return
        
        # Handle older SharpHound format (direct keys)
        if isinstance(data, dict):
            if 'users' in data:
                self._process_users(data['users'])
            if 'groups' in data:
                self._process_groups(data['groups'])
            if 'computers' in data:
                self._process_computers(data['computers'])
            if 'domains' in data:
                self._process_domains(data['domains'])
            if 'gpos' in data:
                self._process_gpos(data['gpos'])
            if 'ous' in data:
                self._process_ous(data['ous'])
            
            # Handle relationships if present
            if 'relationships' in data:
                self._process_relationships(data['relationships'])
            if 'aces' in data:
                self._process_aces(data['aces'])
            return
        
        # Handle array of objects (detect by first item)
        if isinstance(data, list) and len(data) > 0:
            # Determine type based on filename or content
            filename_lower = filename.lower()
            if 'user' in filename_lower:
                self._process_users(data)
            elif 'group' in filename_lower:
                self._process_groups(data)
            elif 'computer' in filename_lower:
                self._process_computers(data)
            elif 'domain' in filename_lower:
                self._process_domains(data)
            elif 'gpo' in filename_lower:
                self._process_gpos(data)
            elif 'ou' in filename_lower:
                self._process_ous(data)
            else:
                self._process_generic(data)
    
    def _process_users(self, users: list) -> None:
        """Process user objects from BloodHound JSON.
        
        Args:
            users: List of user dictionaries
        """
        for user_data in users:
            try:
                props = user_data.get('Properties', user_data.get('properties', {}))
                
                # Get identifiers
                object_id = (
                    user_data.get('ObjectIdentifier') or 
                    user_data.get('objectid') or
                    props.get('objectid') or
                    props.get('objectsid', '')
                )
                
                name = (
                    props.get('name') or 
                    props.get('samaccountname') or
                    user_data.get('Name', '')
                )
                
                domain = props.get('domain', '')
                
                # Extract properties
                user = User(
                    object_id=object_id,
                    name=self._clean_name(name),
                    domain=domain,
                    distinguished_name=props.get('distinguishedname'),
                    enabled=props.get('enabled', True),
                    admin_count=props.get('admincount', False),
                    sensitive=props.get('sensitive', False) or props.get('unconstraineddelegation', False),
                    password_never_expires=props.get('pwdneverexpires', False),
                    password_not_required=props.get('passwordnotreqd', False),
                    is_domain_admin=props.get('isdomainadmin', False),
                    is_enterprise_admin=props.get('isentadmin', False),
                    spn_count=len(props.get('serviceprincipalnames', [])),
                    properties=props
                )
                
                self.graph.add_node(user)
                
                # Process ACEs (permissions this user has)
                self._process_node_aces(user_data, object_id)
                
                # Process group memberships
                self._process_memberships(user_data, object_id)
                
            except Exception as e:
                if self.verbose:
                    print(f"[!] Error processing user: {e}")
    
    def _process_groups(self, groups: list) -> None:
        """Process group objects from BloodHound JSON.
        
        Args:
            groups: List of group dictionaries
        """
        for group_data in groups:
            try:
                props = group_data.get('Properties', group_data.get('properties', {}))
                
                object_id = (
                    group_data.get('ObjectIdentifier') or 
                    group_data.get('objectid') or
                    props.get('objectid') or
                    props.get('objectsid', '')
                )
                
                name = (
                    props.get('name') or 
                    props.get('samaccountname') or
                    group_data.get('Name', '')
                )
                
                domain = props.get('domain', '')
                
                # Check if high-value target
                hvt_names = [
                    "domain admins", "enterprise admins", "administrators",
                    "schema admins", "account operators", "backup operators",
                    "server operators", "print operators", "dnsadmins",
                    "group policy creator owners"
                ]
                clean_name = self._clean_name(name).lower()
                is_high_value = props.get('highvalue', False) or any(
                    hvt in clean_name for hvt in hvt_names
                )
                
                group = Group(
                    object_id=object_id,
                    name=self._clean_name(name),
                    domain=domain,
                    distinguished_name=props.get('distinguishedname'),
                    admin_count=props.get('admincount', False),
                    is_high_value=is_high_value,
                    properties=props
                )
                
                self.graph.add_node(group)
                
                # Process members
                members = group_data.get('Members', group_data.get('members', []))
                for member in members:
                    member_id = member.get('ObjectIdentifier') or member.get('objectid', '')
                    if member_id:
                        edge = ADEdge(
                            source_id=member_id,
                            target_id=object_id,
                            edge_type=EdgeType.MEMBER_OF
                        )
                        self.graph.add_edge(edge)
                
                # Process ACEs
                self._process_node_aces(group_data, object_id)
                
            except Exception as e:
                if self.verbose:
                    print(f"[!] Error processing group: {e}")
    
    def _process_computers(self, computers: list) -> None:
        """Process computer objects from BloodHound JSON.
        
        Args:
            computers: List of computer dictionaries
        """
        for comp_data in computers:
            try:
                props = comp_data.get('Properties', comp_data.get('properties', {}))
                
                object_id = (
                    comp_data.get('ObjectIdentifier') or 
                    comp_data.get('objectid') or
                    props.get('objectid') or
                    props.get('objectsid', '')
                )
                
                name = (
                    props.get('name') or 
                    props.get('samaccountname') or
                    comp_data.get('Name', '')
                )
                
                domain = props.get('domain', '')
                
                # Check if Domain Controller
                is_dc = props.get('isdc', False) or props.get('primarygroupsid', '').endswith('-516')
                
                computer = Computer(
                    object_id=object_id,
                    name=self._clean_name(name),
                    domain=domain,
                    distinguished_name=props.get('distinguishedname'),
                    enabled=props.get('enabled', True),
                    os=props.get('operatingsystem'),
                    is_dc=is_dc,
                    is_unconstrained=props.get('unconstraineddelegation', False),
                    has_laps=props.get('haslaps', False),
                    allowed_to_delegate=props.get('allowedtodelegate', []),
                    properties=props
                )
                
                self.graph.add_node(computer)
                
                # Process sessions
                sessions = comp_data.get('Sessions', comp_data.get('sessions', []))
                for session in sessions:
                    user_id = session.get('UserId') or session.get('userid') or session.get('ObjectIdentifier', '')
                    if user_id:
                        edge = ADEdge(
                            source_id=user_id,
                            target_id=object_id,
                            edge_type=EdgeType.HAS_SESSION
                        )
                        self.graph.add_edge(edge)
                
                # Process local admins
                local_admins = comp_data.get('LocalAdmins', comp_data.get('localadmins', []))
                for admin in local_admins:
                    admin_id = admin.get('ObjectIdentifier') or admin.get('objectid', '')
                    if admin_id:
                        edge = ADEdge(
                            source_id=admin_id,
                            target_id=object_id,
                            edge_type=EdgeType.ADMIN_TO
                        )
                        self.graph.add_edge(edge)
                
                # Process RDP users
                rdp_users = comp_data.get('RemoteDesktopUsers', comp_data.get('remotedesktopusers', []))
                for rdp_user in rdp_users:
                    rdp_id = rdp_user.get('ObjectIdentifier') or rdp_user.get('objectid', '')
                    if rdp_id:
                        edge = ADEdge(
                            source_id=rdp_id,
                            target_id=object_id,
                            edge_type=EdgeType.CAN_RDP
                        )
                        self.graph.add_edge(edge)
                
                # Process PSRemote users
                psremote_users = comp_data.get('PSRemoteUsers', comp_data.get('psremoteusers', []))
                for psremote_user in psremote_users:
                    psremote_id = psremote_user.get('ObjectIdentifier') or psremote_user.get('objectid', '')
                    if psremote_id:
                        edge = ADEdge(
                            source_id=psremote_id,
                            target_id=object_id,
                            edge_type=EdgeType.CAN_PSREMOTE
                        )
                        self.graph.add_edge(edge)
                
                # Process DCOM users
                dcom_users = comp_data.get('DcomUsers', comp_data.get('dcomusers', []))
                for dcom_user in dcom_users:
                    dcom_id = dcom_user.get('ObjectIdentifier') or dcom_user.get('objectid', '')
                    if dcom_id:
                        edge = ADEdge(
                            source_id=dcom_id,
                            target_id=object_id,
                            edge_type=EdgeType.EXECUTE_DCOM
                        )
                        self.graph.add_edge(edge)
                
                # Process ACEs
                self._process_node_aces(comp_data, object_id)
                
                # Process group memberships
                self._process_memberships(comp_data, object_id)
                
            except Exception as e:
                if self.verbose:
                    print(f"[!] Error processing computer: {e}")
    
    def _process_domains(self, domains: list) -> None:
        """Process domain objects from BloodHound JSON.
        
        Args:
            domains: List of domain dictionaries
        """
        for domain_data in domains:
            try:
                props = domain_data.get('Properties', domain_data.get('properties', {}))
                
                object_id = (
                    domain_data.get('ObjectIdentifier') or 
                    domain_data.get('objectid') or
                    props.get('objectid', '')
                )
                
                name = (
                    props.get('name') or 
                    props.get('domain') or
                    domain_data.get('Name', '')
                )
                
                domain = Domain(
                    object_id=object_id,
                    name=name,
                    domain=name,
                    distinguished_name=props.get('distinguishedname'),
                    functional_level=props.get('functionallevel'),
                    properties=props
                )
                
                self.graph.add_node(domain)
                
                # Process trust relationships
                trusts = domain_data.get('Trusts', domain_data.get('trusts', []))
                for trust in trusts:
                    target_id = trust.get('TargetDomainSid') or trust.get('targetdomainsid', '')
                    if target_id:
                        edge = ADEdge(
                            source_id=object_id,
                            target_id=target_id,
                            edge_type=EdgeType.TRUSTED_BY,
                            properties=trust
                        )
                        self.graph.add_edge(edge)
                
                # Process ACEs
                self._process_node_aces(domain_data, object_id)
                
            except Exception as e:
                if self.verbose:
                    print(f"[!] Error processing domain: {e}")
    
    def _process_gpos(self, gpos: list) -> None:
        """Process GPO objects from BloodHound JSON.
        
        Args:
            gpos: List of GPO dictionaries
        """
        for gpo_data in gpos:
            try:
                props = gpo_data.get('Properties', gpo_data.get('properties', {}))
                
                object_id = (
                    gpo_data.get('ObjectIdentifier') or 
                    gpo_data.get('objectid') or
                    props.get('objectid', '')
                )
                
                name = (
                    props.get('name') or 
                    props.get('displayname') or
                    gpo_data.get('Name', '')
                )
                
                gpo = GPO(
                    object_id=object_id,
                    name=name,
                    domain=props.get('domain'),
                    distinguished_name=props.get('distinguishedname'),
                    gpc_path=props.get('gpcpath'),
                    enabled=props.get('enabled', True),
                    properties=props
                )
                
                self.graph.add_node(gpo)
                
                # Process ACEs
                self._process_node_aces(gpo_data, object_id)
                
            except Exception as e:
                if self.verbose:
                    print(f"[!] Error processing GPO: {e}")
    
    def _process_ous(self, ous: list) -> None:
        """Process OU objects from BloodHound JSON.
        
        Args:
            ous: List of OU dictionaries
        """
        for ou_data in ous:
            try:
                props = ou_data.get('Properties', ou_data.get('properties', {}))
                
                object_id = (
                    ou_data.get('ObjectIdentifier') or 
                    ou_data.get('objectid') or
                    props.get('objectid', '')
                )
                
                name = (
                    props.get('name') or 
                    props.get('ou') or
                    ou_data.get('Name', '')
                )
                
                ou = OU(
                    object_id=object_id,
                    name=name,
                    domain=props.get('domain'),
                    distinguished_name=props.get('distinguishedname'),
                    block_inheritance=props.get('blockinheritance', False),
                    properties=props
                )
                
                self.graph.add_node(ou)
                
                # Process child objects (contains edges)
                children = ou_data.get('ChildObjects', ou_data.get('childobjects', []))
                for child in children:
                    child_id = child.get('ObjectIdentifier') or child.get('objectid', '')
                    if child_id:
                        edge = ADEdge(
                            source_id=object_id,
                            target_id=child_id,
                            edge_type=EdgeType.CONTAINS
                        )
                        self.graph.add_edge(edge)
                
                # Process linked GPOs
                links = ou_data.get('Links', ou_data.get('links', []))
                for link in links:
                    gpo_id = link.get('GUID') or link.get('guid', '')
                    if gpo_id:
                        edge = ADEdge(
                            source_id=gpo_id,
                            target_id=object_id,
                            edge_type=EdgeType.GP_LINK,
                            properties={'enforced': link.get('IsEnforced', False)}
                        )
                        self.graph.add_edge(edge)
                
                # Process ACEs
                self._process_node_aces(ou_data, object_id)
                
            except Exception as e:
                if self.verbose:
                    print(f"[!] Error processing OU: {e}")
    
    def _process_node_aces(self, node_data: dict, target_id: str) -> None:
        """Process ACEs (Access Control Entries) for a node.
        
        This creates edges for permissions that other principals have
        on this node.
        
        Args:
            node_data: Node dictionary containing ACEs
            target_id: Object ID of the node being processed
        """
        aces = node_data.get('Aces', node_data.get('aces', []))
        
        for ace in aces:
            try:
                principal_id = ace.get('PrincipalSID') or ace.get('principalsid', '')
                right_name = ace.get('RightName') or ace.get('rightname', '')
                
                if not principal_id or not right_name:
                    continue
                
                # Map right name to edge type
                edge_type = EdgeType.from_string(right_name)
                
                if edge_type != EdgeType.UNKNOWN:
                    edge = ADEdge(
                        source_id=principal_id,
                        target_id=target_id,
                        edge_type=edge_type,
                        properties={
                            'inherited': ace.get('IsInherited', False),
                            'ace_type': ace.get('AceType', '')
                        }
                    )
                    self.graph.add_edge(edge)
                    
            except Exception as e:
                if self.verbose:
                    print(f"[!] Error processing ACE: {e}")
    
    def _process_memberships(self, node_data: dict, source_id: str) -> None:
        """Process group memberships for a node.
        
        Args:
            node_data: Node dictionary
            source_id: Object ID of the node
        """
        # Handle different key formats
        memberships = (
            node_data.get('MemberOf', []) or 
            node_data.get('memberof', []) or
            node_data.get('Properties', {}).get('memberof', []) or
            []
        )
        
        for member in memberships:
            if isinstance(member, dict):
                group_id = member.get('ObjectIdentifier') or member.get('objectid', '')
            else:
                group_id = str(member)
            
            if group_id:
                edge = ADEdge(
                    source_id=source_id,
                    target_id=group_id,
                    edge_type=EdgeType.MEMBER_OF
                )
                self.graph.add_edge(edge)
    
    def _process_relationships(self, relationships: list) -> None:
        """Process explicit relationship data.
        
        Args:
            relationships: List of relationship dictionaries
        """
        for rel in relationships:
            try:
                source_id = rel.get('SourceId') or rel.get('sourceid', '')
                target_id = rel.get('TargetId') or rel.get('targetid', '')
                rel_type = rel.get('Type') or rel.get('type', '')
                
                if not source_id or not target_id or not rel_type:
                    continue
                
                edge_type = EdgeType.from_string(rel_type)
                
                edge = ADEdge(
                    source_id=source_id,
                    target_id=target_id,
                    edge_type=edge_type,
                    properties=rel.get('Properties', {})
                )
                self.graph.add_edge(edge)
                
            except Exception as e:
                if self.verbose:
                    print(f"[!] Error processing relationship: {e}")
    
    def _process_aces(self, aces: list) -> None:
        """Process standalone ACE data.
        
        Args:
            aces: List of ACE dictionaries
        """
        for ace in aces:
            try:
                source_id = ace.get('PrincipalSID') or ace.get('principalsid', '')
                target_id = ace.get('TargetSID') or ace.get('targetsid', '')
                right_name = ace.get('RightName') or ace.get('rightname', '')
                
                if not source_id or not target_id or not right_name:
                    continue
                
                edge_type = EdgeType.from_string(right_name)
                
                edge = ADEdge(
                    source_id=source_id,
                    target_id=target_id,
                    edge_type=edge_type,
                    properties={
                        'inherited': ace.get('IsInherited', False),
                        'ace_type': ace.get('AceType', '')
                    }
                )
                self.graph.add_edge(edge)
                
            except Exception as e:
                if self.verbose:
                    print(f"[!] Error processing ACE: {e}")
    
    def _process_generic(self, items: list) -> None:
        """Process items when type cannot be determined.
        
        Tries to detect type from item content.
        
        Args:
            items: List of item dictionaries
        """
        for item in items:
            try:
                # Try to detect type from properties
                props = item.get('Properties', item.get('properties', {}))
                
                # Check for type indicators
                if 'samaccounttype' in str(props).lower():
                    sat = props.get('samaccounttype', 0)
                    if sat == 805306368:  # User
                        self._process_users([item])
                    elif sat == 268435456:  # Group
                        self._process_groups([item])
                    elif sat == 805306369:  # Computer
                        self._process_computers([item])
                elif 'isdc' in str(props).lower() or 'operatingsystem' in str(props).lower():
                    self._process_computers([item])
                elif 'admincount' in str(props).lower():
                    # Could be user or group - check for more clues
                    if 'serviceprincipalnames' in str(props).lower():
                        self._process_users([item])
                    else:
                        self._process_groups([item])
                elif 'gpcpath' in str(props).lower():
                    self._process_gpos([item])
                elif 'blockinheritance' in str(props).lower():
                    self._process_ous([item])
                elif 'functionallevel' in str(props).lower():
                    self._process_domains([item])
                    
            except Exception as e:
                if self.verbose:
                    print(f"[!] Error processing generic item: {e}")
    
    def _clean_name(self, name: str) -> str:
        """Clean and normalize a name.
        
        Removes domain suffix if present (e.g., "USER@DOMAIN.COM" -> "USER")
        
        Args:
            name: Raw name string
            
        Returns:
            Cleaned name
        """
        if not name:
            return ""
        
        # Remove domain suffix
        if '@' in name:
            name = name.split('@')[0]
        
        # Remove trailing $ for computer accounts
        # But keep it in the name for clarity
        
        return name.strip()

