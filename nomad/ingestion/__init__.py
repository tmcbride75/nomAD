"""
nomAD Ingestion Module
======================

Data loaders for various AD data sources.

Supported Sources:
- BloodHound/SharpHound JSON exports
- LDAP live collection (using ldap3)
- CSV/custom formats (extensible)

Design Philosophy:
- All loaders produce an ADGraph
- Loaders are composable - multiple sources can be merged
- LDAP collection includes ACL enumeration for better attack path coverage
"""

from .bloodhound_loader import BloodHoundLoader
from .ldap_loader import LDAPCollector

