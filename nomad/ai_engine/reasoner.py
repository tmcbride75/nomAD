"""
AI Reasoner Module
==================

Orchestrates AI reasoning over AD analysis results.

This module:
- Prepares prompts from analysis summaries
- Sends requests to the LLM
- Parses responses into structured data
- Enhances attack paths with AI commentary

Design Decisions:
-----------------
1. Uses structured JSON prompts for consistent responses
2. Gracefully handles malformed AI responses
3. Provides fallback analysis when AI is unavailable
4. Separates prompt templates for maintainability
"""

import json
import re
from typing import Optional
from dataclasses import dataclass, field

from .llm_client import LLMClient
from ..model.schemas import AttackPath, RiskLevel, EnvironmentStats
from ..analysis.summarizer import AnalysisSummarizer
from ..model.graph_builder import ADGraph
from ..config import LLMConfig


@dataclass
class AIAnalysisResult:
    """Container for AI-enhanced analysis results.
    
    Attributes:
        overall_assessment: High-level risk assessment
        top_actions: List of immediate recommended actions
        path_analyses: Per-path AI analysis
        general_recommendations: Overall recommendations
        raw_response: Raw AI response for debugging
    """
    overall_assessment: str = ""
    top_actions: list = field(default_factory=list)
    path_analyses: list = field(default_factory=list)
    general_recommendations: list = field(default_factory=list)
    raw_response: str = ""


class AIReasoner:
    """Orchestrates AI reasoning for AD analysis.
    
    Usage:
        reasoner = AIReasoner(llm_config)
        
        # Analyze all paths
        ai_result = reasoner.analyze_paths(graph, attack_paths)
        
        # Enhance paths with AI commentary
        enhanced_paths = reasoner.enhance_paths(attack_paths, ai_result)
    
    The reasoner:
    1. Creates summaries using AnalysisSummarizer
    2. Sends prompts to the LLM
    3. Parses structured responses
    4. Attaches findings to AttackPath objects
    """
    
    # System prompt for AD security analysis
    SYSTEM_PROMPT = """You are an expert Active Directory security analyst and penetration tester.
You are analyzing an AD environment for security vulnerabilities and attack paths.

Your role is to:
1. Assess the risk of discovered attack paths
2. Explain why specific paths are dangerous in plain English
3. Identify the misconfigurations that enable each attack
4. Provide specific, actionable mitigation recommendations

Guidelines:
- Be specific and technical but explain concepts clearly
- Focus on real-world exploitability
- Prioritize recommendations by impact and ease of implementation
- Consider both the attacker's perspective and defensive measures

Always respond with valid JSON when requested."""
    
    def __init__(self, config: Optional[LLMConfig] = None):
        """Initialize the AI reasoner.
        
        Args:
            config: LLM configuration (uses defaults if None)
        """
        self.config = config or LLMConfig()
        self.client = LLMClient(self.config) if self.config.enabled else None
    
    @property
    def is_available(self) -> bool:
        """Check if AI reasoning is available."""
        return self.client is not None and self.client.is_available
    
    def analyze_paths(
        self,
        graph: ADGraph,
        attack_paths: list[AttackPath],
        environment_stats: Optional[EnvironmentStats] = None
    ) -> AIAnalysisResult:
        """Perform AI analysis on discovered attack paths.
        
        Args:
            graph: ADGraph with environment data
            attack_paths: List of discovered attack paths
            environment_stats: Pre-computed environment statistics
            
        Returns:
            AIAnalysisResult with AI-enhanced findings
        """
        if not self.is_available:
            return self._create_fallback_analysis(attack_paths)
        
        # Create summary for the AI
        summarizer = AnalysisSummarizer(graph, attack_paths, environment_stats)
        summary = summarizer.create_full_summary(max_paths=15)
        
        try:
            # Send to LLM
            response = self.client.complete(
                prompt=summary,
                system_prompt=self.SYSTEM_PROMPT,
                json_mode=True
            )
            
            # Parse response
            return self._parse_analysis_response(response.content)
            
        except Exception as e:
            print(f"[!] AI analysis error: {e}")
            return self._create_fallback_analysis(attack_paths)
    
    def analyze_single_path(
        self,
        graph: ADGraph,
        path: AttackPath
    ) -> dict:
        """Get detailed AI analysis for a single path.
        
        Args:
            graph: ADGraph with environment data
            path: AttackPath to analyze
            
        Returns:
            Dictionary with AI analysis for this path
        """
        if not self.is_available:
            return self._create_fallback_path_analysis(path)
        
        # Create detailed summary for this path
        summarizer = AnalysisSummarizer(graph, [path])
        detail_summary = summarizer.get_path_detail_summary(path)
        
        prompt = f"""{detail_summary}

Please analyze this specific attack path and respond with JSON:
{{
    "risk_assessment": "detailed risk assessment",
    "exploitation_steps": ["step 1", "step 2", ...],
    "prerequisites": ["what attacker needs"],
    "detection_opportunities": ["how defenders might detect this"],
    "mitigations": ["specific mitigation 1", "specific mitigation 2"],
    "additional_notes": "any other relevant information"
}}"""
        
        try:
            response = self.client.complete(
                prompt=prompt,
                system_prompt=self.SYSTEM_PROMPT,
                json_mode=True
            )
            
            return json.loads(response.content)
            
        except Exception as e:
            print(f"[!] Single path analysis error: {e}")
            return self._create_fallback_path_analysis(path)
    
    def enhance_paths(
        self,
        attack_paths: list[AttackPath],
        ai_result: AIAnalysisResult
    ) -> list[AttackPath]:
        """Enhance attack paths with AI commentary.
        
        Attaches AI-generated commentary and mitigations to each path.
        
        Args:
            attack_paths: Original attack paths
            ai_result: AI analysis result
            
        Returns:
            List of paths with AI fields populated
        """
        # Build lookup by path ID
        path_analyses = {pa.get('path_id'): pa for pa in ai_result.path_analyses}
        
        for path in attack_paths:
            analysis = path_analyses.get(path.id)
            
            if analysis:
                path.ai_risk_commentary = analysis.get('risk_commentary', '')
                path.ai_explanation = analysis.get('exploitation_requirements', '')
                path.ai_mitigations = analysis.get('mitigations', [])
                
                # Update risk level if AI suggests different
                suggested_level = analysis.get('confirmed_risk_level', '')
                if suggested_level:
                    try:
                        path.risk_level = RiskLevel(suggested_level)
                    except ValueError:
                        pass
            else:
                # Generate generic commentary based on path characteristics
                path.ai_risk_commentary = self._generate_generic_commentary(path)
                path.ai_mitigations = self._generate_generic_mitigations(path)
        
        return attack_paths
    
    def _parse_analysis_response(self, content: str) -> AIAnalysisResult:
        """Parse the AI response JSON.
        
        Handles various response formats and malformed JSON.
        
        Args:
            content: Raw response content
            
        Returns:
            Parsed AIAnalysisResult
        """
        result = AIAnalysisResult(raw_response=content)
        
        try:
            # Try direct JSON parse first
            data = json.loads(content)
        except json.JSONDecodeError:
            # Try to extract JSON from markdown code blocks
            json_match = re.search(r'```(?:json)?\s*([\s\S]*?)```', content)
            if json_match:
                try:
                    data = json.loads(json_match.group(1))
                except json.JSONDecodeError:
                    return result
            else:
                return result
        
        # Extract fields
        result.overall_assessment = data.get('overall_risk_assessment', '')
        result.top_actions = data.get('top_immediate_actions', [])
        result.path_analyses = data.get('path_analyses', [])
        result.general_recommendations = data.get('general_recommendations', [])
        
        return result
    
    def _create_fallback_analysis(self, attack_paths: list[AttackPath]) -> AIAnalysisResult:
        """Create fallback analysis when AI is unavailable.
        
        Uses rule-based logic to generate basic recommendations.
        
        Args:
            attack_paths: Attack paths to analyze
            
        Returns:
            AIAnalysisResult with rule-based analysis
        """
        result = AIAnalysisResult()
        
        # Generate overall assessment
        critical_count = sum(1 for p in attack_paths if p.risk_level == RiskLevel.CRITICAL)
        high_count = sum(1 for p in attack_paths if p.risk_level == RiskLevel.HIGH)
        
        if critical_count > 0:
            result.overall_assessment = (
                f"CRITICAL: Found {critical_count} critical attack paths that require immediate attention. "
                f"These paths allow direct escalation to Domain Admin or equivalent privileges."
            )
        elif high_count > 0:
            result.overall_assessment = (
                f"HIGH RISK: Found {high_count} high-risk attack paths. "
                "Review and remediate these paths to improve security posture."
            )
        else:
            result.overall_assessment = (
                "Moderate risk level. Some attack paths exist but require multiple steps. "
                "Review paths and apply principle of least privilege."
            )
        
        # Generate top actions
        result.top_actions = [
            "Review and minimize Domain Admin group membership",
            "Audit ACL permissions on high-value objects",
            "Implement least-privilege access model",
            "Enable advanced auditing for privilege changes",
            "Review service account permissions and SPNs"
        ]
        
        # Generate path analyses
        for path in attack_paths[:10]:  # Top 10 paths
            analysis = {
                'path_id': path.id,
                'confirmed_risk_level': path.risk_level.value,
                'risk_commentary': self._generate_generic_commentary(path),
                'exploitation_requirements': "Network access and valid credentials for starting user",
                'mitigations': self._generate_generic_mitigations(path)
            }
            result.path_analyses.append(analysis)
        
        # General recommendations
        result.general_recommendations = [
            "Implement tiered administration model",
            "Deploy LAPS for local administrator passwords",
            "Enable Protected Users group for privileged accounts",
            "Regular review of group memberships",
            "Implement just-in-time (JIT) access for admin tasks"
        ]
        
        return result
    
    def _create_fallback_path_analysis(self, path: AttackPath) -> dict:
        """Create fallback analysis for a single path.
        
        Args:
            path: Path to analyze
            
        Returns:
            Dictionary with basic analysis
        """
        return {
            'risk_assessment': f"This is a {path.risk_level.value.lower()}-risk path that could lead to {path.privilege_gain}.",
            'exploitation_steps': [
                "Obtain credentials for the starting account",
                "Follow the attack chain steps in sequence",
                "Each step may require different tools or techniques"
            ],
            'prerequisites': [
                "Network access to the target domain",
                "Valid credentials for the starting account",
                "Tools for exploitation (Mimikatz, Rubeus, etc.)"
            ],
            'detection_opportunities': [
                "Monitor for unusual authentication patterns",
                "Alert on privilege escalation events",
                "Track changes to sensitive group memberships"
            ],
            'mitigations': self._generate_generic_mitigations(path),
            'additional_notes': "Review each step in the chain to identify the weakest link for remediation."
        }
    
    def _generate_generic_commentary(self, path: AttackPath) -> str:
        """Generate generic risk commentary for a path.
        
        Args:
            path: AttackPath to comment on
            
        Returns:
            Commentary string
        """
        edge_types = [e.edge_type.value for e in path.edges]
        
        commentary_parts = [
            f"This {path.estimated_steps}-step attack path leads to {path.privilege_gain}."
        ]
        
        # Add specific comments based on edge types
        if 'GenericAll' in edge_types:
            commentary_parts.append(
                "The GenericAll permission grants full control and is highly dangerous."
            )
        
        if 'GetChangesAll' in edge_types:
            commentary_parts.append(
                "This path enables DCSync attacks to dump all domain credentials."
            )
        
        if 'ForceChangePassword' in edge_types:
            commentary_parts.append(
                "Password reset capability allows immediate account takeover."
            )
        
        if 'WriteDacl' in edge_types or 'WriteOwner' in edge_types:
            commentary_parts.append(
                "ACL modification rights allow the attacker to grant themselves additional permissions."
            )
        
        if path.properties.get('from_authenticated_user'):
            commentary_parts.append(
                "This path is exploitable from the authenticated user's context."
            )
        
        return " ".join(commentary_parts)
    
    def _generate_generic_mitigations(self, path: AttackPath) -> list[str]:
        """Generate generic mitigations for a path.
        
        Args:
            path: AttackPath to generate mitigations for
            
        Returns:
            List of mitigation recommendations
        """
        mitigations = set()
        
        edge_types = {e.edge_type for e in path.edges}
        
        mitigation_map = {
            'GenericAll': "Remove unnecessary GenericAll permissions from non-admin principals",
            'GenericWrite': "Review and restrict GenericWrite permissions using least-privilege",
            'WriteDacl': "Remove WriteDacl rights from non-admin principals",
            'WriteOwner': "Restrict WriteOwner permissions to designated admins only",
            'ForceChangePassword': "Limit password reset capabilities to help desk accounts",
            'AddMember': "Implement approval workflow for group membership changes",
            'MemberOf': "Review group nesting and reduce unnecessary memberships",
            'AdminTo': "Audit local admin group memberships and implement LAPS",
            'CanRDP': "Restrict RDP access and implement jump server architecture",
            'HasSession': "Avoid admin logons to untrusted systems",
            'GetChangesAll': "Remove DCSync rights from non-DC principals",
            'ReadLAPSPassword': "Restrict LAPS password read access",
            'AllowedToDelegate': "Review delegation settings and prefer constrained delegation",
            'AddKeyCredentialLink': "Restrict msDS-KeyCredentialLink attribute modification",
        }
        
        for edge_type in edge_types:
            edge_name = edge_type.value
            if edge_name in mitigation_map:
                mitigations.add(mitigation_map[edge_name])
        
        # Add general recommendations
        mitigations.add("Enable Protected Users group for privileged accounts")
        mitigations.add("Implement tiered administration model")
        
        return list(mitigations)[:7]  # Limit to top 7
    
    def get_mitigation_priority(
        self,
        graph: ADGraph,
        attack_paths: list[AttackPath]
    ) -> str:
        """Get AI-recommended mitigation priorities.
        
        Args:
            graph: ADGraph with environment data
            attack_paths: List of attack paths
            
        Returns:
            Mitigation priority summary
        """
        if not self.is_available:
            return self._get_fallback_mitigation_priority(attack_paths)
        
        summarizer = AnalysisSummarizer(graph, attack_paths)
        mitigation_summary = summarizer.create_mitigation_summary()
        
        prompt = f"""{mitigation_summary}

Based on this analysis, provide a prioritized list of mitigations.
Respond with JSON:
{{
    "priority_1_mitigations": [
        {{"action": "specific action", "impact": "what it fixes", "effort": "low/medium/high"}}
    ],
    "priority_2_mitigations": [...],
    "priority_3_mitigations": [...],
    "quick_wins": ["easy fixes with high impact"]
}}"""
        
        try:
            response = self.client.complete(
                prompt=prompt,
                system_prompt=self.SYSTEM_PROMPT,
                json_mode=True
            )
            return response.content
        except Exception as e:
            return self._get_fallback_mitigation_priority(attack_paths)
    
    def _get_fallback_mitigation_priority(self, attack_paths: list[AttackPath]) -> str:
        """Generate fallback mitigation priority.
        
        Args:
            attack_paths: Attack paths to analyze
            
        Returns:
            JSON string with mitigation priorities
        """
        # Count edge types
        edge_counts = {}
        for path in attack_paths:
            for edge in path.edges:
                edge_name = edge.edge_type.value
                edge_counts[edge_name] = edge_counts.get(edge_name, 0) + 1
        
        # Sort by frequency
        sorted_edges = sorted(edge_counts.items(), key=lambda x: x[1], reverse=True)
        
        result = {
            "priority_1_mitigations": [],
            "priority_2_mitigations": [],
            "priority_3_mitigations": [],
            "quick_wins": []
        }
        
        # Map top edges to mitigations
        for i, (edge_type, count) in enumerate(sorted_edges[:3]):
            result["priority_1_mitigations"].append({
                "action": f"Audit and restrict {edge_type} permissions",
                "impact": f"Affects {count} attack paths",
                "effort": "medium"
            })
        
        for i, (edge_type, count) in enumerate(sorted_edges[3:6]):
            result["priority_2_mitigations"].append({
                "action": f"Review {edge_type} relationships",
                "impact": f"Affects {count} attack paths",
                "effort": "low"
            })
        
        result["quick_wins"] = [
            "Enable Protected Users group",
            "Remove stale admin accounts",
            "Audit service account permissions"
        ]
        
        return json.dumps(result, indent=2)
    
    def generate_attack_chain_remediation(
        self,
        attack_chains: list[dict],
        compromised_users: list[str],
        domain: str
    ) -> dict:
        """Generate AI-powered remediation for successful attack chains.
        
        Args:
            attack_chains: List of executed attack chain steps
            compromised_users: List of compromised user accounts
            domain: Domain name
            
        Returns:
            Dictionary with attack summary and remediation steps
        """
        if not self.is_available:
            return self._generate_fallback_remediation(attack_chains, compromised_users)
        
        # Build attack chain summary for AI - be explicit about what happened
        chain_description = []
        for i, step in enumerate(attack_chains, 1):
            source = step.get('source', 'unknown')
            target = step.get('target', 'unknown')
            permission = step.get('permission', 'unknown')
            method = step.get('method', 'unknown')
            via_group = step.get('via_group', '')
            attack_type = step.get('attack_type', 'Unknown')
            
            if attack_type == 'GroupEscalation':
                chain_description.append(
                    f"Step {i}: {source} joined the '{target}' group by exploiting "
                    f"their membership in '{via_group}' which has {permission} over {target}"
                )
            elif attack_type == 'PasswordChange':
                if via_group:
                    chain_description.append(
                        f"Step {i}: {source} changed {target}'s password using {permission} permission (inherited from {via_group})"
                    )
                else:
                    chain_description.append(
                        f"Step {i}: {source} changed {target}'s password using {permission} permission"
                    )
            else:
                chain_description.append(
                    f"Step {i}: {source} → {target} via {permission} ({method})"
                )
        
        prompt = f"""A successful Active Directory attack chain was executed on domain "{domain}".

ATTACK CHAIN EXECUTED:
{chr(10).join(chain_description)}

COMPROMISED ACCOUNTS:
{', '.join(compromised_users)}

Provide a detailed security analysis in this exact JSON format:
{{
    "attack_summary": "3-4 sentence explanation of how an attacker exploited this chain. Explain the attack flow and why it worked. Mention the specific misconfigurations that enabled each step.",
    "attack_impact": "Describe what an attacker could do with these compromised accounts (data exfiltration, lateral movement, persistence, etc.)",
    "root_cause": "Identify the root cause misconfigurations that enabled this attack chain",
    "risk_level": "Critical/High/Medium/Low",
    "immediate_actions": [
        "URGENT: First thing to do right now",
        "URGENT: Second immediate action",
        "URGENT: Third immediate action"
    ],
    "remediation_steps": [
        {{
            "priority": 1,
            "action": "Specific remediation action with exact steps",
            "reason": "Why this fixes the vulnerability",
            "command_example": "PowerShell or AD command if applicable"
        }},
        {{
            "priority": 2,
            "action": "Second remediation action",
            "reason": "Why this is important",
            "command_example": "Command example if applicable"
        }}
    ],
    "prevention_measures": [
        "Long-term security improvement 1",
        "Long-term security improvement 2",
        "Long-term security improvement 3"
    ],
    "detection_recommendations": [
        "How to detect this attack in the future",
        "Logging and monitoring recommendations"
    ]
}}

Be specific and actionable. Reference the actual accounts and groups involved."""

        try:
            response = self.client.complete(
                prompt=prompt,
                system_prompt=self.SYSTEM_PROMPT,
                json_mode=True
            )
            
            # Parse response
            try:
                result = json.loads(response.content)
            except json.JSONDecodeError:
                # Try to extract JSON from response
                json_match = re.search(r'\{[\s\S]*\}', response.content)
                if json_match:
                    result = json.loads(json_match.group())
                else:
                    return self._generate_fallback_remediation(attack_chains, compromised_users)
            
            return result
            
        except Exception as e:
            return self._generate_fallback_remediation(attack_chains, compromised_users)
    
    def _generate_fallback_remediation(
        self,
        attack_chains: list[dict],
        compromised_users: list[str]
    ) -> dict:
        """Generate rule-based remediation when AI is unavailable.
        
        Args:
            attack_chains: Attack chain steps
            compromised_users: Compromised accounts
            
        Returns:
            Remediation dictionary
        """
        # Detect attack patterns
        methods_used = set()
        permissions_abused = set()
        
        for step in attack_chains:
            methods_used.add(step.get('method', 'unknown'))
            permissions_abused.add(step.get('permission', 'unknown'))
        
        # Build remediation based on patterns
        remediation_steps = []
        
        if 'Shadow Credentials' in str(methods_used):
            remediation_steps.append({
                "priority": 1,
                "action": "Restrict msDS-KeyCredentialLink attribute modification",
                "reason": "Prevents Shadow Credentials attacks for credential theft"
            })
        
        if 'GenericWrite' in permissions_abused or 'GenericAll' in permissions_abused:
            remediation_steps.append({
                "priority": 1,
                "action": "Audit and remove excessive GenericWrite/GenericAll permissions",
                "reason": "These permissions allow attackers to modify objects and steal credentials"
            })
        
        if any('group' in str(step).lower() for step in attack_chains):
            remediation_steps.append({
                "priority": 2,
                "action": "Review group membership modification permissions",
                "reason": "Attackers leveraged group memberships to gain inherited permissions"
            })
        
        # Add default recommendations
        remediation_steps.extend([
            {
                "priority": 2,
                "action": "Implement tiered administration model",
                "reason": "Limits lateral movement between security tiers"
            },
            {
                "priority": 3,
                "action": "Enable Protected Users group for privileged accounts",
                "reason": "Prevents credential caching and certain attack techniques"
            }
        ])
        
        # Build attack summary
        chain_str = " → ".join([f"{s.get('source', '?')} → {s.get('target', '?')}" for s in attack_chains[:3]])
        
        # Identify intermediate groups used
        groups_used = [s.get('via_group', '') for s in attack_chains if s.get('via_group')]
        
        attack_summary = (
            f"Attacker successfully compromised {len(compromised_users)} accounts by exploiting "
            f"a chain of Active Directory permission misconfigurations. "
            f"The attack leveraged {', '.join(permissions_abused)} permissions "
        )
        if groups_used:
            attack_summary += f"through group memberships ({', '.join(set(groups_used))}). "
        else:
            attack_summary += "to pivot between accounts. "
        attack_summary += f"Attack methods employed: {', '.join(methods_used)}."
        
        return {
            "attack_summary": attack_summary,
            "attack_impact": (
                f"With {len(compromised_users)} compromised accounts, an attacker could: "
                "read sensitive data, access internal systems, create backdoor accounts, "
                "deploy malware, and potentially achieve domain dominance."
            ),
            "root_cause": (
                "Excessive permissions granted to groups and users violating least-privilege principle. "
                f"Specifically: {', '.join(permissions_abused)} permissions allowing account takeover."
            ),
            "risk_level": "Critical" if len(compromised_users) > 2 else "High",
            "remediation_steps": remediation_steps[:5],
            "immediate_actions": [
                f"URGENT: Reset passwords for compromised accounts: {', '.join(compromised_users)}",
                "URGENT: Review and revoke excessive ACL permissions on affected accounts",
                "URGENT: Check for persistence mechanisms (new accounts, scheduled tasks, GPO changes)",
                "URGENT: Enable advanced auditing (Event IDs 4728, 4738, 5136)"
            ],
            "prevention_measures": [
                "Implement tiered administration model",
                "Regular ACL audits using BloodHound or similar tools",
                "Enable Protected Users group for privileged accounts",
                "Apply principle of least privilege across all accounts"
            ],
            "detection_recommendations": [
                "Monitor Event ID 4728 (member added to security group)",
                "Monitor Event ID 4738 (user account changed)",
                "Alert on msDS-KeyCredentialLink modifications",
                "Deploy honeypot accounts to detect enumeration"
            ]
        }

