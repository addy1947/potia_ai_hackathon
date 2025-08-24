"""
Policy Engine Tool for Gemini AI Agent
Enforces security and update policies for dependencies
"""

from typing import Dict, List, Optional, Any
from ..utils.tool_registry import Tool
from packaging import version
import re
from datetime import datetime, timedelta


class PolicyEngine(Tool):
    """Tool for enforcing dependency security and update policies"""

    def __init__(self, config: Dict[str, Any]):
        super().__init__(
            name="policy_engine",
            description="Enforce security and update policies for dependency management",
        )
        self.config = config
        # Add required fields for compatibility
        self.id = "policy_engine"
        self.output_schema = {
            "type": "object",
            "properties": {
                "success": {"type": "boolean"},
                "policy_violations": {"type": "integer"},
                "actions_required": {"type": "array"},
                "error": {"type": "string"},
            },
        }
        self.policies = config.get("policies", {})

    def execute(self, **kwargs) -> Any:
        """Execute the policy engine tool"""
        action = kwargs.get("action", "evaluate_security_policy")

        if action == "evaluate_security_policy":
            return self.evaluate_security_policy(kwargs.get("vulnerabilities", []))
        elif action == "evaluate_version_update_policy":
            return self.evaluate_version_update_policy(
                kwargs.get("current_version"),
                kwargs.get("new_version"),
                kwargs.get("package_name"),
            )
        elif action == "evaluate_license_policy":
            return self.evaluate_license_policy(
                kwargs.get("license"), kwargs.get("package_name")
            )
        elif action == "get_policy_summary":
            return self.get_policy_summary()
        else:
            return {
                "error": f"Unknown action: {action}. Supported actions: evaluate_security_policy, evaluate_version_update_policy, evaluate_license_policy, get_policy_summary"
            }

    def evaluate_security_policy(
        self, vulnerabilities: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """
        Evaluate vulnerabilities against security policies

        Args:
            vulnerabilities: List of vulnerability dictionaries

        Returns:
            Policy evaluation results with actions
        """
        security_policy = self.policies.get("security", {})
        max_cvss_score = security_policy.get("max_cvss_score", 7.0)
        require_human_approval = security_policy.get(
            "require_human_approval_for_critical", True
        )
        auto_fix_low_severity = security_policy.get("auto_fix_low_severity", True)

        results = {
            "total_vulnerabilities": len(vulnerabilities),
            "blocked_vulnerabilities": [],
            "auto_fix_vulnerabilities": [],
            "human_review_required": [],
            "allowed_vulnerabilities": [],
            "policy_violations": 0,
            "actions_required": [],
        }

        for vuln in vulnerabilities:
            severity = vuln.get("severity", {})
            cvss_score = severity.get("score", 0)
            severity_level = severity.get("level", "unknown")

            # Check against CVSS score threshold
            if cvss_score > max_cvss_score:
                results["blocked_vulnerabilities"].append(vuln)
                results["policy_violations"] += 1
                results["actions_required"].append(
                    {
                        "action": "block_update",
                        "reason": f"CVSS score {cvss_score} exceeds maximum allowed {max_cvss_score}",
                        "vulnerability": vuln["id"],
                        "package": vuln.get("package_name", "unknown"),
                        "severity": severity_level,
                    }
                )

            # Check for human approval requirements
            elif severity_level in ["critical", "high"] and require_human_approval:
                results["human_review_required"].append(vuln)
                results["actions_required"].append(
                    {
                        "action": "require_human_approval",
                        "reason": f"{severity_level.title()} severity vulnerability requires manual review",
                        "vulnerability": vuln["id"],
                        "package": vuln.get("package_name", "unknown"),
                        "severity": severity_level,
                    }
                )

            # Check for auto-fix eligibility
            elif severity_level in ["low", "medium"] and auto_fix_low_severity:
                results["auto_fix_vulnerabilities"].append(vuln)
                results["actions_required"].append(
                    {
                        "action": "auto_fix",
                        "reason": f"{severity_level.title()} severity vulnerability approved for automatic fixing",
                        "vulnerability": vuln["id"],
                        "package": vuln.get("package_name", "unknown"),
                        "severity": severity_level,
                    }
                )

            else:
                results["allowed_vulnerabilities"].append(vuln)

        return results

    def evaluate_version_update_policy(
        self, current_version: str, new_version: str, package_name: str
    ) -> Dict[str, Any]:
        """
        Evaluate a version update against version update policies

        Args:
            current_version: Current package version
            new_version: Proposed new version
            package_name: Name of the package

        Returns:
            Policy evaluation results
        """
        version_policy = self.policies.get("version_updates", {})
        allow_major = version_policy.get("allow_major_versions", False)
        allow_minor = version_policy.get("allow_minor_versions", True)
        allow_patch = version_policy.get("allow_patch_versions", True)

        try:
            # Parse versions
            current = version.parse(self._normalize_version(current_version))
            new = version.parse(self._normalize_version(new_version))

            # Determine update type
            update_type = self._determine_update_type(current, new)

            result = {
                "package_name": package_name,
                "current_version": current_version,
                "new_version": new_version,
                "update_type": update_type,
                "allowed": False,
                "reason": "",
                "requires_approval": False,
            }

            if update_type == "patch" and allow_patch:
                result["allowed"] = True
                result["reason"] = "Patch updates are allowed by policy"
            elif update_type == "minor" and allow_minor:
                result["allowed"] = True
                result["reason"] = "Minor updates are allowed by policy"
            elif update_type == "major" and allow_major:
                result["allowed"] = True
                result["reason"] = "Major updates are allowed by policy"
            elif update_type == "major" and not allow_major:
                result["allowed"] = False
                result["reason"] = "Major version updates are blocked by policy"
                result["requires_approval"] = True
            elif update_type == "minor" and not allow_minor:
                result["allowed"] = False
                result["reason"] = "Minor version updates are blocked by policy"
                result["requires_approval"] = True
            elif update_type == "patch" and not allow_patch:
                result["allowed"] = False
                result["reason"] = "Patch updates are blocked by policy"
            else:
                result["allowed"] = False
                result["reason"] = (
                    f"Update type '{update_type}' is not explicitly allowed"
                )

            return result

        except Exception as e:
            return {
                "package_name": package_name,
                "current_version": current_version,
                "new_version": new_version,
                "allowed": False,
                "reason": f"Version comparison failed: {str(e)}",
                "requires_approval": True,
                "error": True,
            }

    def evaluate_license_policy(self, license_info: str) -> Dict[str, Any]:
        """
        Evaluate a license against license policies

        Args:
            license_info: License string (e.g., "MIT", "GPL-3.0")

        Returns:
            License policy evaluation results
        """
        allowed_licenses = self.policies.get("allowed_licenses", [])
        blocked_licenses = self.policies.get("blocked_licenses", [])

        # Normalize license string
        normalized_license = license_info.strip().upper()

        result = {
            "license": license_info,
            "normalized_license": normalized_license,
            "allowed": True,
            "reason": "",
            "policy_match": None,
        }

        # Check blocked licenses first (more restrictive)
        for blocked in blocked_licenses:
            if blocked.upper() in normalized_license:
                result["allowed"] = False
                result["reason"] = (
                    f"License '{license_info}' matches blocked license '{blocked}'"
                )
                result["policy_match"] = blocked
                return result

        # Check allowed licenses
        if allowed_licenses:  # If allowed list is defined, use it
            license_allowed = False
            for allowed in allowed_licenses:
                if allowed.upper() in normalized_license:
                    license_allowed = True
                    result["policy_match"] = allowed
                    break

            if not license_allowed:
                result["allowed"] = False
                result["reason"] = (
                    f"License '{license_info}' is not in the allowed licenses list"
                )
            else:
                result["reason"] = f"License '{license_info}' is explicitly allowed"
        else:
            # No allowed list defined, allow by default (unless blocked)
            result["reason"] = "No license restrictions defined, allowing by default"

        return result

    def evaluate_bulk_update_policy(
        self, updates: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """
        Evaluate a bulk set of updates against policies

        Args:
            updates: List of update dictionaries with package info

        Returns:
            Bulk policy evaluation results
        """
        results = {
            "total_updates": len(updates),
            "allowed_updates": [],
            "blocked_updates": [],
            "requires_approval": [],
            "policy_violations": 0,
            "summary": {},
        }

        update_types = {"major": 0, "minor": 0, "patch": 0}

        for update in updates:
            # Evaluate version policy
            version_result = self.evaluate_version_update_policy(
                update.get("current_version", "0.0.0"),
                update.get("new_version", "0.0.0"),
                update.get("package_name", "unknown"),
            )

            # Evaluate license policy if available
            license_result = None
            if "license" in update:
                license_result = self.evaluate_license_policy(update["license"])

            # Evaluate security policy if vulnerabilities are present
            security_result = None
            if "vulnerabilities" in update:
                security_result = self.evaluate_security_policy(
                    update["vulnerabilities"]
                )

            # Combine results
            combined_result = {
                "package_name": update.get("package_name"),
                "current_version": update.get("current_version"),
                "new_version": update.get("new_version"),
                "version_policy": version_result,
                "license_policy": license_result,
                "security_policy": security_result,
                "overall_allowed": True,
                "reasons": [],
            }

            # Check version policy
            if not version_result.get("allowed", False):
                combined_result["overall_allowed"] = False
                combined_result["reasons"].append(
                    version_result.get("reason", "Version policy violation")
                )

                if version_result.get("requires_approval", False):
                    results["requires_approval"].append(combined_result)
                else:
                    results["blocked_updates"].append(combined_result)
                    results["policy_violations"] += 1

            # Check license policy
            if license_result and not license_result.get("allowed", True):
                combined_result["overall_allowed"] = False
                combined_result["reasons"].append(
                    license_result.get("reason", "License policy violation")
                )
                results["blocked_updates"].append(combined_result)
                results["policy_violations"] += 1

            # Check security policy
            if security_result and security_result.get("policy_violations", 0) > 0:
                combined_result["overall_allowed"] = False
                combined_result["reasons"].append("Security policy violations detected")
                results["blocked_updates"].append(combined_result)
                results["policy_violations"] += security_result["policy_violations"]

            # If all policies pass, allow the update
            if combined_result["overall_allowed"]:
                results["allowed_updates"].append(combined_result)

                # Count update types for summary
                update_type = version_result.get("update_type", "unknown")
                if update_type in update_types:
                    update_types[update_type] += 1

        # Generate summary
        results["summary"] = {
            "allowed_count": len(results["allowed_updates"]),
            "blocked_count": len(results["blocked_updates"]),
            "requires_approval_count": len(results["requires_approval"]),
            "update_types": update_types,
            "policy_compliance_rate": (
                (len(results["allowed_updates"]) / len(updates) * 100)
                if updates
                else 100
            ),
        }

        return results

    def generate_policy_report(
        self, evaluation_results: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Generate a human-readable policy evaluation report
        """
        report = {
            "timestamp": datetime.now().isoformat(),
            "policy_summary": evaluation_results.get("summary", {}),
            "recommendations": [],
            "action_items": [],
            "compliance_status": "unknown",
        }

        # Determine overall compliance status
        total_updates = evaluation_results.get("total_updates", 0)
        allowed_count = evaluation_results.get("summary", {}).get("allowed_count", 0)
        blocked_count = evaluation_results.get("summary", {}).get("blocked_count", 0)

        if total_updates == 0:
            report["compliance_status"] = "no_updates"
        elif blocked_count == 0:
            report["compliance_status"] = "fully_compliant"
        elif allowed_count > blocked_count:
            report["compliance_status"] = "mostly_compliant"
        else:
            report["compliance_status"] = "non_compliant"

        # Generate recommendations
        if blocked_count > 0:
            report["recommendations"].append(
                f"{blocked_count} updates blocked by policy. Review and consider policy adjustments if needed."
            )

        approval_count = evaluation_results.get("summary", {}).get(
            "requires_approval_count", 0
        )
        if approval_count > 0:
            report["recommendations"].append(
                f"{approval_count} updates require manual approval. Please review these changes."
            )

        if allowed_count > 0:
            report["recommendations"].append(
                f"{allowed_count} updates approved for automatic processing."
            )

        # Generate action items
        for blocked in evaluation_results.get("blocked_updates", []):
            report["action_items"].append(
                {
                    "type": "policy_violation",
                    "package": blocked.get("package_name"),
                    "issue": blocked.get("reasons", ["Unknown policy violation"])[0],
                    "action": "Review policy or exclude package from automated updates",
                }
            )

        for approval_needed in evaluation_results.get("requires_approval", []):
            report["action_items"].append(
                {
                    "type": "manual_review",
                    "package": approval_needed.get("package_name"),
                    "issue": "Requires manual approval",
                    "action": "Review and approve/deny the update manually",
                }
            )

        return report

    def _determine_update_type(
        self, current: version.Version, new: version.Version
    ) -> str:
        """Determine if an update is major, minor, or patch"""
        if new.major > current.major:
            return "major"
        elif new.minor > current.minor:
            return "minor"
        elif new.micro > current.micro:
            return "patch"
        else:
            return "same"

    def _normalize_version(self, version_str: str) -> str:
        """Normalize version string for parsing"""
        # Remove common version prefixes and constraints
        normalized = re.sub(r"^[~^>=<]+", "", version_str)
        normalized = re.split(r"\s+\|\|", normalized)[0]
        return normalized.strip()

    def run(self, **kwargs) -> Dict[str, Any]:
        """
        Main run method for the policy engine tool
        """
        operation = kwargs.get("operation")

        if operation == "evaluate_security":
            return self.evaluate_security_policy(kwargs["vulnerabilities"])
        elif operation == "evaluate_version_update":
            return self.evaluate_version_update_policy(
                kwargs["current_version"], kwargs["new_version"], kwargs["package_name"]
            )
        elif operation == "evaluate_license":
            return self.evaluate_license_policy(kwargs["license"])
        elif operation == "evaluate_bulk_updates":
            return self.evaluate_bulk_update_policy(kwargs["updates"])
        elif operation == "generate_report":
            return self.generate_policy_report(kwargs["evaluation_results"])
        else:
            return {"error": f"Unknown operation: {operation}"}
