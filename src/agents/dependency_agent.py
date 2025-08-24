"""
Automated Dependency Security & Management Agent using Gemini AI
"""

import os
import yaml
from typing import Dict, List, Optional, Any
from dotenv import load_dotenv
from datetime import datetime

# Import our custom Gemini client and tool registry
from ..utils.gemini_client import GeminiClient
from ..utils.tool_registry import ToolRegistry, example_tool_registry

# Import our custom tools
from ..tools.github_tool import GitHubTool
from ..tools.vulnerability_scanner import VulnerabilityScanner
from ..tools.dependency_parser import DependencyParser
from ..tools.dependency_updater import DependencyUpdater
from ..tools.policy_engine import PolicyEngine
from ..tools.notification_tool import NotificationTool
from ..tools.reporting_tool import ReportingTool

# Load environment variables
load_dotenv()


class DependencySecurityAgent:
    """
    Main agent class that orchestrates dependency security management
    """

    def __init__(self, config_path: str = "config.yaml"):
        """Initialize the agent with configuration"""
        self.config = self._load_config(config_path)
        self.gemini_client = self._setup_gemini_client()
        self.tools = self._setup_tools()

    def _load_config(self, config_path: str) -> Dict[str, Any]:
        """Load configuration from YAML file"""
        try:
            with open(config_path, "r") as file:
                return yaml.safe_load(file)
        except FileNotFoundError:
            print(f"Configuration file {config_path} not found. Using defaults.")
            return self._get_default_config()

    def _get_default_config(self) -> Dict[str, Any]:
        """Return default configuration"""
        return {
            "policies": {
                "version_updates": {
                    "allow_major_versions": False,
                    "allow_minor_versions": True,
                    "allow_patch_versions": True,
                },
                "security": {
                    "max_cvss_score": 7.0,
                    "require_human_approval_for_critical": True,
                    "auto_fix_low_severity": True,
                },
            },
            "package_managers": ["npm", "pip", "maven", "gradle"],
            "notifications": {"slack": {"enabled": True}},
        }

    def _setup_gemini_client(self) -> GeminiClient:
        """Setup Gemini client with API key"""
        # Check for Gemini API key
        if not os.getenv("GEMINI_API_KEY"):
            raise ValueError("GEMINI_API_KEY environment variable is required")

        return GeminiClient()

    def _setup_tools(self) -> ToolRegistry:
        """Setup custom tools for the agent"""
        tools = ToolRegistry()

        # Add our custom tools
        tools.add_tool(GitHubTool(config=self.config))
        tools.add_tool(VulnerabilityScanner(config=self.config))
        tools.add_tool(DependencyParser(config=self.config))
        tools.add_tool(DependencyUpdater(config=self.config))
        tools.add_tool(PolicyEngine(config=self.config))
        tools.add_tool(NotificationTool(config=self.config))
        tools.add_tool(ReportingTool(config=self.config))

        return tools

    def scan_dependencies(
        self, repository: str, branch: str = "main"
    ) -> Dict[str, Any]:
        """
        Scan dependencies in a repository for security vulnerabilities
        """
        prompt = f"""
        Analyze the dependencies in repository {repository} (branch: {branch}) for security vulnerabilities.
        
        Please:
        1. Identify all dependencies and their versions
        2. Check for known security vulnerabilities
        3. Assess license compliance
        4. Provide recommendations for updates
        5. Generate a security score
        
        Repository: {repository}
        Branch: {branch}
        """

        # Get tool descriptions for context
        tool_descriptions = self.tools.list_tools()

        # Run analysis through Gemini
        result = self.gemini_client.run(prompt, tool_descriptions)

        if result["state"] == "COMPLETE":
            return {
                "status": "success",
                "repository": repository,
                "branch": branch,
                "analysis": result["final_output"]["response"],
                "security_score": self._extract_security_score(
                    result["final_output"]["response"]
                ),
            }
        else:
            return {
                "status": "error",
                "error": result.get("error", "Unknown error"),
                "repository": repository,
                "branch": branch,
            }

    def analyze_repository(
        self, owner: str, repo: str, branch: str = "main"
    ) -> Dict[str, Any]:
        """
        Analyze a repository for dependency security issues
        This is an alias for scan_dependencies to maintain compatibility
        """
        repository = f"{owner}/{repo}"
        return self.scan_dependencies(repository, branch)

    def emergency_response(self, cve_id: str) -> Dict[str, Any]:
        """
        Handle emergency CVE response
        This is an alias for emergency_scan to maintain compatibility
        """
        return self.emergency_scan(cve_id=cve_id)

    def run_scheduled_scan(self) -> Dict[str, Any]:
        """
        Run scheduled scan for all monitored repositories
        """
        config = self.config
        monitored_repos = config.get("repositories", {}).get("monitored", [])

        if not monitored_repos:
            return {
                "status": "error",
                "error": "No repositories configured for monitoring",
            }

        results = []
        for repo_config in monitored_repos:
            owner = repo_config.get("owner")
            repo = repo_config.get("repo")
            branch = repo_config.get("branch", "main")

            if owner and repo:
                result = self.scan_dependencies(f"{owner}/{repo}", branch)
                results.append(result)

        return {
            "status": "success",
            "scan_type": "scheduled",
            "repositories_scanned": len(results),
            "results": results,
            "final_output": {
                "total_repositories": len(results),
                "successful_scans": len(
                    [r for r in results if r["status"] == "success"]
                ),
                "failed_scans": len([r for r in results if r["status"] == "error"]),
            },
        }

    def generate_security_report(
        self, repo_list: List[Dict[str, str]]
    ) -> Dict[str, Any]:
        """
        Generate security report for specified repositories
        """
        if not repo_list:
            return {"status": "error", "error": "No repositories specified for report"}

        repo_names = [f"{repo['owner']}/{repo['repo']}" for repo in repo_list]
        return self.generate_report(repo_names, "comprehensive")

    def execute_dependency_update_workflow(
        self, owner: str, repo: str, branch: str = "main", update_type: str = "patch"
    ) -> Dict[str, Any]:
        """
        Complete workflow: clone repo, update dependencies, create PR, and deploy

        Args:
            owner: Repository owner
            repo: Repository name
            branch: Base branch (default: main)
            update_type: Type of updates to apply (patch, minor, major)

        Returns:
            Dictionary containing workflow execution results
        """
        try:
            repository = f"{owner}/{repo}"

            # Step 1: Clone repository locally
            clone_result = self.tools.get_tool("github_tool").execute(
                action="clone_repository",
                repo_owner=owner,
                repo_name=repo,
                branch=branch,
            )

            if not clone_result.get("success"):
                return {
                    "status": "error",
                    "error": f"Failed to clone repository: {clone_result.get('error')}",
                    "step": "clone",
                }

            local_path = clone_result.get("local_path")

            # Step 2: Scan for dependencies and vulnerabilities
            scan_result = self.scan_dependencies(repository, branch)
            if scan_result.get("status") != "success":
                return {
                    "status": "error",
                    "error": f"Failed to scan dependencies: {scan_result.get('error')}",
                    "step": "scan",
                }

            # Step 3: Create new branch for updates
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            new_branch = f"dependency-update-{update_type}-{timestamp}"

            branch_result = self.tools.get_tool("github_tool").execute(
                action="create_branch",
                repo_owner=owner,
                repo_name=repo,
                base_branch=branch,
                new_branch=new_branch,
            )

            if not branch_result.get("success"):
                return {
                    "status": "error",
                    "error": f"Failed to create branch: {branch_result.get('error')}",
                    "step": "create_branch",
                }

            # Step 4: Find and update dependency files
            dependency_files = self._find_dependency_files(local_path)
            file_updates = {}

            for dep_file in dependency_files:
                # Parse current dependencies
                parse_result = self.tools.get_tool("dependency_updater").execute(
                    action="parse_dependencies",
                    file_path=dep_file,
                    file_type=None,  # Auto-detect
                )

                if parse_result.get("success"):
                    current_deps = parse_result.get("dependencies", [])

                    # Generate update plan based on policies
                    update_plan = self._generate_update_plan(current_deps, update_type)

                    if update_plan:
                        # Update the file
                        update_result = self.tools.get_tool(
                            "dependency_updater"
                        ).execute(
                            action="update_dependencies",
                            file_path=dep_file,
                            updates=update_plan,
                            file_type=parse_result.get("file_type"),
                        )

                        if update_result.get("success"):
                            # Store the updated content for commit
                            relative_path = os.path.relpath(dep_file, local_path)
                            file_updates[relative_path] = update_result.get(
                                "new_content"
                            )

            if not file_updates:
                return {
                    "status": "success",
                    "message": "No dependency updates needed",
                    "repository": repository,
                    "branch": new_branch,
                }

            # Step 5: Commit and push changes
            commit_message = f"Update dependencies ({update_type} updates)\n\n- Updated {len(file_updates)} files\n- Branch: {new_branch}\n- Generated by Dependency Security Agent"

            commit_result = self.tools.get_tool("github_tool").execute(
                action="commit_and_push",
                repo_owner=owner,
                repo_name=repo,
                branch=new_branch,
                commit_message=commit_message,
                file_changes=file_updates,
            )

            if not commit_result.get("success"):
                return {
                    "status": "error",
                    "error": f"Failed to commit changes: {commit_result.get('error')}",
                    "step": "commit_and_push",
                }

            # Step 6: Create pull request
            pr_title = f"🔒 Dependency Security Updates ({update_type})"
            pr_body = f"""
## Dependency Security Updates

This PR contains automated dependency updates to improve security and maintainability.

### Summary
- **Update Type**: {update_type}
- **Files Modified**: {len(file_updates)}
- **Branch**: {new_branch}
- **Generated**: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}

### Changes
{self._format_file_changes(file_updates)}

### Security Impact
- Addresses identified vulnerabilities
- Updates outdated dependencies
- Maintains compatibility

### Testing
Please run tests to ensure compatibility:
- [ ] Unit tests pass
- [ ] Integration tests pass
- [ ] Manual verification

### Rollback
If issues arise, this branch can be reverted to {branch}.

---
*Generated by Dependency Security Agent*
            """

            pr_result = self.tools.get_tool("github_tool").execute(
                action="create_pull_request",
                repo_owner=owner,
                repo_name=repo,
                title=pr_title,
                body=pr_body,
                head_branch=new_branch,
                base_branch=branch,
            )

            if not pr_result.get("success"):
                return {
                    "status": "error",
                    "error": f"Failed to create PR: {pr_result.get('error')}",
                    "step": "create_pull_request",
                }

            # Step 7: Deploy changes (if configured)
            deploy_result = self._deploy_changes(owner, repo, new_branch)

            return {
                "status": "success",
                "repository": repository,
                "base_branch": branch,
                "new_branch": new_branch,
                "pull_request": pr_result.get("html_url"),
                "files_updated": list(file_updates.keys()),
                "commit_sha": commit_result.get("commit_sha"),
                "deployment": deploy_result,
                "message": f"Successfully updated dependencies and created PR #{pr_result.get('number')}",
            }

        except Exception as e:
            return {
                "status": "error",
                "error": f"Workflow execution failed: {str(e)}",
                "step": "workflow_execution",
            }

    def _find_dependency_files(self, local_path: str) -> List[str]:
        """Find dependency files in the local repository"""
        dependency_files = []

        for root, dirs, files in os.walk(local_path):
            # Skip hidden directories and common exclusions
            dirs[:] = [
                d
                for d in dirs
                if not d.startswith(".")
                and d not in ["node_modules", "venv", "__pycache__"]
            ]

            for file in files:
                if file in [
                    "package.json",
                    "requirements.txt",
                    "pom.xml",
                    "build.gradle",
                    "Cargo.toml",
                    "go.mod",
                    "composer.json",
                ]:
                    dependency_files.append(os.path.join(root, file))

        return dependency_files

    def _generate_update_plan(
        self, current_deps: List[Dict[str, str]], update_type: str
    ) -> List[Dict[str, str]]:
        """Generate update plan based on current dependencies and update type"""
        # This is a simplified version - in a real implementation, you'd check
        # available versions from package registries
        updates = []

        for dep in current_deps:
            current_version = dep.get("version", "")

            # Simple version bump logic (in reality, you'd check actual available versions)
            if update_type == "patch" and current_version:
                # For patch updates, just increment the patch version
                try:
                    parts = current_version.split(".")
                    if len(parts) >= 3:
                        patch = int(parts[2]) + 1
                        new_version = f"{parts[0]}.{parts[1]}.{patch}"
                        updates.append(
                            {
                                "name": dep.get("name"),
                                "old_version": current_version,
                                "new_version": new_version,
                            }
                        )
                except:
                    pass

        return updates

    def _format_file_changes(self, file_updates: Dict[str, str]) -> str:
        """Format file changes for PR description"""
        formatted = []
        for file_path in file_updates.keys():
            formatted.append(f"- `{file_path}`")
        return "\n".join(formatted)

    def _deploy_changes(self, owner: str, repo: str, branch: str) -> Dict[str, Any]:
        """Deploy changes if deployment is configured"""
        # This is a placeholder for deployment logic
        # In a real implementation, you'd integrate with CI/CD systems
        return {
            "status": "not_configured",
            "message": "Deployment not configured - manual deployment required",
        }

    def update_dependencies(
        self, repository: str, branch: str = "main", update_type: str = "patch"
    ) -> Dict[str, Any]:
        """
        Update dependencies in a repository
        """
        prompt = f"""
        Update dependencies in repository {repository} (branch: {branch}) with {update_type} updates.
        
        Please:
        1. Identify outdated dependencies
        2. Check for available updates
        3. Verify compatibility
        4. Generate update plan
        5. Provide rollback instructions
        
        Repository: {repository}
        Branch: {branch}
        Update Type: {update_type}
        """

        tool_descriptions = self.tools.list_tools()
        result = self.gemini_client.run(prompt, tool_descriptions)

        if result["state"] == "COMPLETE":
            return {
                "status": "success",
                "repository": repository,
                "branch": branch,
                "update_plan": result["final_output"]["response"],
                "update_type": update_type,
            }
        else:
            return {
                "status": "error",
                "error": result.get("error", "Unknown error"),
                "repository": repository,
                "branch": branch,
            }

    def emergency_scan(
        self, cve_id: str = None, package_name: str = None
    ) -> Dict[str, Any]:
        """
        Perform emergency security scan for specific CVE or package
        """
        if cve_id:
            prompt = f"""
            Perform emergency security scan for CVE: {cve_id}
            
            Please:
            1. Analyze the CVE details and impact
            2. Identify affected dependencies across monitored repositories
            3. Assess severity and risk
            4. Provide immediate mitigation steps
            5. Generate emergency response plan
            
            CVE ID: {cve_id}
            """
        elif package_name:
            prompt = f"""
            Perform emergency security scan for package: {package_name}
            
            Please:
            1. Check for known vulnerabilities in this package
            2. Identify affected repositories
            3. Assess current risk level
            4. Provide immediate mitigation steps
            5. Generate emergency response plan
            
            Package: {package_name}
            """
        else:
            prompt = """
            Perform emergency security scan across all monitored repositories
            
            Please:
            1. Check for critical security vulnerabilities
            2. Identify high-risk dependencies
            3. Assess overall security posture
            4. Provide immediate mitigation steps
            5. Generate emergency response plan
            """

        tool_descriptions = self.tools.list_tools()
        result = self.gemini_client.run(prompt, tool_descriptions)

        if result["state"] == "COMPLETE":
            return {
                "status": "success",
                "scan_type": "emergency",
                "cve_id": cve_id,
                "package_name": package_name,
                "analysis": result["final_output"]["response"],
            }
        else:
            return {
                "status": "error",
                "error": result.get("error", "Unknown error"),
                "scan_type": "emergency",
            }

    def generate_report(
        self, repositories: List[str] = None, report_type: str = "comprehensive"
    ) -> Dict[str, Any]:
        """
        Generate comprehensive dependency security report
        """
        if repositories:
            repos_text = ", ".join(repositories)
            prompt = f"""
            Generate a {report_type} dependency security report for repositories: {repos_text}
            
            Please include:
            1. Executive summary
            2. Security posture overview
            3. Vulnerability analysis
            4. License compliance status
            5. Update recommendations
            6. Risk assessment
            7. Action items
            
            Repositories: {repos_text}
            Report Type: {report_type}
            """
        else:
            prompt = f"""
            Generate a {report_type} dependency security report for all monitored repositories
            
            Please include:
            1. Executive summary
            2. Security posture overview
            3. Vulnerability analysis
            4. License compliance status
            5. Update recommendations
            6. Risk assessment
            7. Action items
            
            Report Type: {report_type}
            """

        tool_descriptions = self.tools.list_tools()
        result = self.gemini_client.run(prompt, tool_descriptions)

        if result["state"] == "COMPLETE":
            return {
                "status": "success",
                "report_type": report_type,
                "repositories": repositories or "all",
                "report": result["final_output"]["response"],
            }
        else:
            return {
                "status": "error",
                "error": result.get("error", "Unknown error"),
                "report_type": report_type,
            }

    def _extract_security_score(self, analysis_text: str) -> float:
        """Extract security score from analysis text (placeholder implementation)"""
        # This is a simple placeholder - in a real implementation,
        # you'd want to parse the analysis text more intelligently
        try:
            # Look for numbers that might represent scores
            import re

            numbers = re.findall(r"\b\d+(?:\.\d+)?\b", analysis_text)
            if numbers:
                # Return the first number found, capped between 0-10
                score = float(numbers[0])
                return max(0, min(10, score))
        except:
            pass

        # Default score if parsing fails
        return 5.0

    @property
    def portia(self):
        """Compatibility property to maintain existing interface"""
        return self.gemini_client


# Example usage and main entry point
def main():
    """Main entry point for the agent"""
    agent = DependencySecurityAgent()

    # Example: Analyze a specific repository
    result = agent.scan_dependencies("octocat/Hello-World")
    print("Analysis Result:", result)


if __name__ == "__main__":
    main()
