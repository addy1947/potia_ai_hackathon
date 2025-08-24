"""
Dependency Updater Tool
Handles parsing, updating, and modifying dependency files
"""

import os
import json
import re
from typing import Dict, List, Any, Optional
from ..utils.tool_registry import Tool


class DependencyUpdater(Tool):
    """Tool for updating dependency files"""

    def __init__(self, config: Dict[str, Any]):
        super().__init__(
            name="dependency_updater",
            description="Parse, update, and modify dependency files",
        )
        self.config = config
        self.id = "dependency_updater"
        self.output_schema = {
            "type": "object",
            "properties": {
                "success": {"type": "boolean"},
                "updates": {"type": "array"},
                "error": {"type": "string"},
            },
        }

    def execute(self, **kwargs) -> Any:
        """Execute the dependency updater tool"""
        action = kwargs.get("action", "parse_dependencies")

        if action == "parse_dependencies":
            return self.parse_dependencies(
                kwargs.get("file_path"),
                kwargs.get("file_type"),
            )
        elif action == "update_dependencies":
            return self.update_dependencies(
                kwargs.get("file_path"),
                kwargs.get("updates"),
                kwargs.get("file_type"),
            )
        elif action == "generate_update_plan":
            return self.generate_update_plan(
                kwargs.get("current_deps"),
                kwargs.get("available_updates"),
            )
        else:
            return {
                "error": f"Unknown action: {action}. Supported actions: parse_dependencies, update_dependencies, generate_update_plan"
            }

    def parse_dependencies(
        self, file_path: str, file_type: str = None
    ) -> Dict[str, Any]:
        """
        Parse dependency file and extract current versions

        Args:
            file_path: Path to dependency file
            file_type: Type of dependency file (auto-detected if None)

        Returns:
            Dictionary containing parsed dependencies
        """
        try:
            if not os.path.exists(file_path):
                return {"success": False, "error": f"File not found: {file_path}"}

            # Auto-detect file type if not specified
            if not file_type:
                file_type = self._detect_file_type(file_path)

            if file_type == "npm":
                return self._parse_package_json(file_path)
            elif file_type == "pip":
                return self._parse_requirements_txt(file_path)
            elif file_type == "maven":
                return self._parse_pom_xml(file_path)
            elif file_type == "gradle":
                return self._parse_build_gradle(file_path)
            else:
                return {
                    "success": False,
                    "error": f"Unsupported file type: {file_type}",
                }

        except Exception as e:
            return {
                "success": False,
                "error": f"Failed to parse dependencies: {str(e)}",
            }

    def update_dependencies(
        self, file_path: str, updates: List[Dict[str, str]], file_type: str = None
    ) -> Dict[str, Any]:
        """
        Update dependency file with new versions

        Args:
            file_path: Path to dependency file
            updates: List of updates in format [{"name": "package", "old_version": "1.0.0", "new_version": "1.1.0"}]
            file_type: Type of dependency file

        Returns:
            Dictionary containing update status and new content
        """
        try:
            if not os.path.exists(file_path):
                return {"success": False, "error": f"File not found: {file_path}"}

            # Auto-detect file type if not specified
            if not file_type:
                file_type = self._detect_file_type(file_path)

            # Read current content
            with open(file_path, "r", encoding="utf-8") as f:
                content = f.read()

            # Apply updates based on file type
            if file_type == "npm":
                new_content = self._update_package_json(content, updates)
            elif file_type == "pip":
                new_content = self._update_requirements_txt(content, updates)
            elif file_type == "maven":
                new_content = self._update_pom_xml(content, updates)
            elif file_type == "gradle":
                new_content = self._update_build_gradle(content, updates)
            else:
                return {
                    "success": False,
                    "error": f"Unsupported file type: {file_type}",
                }

            return {
                "success": True,
                "file_path": file_path,
                "file_type": file_type,
                "new_content": new_content,
                "updates_applied": len(updates),
                "message": f"Successfully updated {len(updates)} dependencies",
            }

        except Exception as e:
            return {
                "success": False,
                "error": f"Failed to update dependencies: {str(e)}",
            }

    def generate_update_plan(
        self,
        current_deps: List[Dict[str, str]],
        available_updates: List[Dict[str, str]],
    ) -> Dict[str, Any]:
        """
        Generate a plan for updating dependencies

        Args:
            current_deps: Current dependencies with versions
            available_updates: Available updates with new versions

        Returns:
            Dictionary containing update plan
        """
        try:
            update_plan = []

            for current_dep in current_deps:
                dep_name = current_dep.get("name")
                current_version = current_dep.get("version")

                # Find available update for this dependency
                for update in available_updates:
                    if update.get("name") == dep_name:
                        new_version = update.get("new_version")
                        update_type = self._determine_update_type(
                            current_version, new_version
                        )

                        update_plan.append(
                            {
                                "name": dep_name,
                                "current_version": current_version,
                                "new_version": new_version,
                                "update_type": update_type,
                                "recommended": self._is_update_recommended(
                                    update_type, update.get("security_risk", "low")
                                ),
                            }
                        )
                        break

            return {
                "success": True,
                "update_plan": update_plan,
                "total_updates": len(update_plan),
                "security_updates": len(
                    [u for u in update_plan if u.get("security_risk") == "high"]
                ),
                "minor_updates": len(
                    [u for u in update_plan if u.get("update_type") == "minor"]
                ),
                "patch_updates": len(
                    [u for u in update_plan if u.get("update_type") == "patch"]
                ),
            }

        except Exception as e:
            return {
                "success": False,
                "error": f"Failed to generate update plan: {str(e)}",
            }

    def _detect_file_type(self, file_path: str) -> str:
        """Detect dependency file type based on filename"""
        filename = os.path.basename(file_path).lower()

        if filename == "package.json":
            return "npm"
        elif filename == "requirements.txt":
            return "pip"
        elif filename == "pom.xml":
            return "maven"
        elif filename == "build.gradle":
            return "gradle"
        elif filename.endswith(".csproj"):
            return "nuget"
        elif filename == "cargo.toml":
            return "cargo"
        elif filename == "go.mod":
            return "go"
        elif filename == "composer.json":
            return "composer"
        else:
            return "unknown"

    def _parse_package_json(self, file_path: str) -> Dict[str, Any]:
        """Parse npm package.json file"""
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                data = json.load(f)

            dependencies = {}
            if "dependencies" in data:
                dependencies.update(data["dependencies"])
            if "devDependencies" in data:
                dependencies.update(data["devDependencies"])

            deps_list = []
            for name, version in dependencies.items():
                deps_list.append(
                    {
                        "name": name,
                        "version": version,
                        "type": (
                            "dependency"
                            if name in data.get("dependencies", {})
                            else "devDependency"
                        ),
                    }
                )

            return {
                "success": True,
                "file_type": "npm",
                "dependencies": deps_list,
                "total_dependencies": len(deps_list),
            }

        except Exception as e:
            return {
                "success": False,
                "error": f"Failed to parse package.json: {str(e)}",
            }

    def _parse_requirements_txt(self, file_path: str) -> Dict[str, Any]:
        """Parse pip requirements.txt file"""
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                lines = f.readlines()

            deps_list = []
            for line in lines:
                line = line.strip()
                if line and not line.startswith("#"):
                    # Parse package==version format
                    if "==" in line:
                        name, version = line.split("==", 1)
                        deps_list.append(
                            {
                                "name": name.strip(),
                                "version": version.strip(),
                                "type": "dependency",
                            }
                        )
                    elif ">=" in line:
                        name, version = line.split(">=", 1)
                        deps_list.append(
                            {
                                "name": name.strip(),
                                "version": f">={version.strip()}",
                                "type": "dependency",
                            }
                        )
                    else:
                        deps_list.append(
                            {"name": line, "version": "latest", "type": "dependency"}
                        )

            return {
                "success": True,
                "file_type": "pip",
                "dependencies": deps_list,
                "total_dependencies": len(deps_list),
            }

        except Exception as e:
            return {
                "success": False,
                "error": f"Failed to parse requirements.txt: {str(e)}",
            }

    def _update_package_json(self, content: str, updates: List[Dict[str, str]]) -> str:
        """Update package.json content with new versions"""
        try:
            data = json.loads(content)

            for update in updates:
                dep_name = update.get("name")
                new_version = update.get("new_version")

                # Update in dependencies
                if "dependencies" in data and dep_name in data["dependencies"]:
                    data["dependencies"][dep_name] = new_version

                # Update in devDependencies
                if "devDependencies" in data and dep_name in data["devDependencies"]:
                    data["devDependencies"][dep_name] = new_version

            return json.dumps(data, indent=2)

        except Exception as e:
            raise Exception(f"Failed to update package.json: {str(e)}")

    def _update_requirements_txt(
        self, content: str, updates: List[Dict[str, str]]
    ) -> str:
        """Update requirements.txt content with new versions"""
        try:
            lines = content.split("\n")
            updated_lines = []

            for line in lines:
                updated_line = line
                for update in updates:
                    dep_name = update.get("name")
                    new_version = update.get("new_version")

                    if line.strip().startswith(dep_name + "=="):
                        updated_line = f"{dep_name}=={new_version}"
                        break

                updated_lines.append(updated_line)

            return "\n".join(updated_lines)

        except Exception as e:
            raise Exception(f"Failed to update requirements.txt: {str(e)}")

    def _parse_pom_xml(self, file_path: str) -> Dict[str, Any]:
        """Parse Maven pom.xml file"""
        try:
            # Simple XML parsing for pom.xml
            with open(file_path, "r", encoding="utf-8") as f:
                content = f.read()

            deps_list = []

            # Basic XML parsing to find dependencies
            import re

            dependency_pattern = r"<dependency>.*?<groupId>(.*?)</groupId>.*?<artifactId>(.*?)</artifactId>.*?<version>(.*?)</version>.*?</dependency>"
            matches = re.findall(dependency_pattern, content, re.DOTALL)

            for group_id, artifact_id, version in matches:
                deps_list.append(
                    {
                        "name": f"{group_id}:{artifact_id}",
                        "version": version.strip(),
                        "type": "dependency",
                    }
                )

            return {
                "success": True,
                "file_type": "maven",
                "dependencies": deps_list,
                "total_dependencies": len(deps_list),
            }

        except Exception as e:
            return {"success": False, "error": f"Failed to parse pom.xml: {str(e)}"}

    def _parse_build_gradle(self, file_path: str) -> Dict[str, Any]:
        """Parse Gradle build.gradle file"""
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                content = f.read()

            deps_list = []

            # Basic parsing for Gradle dependencies
            import re

            # Look for implementation dependencies
            impl_pattern = r"implementation\s+['\"]([^'\"]+)['\"]"
            impl_matches = re.findall(impl_pattern, content)

            for dep in impl_matches:
                if ":" in dep:
                    name, version = dep.split(":", 1)
                    deps_list.append(
                        {
                            "name": name.strip(),
                            "version": version.strip(),
                            "type": "dependency",
                        }
                    )
                else:
                    deps_list.append(
                        {"name": dep.strip(), "version": "latest", "type": "dependency"}
                    )

            return {
                "success": True,
                "file_type": "gradle",
                "dependencies": deps_list,
                "total_dependencies": len(deps_list),
            }

        except Exception as e:
            return {
                "success": False,
                "error": f"Failed to parse build.gradle: {str(e)}",
            }

    def _update_pom_xml(self, content: str, updates: List[Dict[str, str]]) -> str:
        """Update pom.xml content with new versions"""
        try:
            # Simple XML updating for pom.xml
            updated_content = content

            for update in updates:
                dep_name = update.get("name")
                new_version = update.get("new_version")

                if ":" in dep_name:
                    group_id, artifact_id = dep_name.split(":", 1)

                    # Find and replace the version for this dependency
                    pattern = rf"<dependency>.*?<groupId>{re.escape(group_id)}</groupId>.*?<artifactId>{re.escape(artifact_id)}</artifactId>.*?<version>([^<]+)</version>"
                    replacement = rf"<dependency>\g<0><version>{new_version}</version>"
                    updated_content = re.sub(
                        pattern, replacement, updated_content, flags=re.DOTALL
                    )

            return updated_content

        except Exception as e:
            raise Exception(f"Failed to update pom.xml: {str(e)}")

    def _update_build_gradle(self, content: str, updates: List[Dict[str, str]]) -> str:
        """Update build.gradle content with new versions"""
        try:
            updated_content = content

            for update in updates:
                dep_name = update.get("name")
                new_version = update.get("new_version")

                # Find and replace version in implementation statements
                pattern = (
                    rf"implementation\s+['\"]({re.escape(dep_name)}):([^'\"]+)['\"]"
                )
                replacement = rf"implementation '{dep_name}:{new_version}'"
                updated_content = re.sub(pattern, replacement, updated_content)

            return updated_content

        except Exception as e:
            raise Exception(f"Failed to update build.gradle: {str(e)}")

    def _determine_update_type(self, current_version: str, new_version: str) -> str:
        """Determine if update is major, minor, or patch"""
        try:
            # Simple semantic versioning check
            current_parts = current_version.split(".")
            new_parts = new_version.split(".")

            if len(current_parts) >= 3 and len(new_parts) >= 3:
                if new_parts[0] != current_parts[0]:
                    return "major"
                elif new_parts[1] != current_parts[1]:
                    return "minor"
                else:
                    return "patch"

            return "unknown"

        except:
            return "unknown"

    def _is_update_recommended(self, update_type: str, security_risk: str) -> bool:
        """Determine if update is recommended based on policies"""
        policies = self.config.get("policies", {})
        version_policy = policies.get("version_updates", {})

        if security_risk == "high":
            return True

        if update_type == "major":
            return version_policy.get("allow_major_versions", False)
        elif update_type == "minor":
            return version_policy.get("allow_minor_versions", True)
        elif update_type == "patch":
            return version_policy.get("allow_patch_versions", True)

        return False
