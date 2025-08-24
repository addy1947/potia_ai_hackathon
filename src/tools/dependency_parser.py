"""
Dependency Parser Tool for Gemini AI Agent
Parses various dependency manifest files and extracts package information
"""

import json
import re
import xml.etree.ElementTree as ET
from typing import Dict, List, Optional, Any, Tuple
from ..utils.tool_registry import Tool
import yaml
from packaging import version
import toml


class DependencyParser(Tool):
    """Tool for parsing dependency manifest files from various package managers"""

    def __init__(self, config: Dict[str, Any]):
        super().__init__(
            name="dependency_parser",
            description="Parse dependency manifest files and extract package information",
        )
        self.config = config
        # Add required fields for compatibility
        self.id = "dependency_parser"
        self.output_schema = {
            "type": "object",
            "properties": {
                "success": {"type": "boolean"},
                "package_manager": {"type": "string"},
                "project_name": {"type": "string"},
                "project_version": {"type": "string"},
                "dependencies": {"type": "object"},
                "dev_dependencies": {"type": "object"},
                "total_dependencies": {"type": "integer"},
                "license": {"type": "string"},
                "error": {"type": "string"},
            },
        }

    def execute(self, **kwargs) -> Any:
        """Execute the dependency parser tool"""
        file_type = kwargs.get("file_type", "auto")
        content = kwargs.get("content", "")

        if file_type == "package_json" or (
            file_type == "auto" and content.strip().startswith("{")
        ):
            return self.parse_package_json(content)
        elif file_type == "requirements_txt" or (
            file_type == "auto" and ">=" in content or "==" in content
        ):
            return self.parse_requirements_txt(content)
        elif file_type == "pom_xml" or (
            file_type == "auto" and content.strip().startswith("<?xml")
        ):
            return self.parse_pom_xml(content)
        elif file_type == "build_gradle" or (
            file_type == "auto" and "implementation" in content
        ):
            return self.parse_build_gradle(content)
        elif file_type == "composer_json" or (
            file_type == "auto" and '"require"' in content
        ):
            return self.parse_composer_json(content)
        elif file_type == "cargo_toml" or (
            file_type == "auto" and "[dependencies]" in content
        ):
            return self.parse_cargo_toml(content)
        elif file_type == "go_mod" or (file_type == "auto" and "require (" in content):
            return self.parse_go_mod(content)
        else:
            return {
                "success": False,
                "error": f"Unsupported file type: {file_type} or unable to auto-detect",
            }

    def parse_package_json(self, content: str) -> Dict[str, Any]:
        """
        Parse package.json (npm) file
        """
        try:
            data = json.loads(content)

            dependencies = {}
            dev_dependencies = {}

            # Regular dependencies
            if "dependencies" in data:
                dependencies = self._normalize_npm_versions(data["dependencies"])

            # Development dependencies
            if "devDependencies" in data:
                dev_dependencies = self._normalize_npm_versions(data["devDependencies"])

            return {
                "success": True,
                "package_manager": "npm",
                "project_name": data.get("name", "unknown"),
                "project_version": data.get("version", "unknown"),
                "dependencies": dependencies,
                "dev_dependencies": dev_dependencies,
                "total_dependencies": len(dependencies) + len(dev_dependencies),
                "engines": data.get("engines", {}),
                "scripts": data.get("scripts", {}),
                "license": data.get("license", "unknown"),
            }

        except json.JSONDecodeError as e:
            return {
                "success": False,
                "error": f"Invalid JSON in package.json: {str(e)}",
            }
        except Exception as e:
            return {
                "success": False,
                "error": f"Failed to parse package.json: {str(e)}",
            }

    def parse_requirements_txt(self, content: str) -> Dict[str, Any]:
        """
        Parse requirements.txt (pip) file
        """
        try:
            dependencies = {}
            lines = content.strip().split("\n")

            for line in lines:
                line = line.strip()

                # Skip empty lines and comments
                if not line or line.startswith("#"):
                    continue

                # Skip -e (editable installs) for now
                if line.startswith("-e"):
                    continue

                # Parse package specification
                parsed = self._parse_pip_requirement(line)
                if parsed:
                    name, version_spec = parsed
                    dependencies[name] = version_spec

            return {
                "success": True,
                "package_manager": "pip",
                "dependencies": dependencies,
                "total_dependencies": len(dependencies),
                "dev_dependencies": {},  # requirements.txt doesn't separate dev deps
                "project_name": "unknown",
                "project_version": "unknown",
            }

        except Exception as e:
            return {
                "success": False,
                "error": f"Failed to parse requirements.txt: {str(e)}",
            }

    def parse_pom_xml(self, content: str) -> Dict[str, Any]:
        """
        Parse pom.xml (Maven) file
        """
        try:
            root = ET.fromstring(content)

            # Handle namespaces
            namespaces = {"maven": "http://maven.apache.org/POM/4.0.0"}

            # Try to find namespace from root
            if root.tag.startswith("{"):
                namespace = root.tag.split("}")[0][1:]
                namespaces["maven"] = namespace

            dependencies = {}
            dev_dependencies = {}

            # Project information
            project_name = self._get_xml_text(root, ".//maven:artifactId", namespaces)
            project_version = self._get_xml_text(root, ".//maven:version", namespaces)

            # Parse dependencies
            deps_element = root.find(".//maven:dependencies", namespaces)
            if deps_element is not None:
                for dep in deps_element.findall("maven:dependency", namespaces):
                    group_id = self._get_xml_text(dep, "./maven:groupId", namespaces)
                    artifact_id = self._get_xml_text(
                        dep, "./maven:artifactId", namespaces
                    )
                    dep_version = self._get_xml_text(dep, "./maven:version", namespaces)
                    scope = (
                        self._get_xml_text(dep, "./maven:scope", namespaces)
                        or "compile"
                    )

                    if group_id and artifact_id:
                        package_name = f"{group_id}:{artifact_id}"

                        if scope in ["test", "provided"]:
                            dev_dependencies[package_name] = dep_version or "unknown"
                        else:
                            dependencies[package_name] = dep_version or "unknown"

            return {
                "success": True,
                "package_manager": "maven",
                "project_name": project_name or "unknown",
                "project_version": project_version or "unknown",
                "dependencies": dependencies,
                "dev_dependencies": dev_dependencies,
                "total_dependencies": len(dependencies) + len(dev_dependencies),
            }

        except ET.ParseError as e:
            return {"success": False, "error": f"Invalid XML in pom.xml: {str(e)}"}
        except Exception as e:
            return {"success": False, "error": f"Failed to parse pom.xml: {str(e)}"}

    def parse_build_gradle(self, content: str) -> Dict[str, Any]:
        """
        Parse build.gradle (Gradle) file
        """
        try:
            dependencies = {}
            dev_dependencies = {}

            # Extract dependencies using regex (simplified parsing)
            # This is a basic parser - Gradle files can be complex
            dep_patterns = [
                r"implementation\s+['\"]([^:]+):([^:]+):([^'\"]+)['\"]",
                r"compile\s+['\"]([^:]+):([^:]+):([^'\"]+)['\"]",
                r"api\s+['\"]([^:]+):([^:]+):([^'\"]+)['\"]",
            ]

            dev_dep_patterns = [
                r"testImplementation\s+['\"]([^:]+):([^:]+):([^'\"]+)['\"]",
                r"testCompile\s+['\"]([^:]+):([^:]+):([^'\"]+)['\"]",
                r"androidTestImplementation\s+['\"]([^:]+):([^:]+):([^'\"]+)['\"]",
            ]

            # Parse regular dependencies
            for pattern in dep_patterns:
                matches = re.findall(pattern, content)
                for group_id, artifact_id, dep_version in matches:
                    package_name = f"{group_id}:{artifact_id}"
                    dependencies[package_name] = dep_version

            # Parse dev dependencies
            for pattern in dev_dep_patterns:
                matches = re.findall(pattern, content)
                for group_id, artifact_id, dep_version in matches:
                    package_name = f"{group_id}:{artifact_id}"
                    dev_dependencies[package_name] = dep_version

            return {
                "success": True,
                "package_manager": "gradle",
                "dependencies": dependencies,
                "dev_dependencies": dev_dependencies,
                "total_dependencies": len(dependencies) + len(dev_dependencies),
                "project_name": "unknown",
                "project_version": "unknown",
            }

        except Exception as e:
            return {
                "success": False,
                "error": f"Failed to parse build.gradle: {str(e)}",
            }

    def parse_composer_json(self, content: str) -> Dict[str, Any]:
        """
        Parse composer.json (PHP Composer) file
        """
        try:
            data = json.loads(content)

            dependencies = {}
            dev_dependencies = {}

            # Regular dependencies
            if "require" in data:
                dependencies = {
                    k: v
                    for k, v in data["require"].items()
                    if not k.startswith("php") and k != "ext-"
                }

            # Development dependencies
            if "require-dev" in data:
                dev_dependencies = data["require-dev"]

            return {
                "success": True,
                "package_manager": "composer",
                "project_name": data.get("name", "unknown"),
                "project_version": data.get("version", "unknown"),
                "dependencies": dependencies,
                "dev_dependencies": dev_dependencies,
                "total_dependencies": len(dependencies) + len(dev_dependencies),
                "license": data.get("license", "unknown"),
            }

        except json.JSONDecodeError as e:
            return {
                "success": False,
                "error": f"Invalid JSON in composer.json: {str(e)}",
            }
        except Exception as e:
            return {
                "success": False,
                "error": f"Failed to parse composer.json: {str(e)}",
            }

    def parse_cargo_toml(self, content: str) -> Dict[str, Any]:
        """
        Parse Cargo.toml (Rust) file
        """
        try:
            data = toml.loads(content)

            dependencies = {}
            dev_dependencies = {}

            # Regular dependencies
            if "dependencies" in data:
                for name, spec in data["dependencies"].items():
                    if isinstance(spec, str):
                        dependencies[name] = spec
                    elif isinstance(spec, dict) and "version" in spec:
                        dependencies[name] = spec["version"]

            # Development dependencies
            if "dev-dependencies" in data:
                for name, spec in data["dev-dependencies"].items():
                    if isinstance(spec, str):
                        dev_dependencies[name] = spec
                    elif isinstance(spec, dict) and "version" in spec:
                        dev_dependencies[name] = spec["version"]

            # Project information
            package_info = data.get("package", {})

            return {
                "success": True,
                "package_manager": "cargo",
                "project_name": package_info.get("name", "unknown"),
                "project_version": package_info.get("version", "unknown"),
                "dependencies": dependencies,
                "dev_dependencies": dev_dependencies,
                "total_dependencies": len(dependencies) + len(dev_dependencies),
                "license": package_info.get("license", "unknown"),
            }

        except Exception as e:
            return {"success": False, "error": f"Failed to parse Cargo.toml: {str(e)}"}

    def parse_go_mod(self, content: str) -> Dict[str, Any]:
        """
        Parse go.mod (Go modules) file
        """
        try:
            dependencies = {}
            lines = content.strip().split("\n")

            in_require_block = False
            module_name = "unknown"
            go_version = "unknown"

            for line in lines:
                line = line.strip()

                if line.startswith("module "):
                    module_name = line.split(" ", 1)[1]
                elif line.startswith("go "):
                    go_version = line.split(" ", 1)[1]
                elif line == "require (":
                    in_require_block = True
                elif line == ")" and in_require_block:
                    in_require_block = False
                elif in_require_block or line.startswith("require "):
                    # Parse requirement line
                    if line.startswith("require "):
                        line = line[8:]  # Remove 'require '

                    line = line.strip()
                    if line and not line.startswith("//"):
                        parts = line.split()
                        if len(parts) >= 2:
                            package_name = parts[0]
                            package_version = parts[1]
                            dependencies[package_name] = package_version

            return {
                "success": True,
                "package_manager": "go",
                "project_name": module_name,
                "project_version": go_version,
                "dependencies": dependencies,
                "dev_dependencies": {},  # Go doesn't separate dev dependencies in go.mod
                "total_dependencies": len(dependencies),
            }

        except Exception as e:
            return {"success": False, "error": f"Failed to parse go.mod: {str(e)}"}

    def parse_pyproject_toml(self, content: str) -> Dict[str, Any]:
        """
        Parse pyproject.toml (Modern Python packaging) file
        """
        try:
            data = toml.loads(content)

            dependencies = {}
            dev_dependencies = {}

            # Check for different dependency specifications
            # Poetry format
            if "tool" in data and "poetry" in data["tool"]:
                poetry = data["tool"]["poetry"]

                if "dependencies" in poetry:
                    for name, spec in poetry["dependencies"].items():
                        if name != "python":  # Skip Python version requirement
                            if isinstance(spec, str):
                                dependencies[name] = spec
                            elif isinstance(spec, dict) and "version" in spec:
                                dependencies[name] = spec["version"]

                if "dev-dependencies" in poetry:
                    for name, spec in poetry["dev-dependencies"].items():
                        if isinstance(spec, str):
                            dev_dependencies[name] = spec
                        elif isinstance(spec, dict) and "version" in spec:
                            dev_dependencies[name] = spec["version"]

                project_name = poetry.get("name", "unknown")
                project_version = poetry.get("version", "unknown")
                license_info = poetry.get("license", "unknown")

            # PEP 621 format
            elif "project" in data:
                project = data["project"]

                if "dependencies" in project:
                    for dep in project["dependencies"]:
                        parsed = self._parse_pip_requirement(dep)
                        if parsed:
                            name, version_spec = parsed
                            dependencies[name] = version_spec

                # Optional dependencies (often used for dev dependencies)
                if "optional-dependencies" in project:
                    for group, deps in project["optional-dependencies"].items():
                        for dep in deps:
                            parsed = self._parse_pip_requirement(dep)
                            if parsed:
                                name, version_spec = parsed
                                dev_dependencies[name] = version_spec

                project_name = project.get("name", "unknown")
                project_version = project.get("version", "unknown")
                license_info = project.get("license", {}).get("text", "unknown")

            else:
                return {
                    "success": False,
                    "error": "No recognized dependency format found in pyproject.toml",
                }

            return {
                "success": True,
                "package_manager": "pyproject",
                "project_name": project_name,
                "project_version": project_version,
                "dependencies": dependencies,
                "dev_dependencies": dev_dependencies,
                "total_dependencies": len(dependencies) + len(dev_dependencies),
                "license": license_info,
            }

        except Exception as e:
            return {
                "success": False,
                "error": f"Failed to parse pyproject.toml: {str(e)}",
            }

    def auto_parse_file(self, file_path: str, content: str) -> Dict[str, Any]:
        """
        Automatically detect and parse dependency file based on filename
        """
        filename = file_path.lower().split("/")[-1]  # Get just the filename

        parsers = {
            "package.json": self.parse_package_json,
            "requirements.txt": self.parse_requirements_txt,
            "pom.xml": self.parse_pom_xml,
            "build.gradle": self.parse_build_gradle,
            "composer.json": self.parse_composer_json,
            "cargo.toml": self.parse_cargo_toml,
            "go.mod": self.parse_go_mod,
            "pyproject.toml": self.parse_pyproject_toml,
        }

        for pattern, parser in parsers.items():
            if pattern in filename:
                result = parser(content)
                result["file_path"] = file_path
                result["filename"] = filename
                return result

        return {
            "success": False,
            "error": f"No parser available for file: {filename}",
            "file_path": file_path,
            "filename": filename,
        }

    def compare_versions(
        self, version1: str, version2: str, package_manager: str = "npm"
    ) -> Dict[str, Any]:
        """
        Compare two version strings and determine which is newer
        """
        try:
            # Normalize versions by removing common prefixes and constraints
            v1 = self._normalize_version(version1)
            v2 = self._normalize_version(version2)

            # Use packaging library for comparison
            parsed_v1 = version.parse(v1)
            parsed_v2 = version.parse(v2)

            if parsed_v1 > parsed_v2:
                result = "newer"
            elif parsed_v1 < parsed_v2:
                result = "older"
            else:
                result = "same"

            return {
                "success": True,
                "version1": version1,
                "version2": version2,
                "normalized_v1": v1,
                "normalized_v2": v2,
                "comparison": result,
            }

        except Exception as e:
            return {
                "success": False,
                "error": f"Version comparison failed: {str(e)}",
                "version1": version1,
                "version2": version2,
            }

    def extract_licenses(self, parsed_files: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Extract license information from parsed dependency files
        """
        licenses = {}

        for file_info in parsed_files:
            if file_info.get("success") and "license" in file_info:
                filename = file_info.get("filename", "unknown")
                license_info = file_info["license"]

                if license_info and license_info != "unknown":
                    licenses[filename] = license_info

        return {
            "success": True,
            "licenses": licenses,
            "unique_licenses": list(set(licenses.values())),
            "license_count": len(set(licenses.values())),
        }

    def _normalize_npm_versions(self, deps: Dict[str, str]) -> Dict[str, str]:
        """Normalize npm version specifications"""
        normalized = {}
        for name, ver in deps.items():
            # Remove common npm version prefixes
            clean_ver = ver.lstrip("^~>=<")
            normalized[name] = clean_ver
        return normalized

    def _parse_pip_requirement(self, requirement: str) -> Optional[Tuple[str, str]]:
        """Parse a pip requirement string"""
        try:
            # Simple regex to parse package requirements
            match = re.match(r"^([a-zA-Z0-9\-_\.]+)([><=!]+.*)?", requirement)
            if match:
                name = match.group(1)
                version_spec = match.group(2) or "unknown"
                return (name, version_spec.strip())
        except:
            pass
        return None

    def _get_xml_text(
        self, element, xpath: str, namespaces: Dict[str, str]
    ) -> Optional[str]:
        """Safely extract text from XML element"""
        try:
            found = element.find(xpath, namespaces)
            return found.text if found is not None else None
        except:
            return None

    def _normalize_version(self, version_str: str) -> str:
        """Normalize version string for comparison"""
        # Remove common version prefixes and constraints
        normalized = re.sub(r"^[~^>=<]+", "", version_str)

        # Remove additional constraints like " || ^2.0.0"
        normalized = re.split(r"\s+\|\|", normalized)[0]

        # Clean up whitespace and common suffixes
        normalized = normalized.strip()

        return normalized

    def run(self, **kwargs) -> Dict[str, Any]:
        """
        Main run method for the dependency parser tool
        """
        operation = kwargs.get("operation")

        if operation == "parse_file":
            return self.auto_parse_file(kwargs["file_path"], kwargs["content"])
        elif operation == "parse_package_json":
            return self.parse_package_json(kwargs["content"])
        elif operation == "parse_requirements_txt":
            return self.parse_requirements_txt(kwargs["content"])
        elif operation == "parse_pom_xml":
            return self.parse_pom_xml(kwargs["content"])
        elif operation == "parse_build_gradle":
            return self.parse_build_gradle(kwargs["content"])
        elif operation == "parse_composer_json":
            return self.parse_composer_json(kwargs["content"])
        elif operation == "parse_cargo_toml":
            return self.parse_cargo_toml(kwargs["content"])
        elif operation == "parse_go_mod":
            return self.parse_go_mod(kwargs["content"])
        elif operation == "parse_pyproject_toml":
            return self.parse_pyproject_toml(kwargs["content"])
        elif operation == "compare_versions":
            return self.compare_versions(
                kwargs["version1"],
                kwargs["version2"],
                kwargs.get("package_manager", "npm"),
            )
        elif operation == "extract_licenses":
            return self.extract_licenses(kwargs["parsed_files"])
        else:
            return {"error": f"Unknown operation: {operation}"}
