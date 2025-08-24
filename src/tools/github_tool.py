"""
GitHub Integration Tool for Gemini AI Agent
Provides GitHub repository access and management capabilities
"""

import os
import requests
from typing import Dict, List, Optional, Any
from github import Github, GithubException
from ..utils.tool_registry import Tool
from datetime import datetime


class GitHubTool(Tool):
    """Tool for GitHub repository operations"""

    def __init__(self, config: Dict[str, Any]):
        super().__init__(
            name="github_tool",
            description="GitHub repository access and management capabilities",
        )
        self.config = config
        # Add required fields for compatibility
        self.id = "github_tool"
        self.output_schema = {
            "type": "object",
            "properties": {
                "success": {"type": "boolean"},
                "files": {"type": "object"},
                "error": {"type": "string"},
            },
        }
        self.github_token = os.getenv("GITHUB_TOKEN")
        if not self.github_token:
            raise ValueError("GITHUB_TOKEN environment variable is required")

        self.github = Github(self.github_token)

    def execute(self, **kwargs) -> Any:
        """Execute the GitHub tool"""
        action = kwargs.get("action", "get_repository_files")

        if action == "get_repository_files":
            return self.get_repository_files(
                kwargs.get("repo_owner"),
                kwargs.get("repo_name"),
                kwargs.get("branch", "main"),
                kwargs.get("file_patterns"),
            )
        elif action == "get_dependency_files":
            return self.get_dependency_files(
                kwargs.get("repo_owner"),
                kwargs.get("repo_name"),
                kwargs.get("branch", "main"),
            )
        elif action == "create_pull_request":
            return self.create_pull_request(
                kwargs.get("repo_owner"),
                kwargs.get("repo_name"),
                kwargs.get("title"),
                kwargs.get("body"),
                kwargs.get("head_branch"),
                kwargs.get("base_branch", "main"),
            )
        elif action == "get_repository_info":
            return self.get_repository_info(
                kwargs.get("repo_owner"), kwargs.get("repo_name")
            )
        elif action == "clone_repository":
            return self.clone_repository(
                kwargs.get("repo_owner"),
                kwargs.get("repo_name"),
                kwargs.get("branch", "main"),
                kwargs.get("local_path"),
            )
        elif action == "create_branch":
            return self.create_branch(
                kwargs.get("repo_owner"),
                kwargs.get("repo_name"),
                kwargs.get("base_branch", "main"),
                kwargs.get("new_branch"),
            )
        elif action == "commit_and_push":
            return self.commit_and_push(
                kwargs.get("repo_owner"),
                kwargs.get("repo_name"),
                kwargs.get("branch"),
                kwargs.get("commit_message"),
                kwargs.get("file_changes"),
            )
        else:
            return {
                "error": f"Unknown action: {action}. Supported actions: get_repository_files, get_dependency_files, create_pull_request, get_repository_info, clone_repository, create_branch, commit_and_push"
            }

    def get_repository_files(
        self,
        repo_owner: str,
        repo_name: str,
        branch: str = "main",
        file_patterns: List[str] = None,
    ) -> Dict[str, Any]:
        """
        Get repository files, optionally filtering by patterns

        Args:
            repo_owner: Repository owner username
            repo_name: Repository name
            branch: Branch name (default: main)
            file_patterns: List of file patterns to match (e.g., ["package.json", "requirements.txt"])

        Returns:
            Dictionary containing file contents and metadata
        """
        try:
            repo = self.github.get_repo(f"{repo_owner}/{repo_name}")

            # Get all files in repository
            contents = repo.get_contents("", ref=branch)
            files = {}

            def process_contents(contents_list, path_prefix=""):
                for content in contents_list:
                    if content.type == "dir":
                        # Recursively process directory contents
                        dir_contents = repo.get_contents(content.path, ref=branch)
                        process_contents(dir_contents, f"{path_prefix}{content.name}/")
                    else:
                        full_path = f"{path_prefix}{content.name}"

                        # Check if file matches our patterns (if specified)
                        if file_patterns:
                            if not any(
                                pattern in content.name or pattern in full_path
                                for pattern in file_patterns
                            ):
                                continue

                        # Get file content
                        try:
                            file_content = base64.b64decode(content.content).decode(
                                "utf-8"
                            )
                            files[full_path] = {
                                "content": file_content,
                                "path": full_path,
                                "sha": content.sha,
                                "size": content.size,
                                "url": content.html_url,
                            }
                        except Exception as e:
                            files[full_path] = {
                                "error": f"Could not decode file: {str(e)}",
                                "path": full_path,
                                "sha": content.sha,
                                "size": content.size,
                                "url": content.html_url,
                            }

            process_contents(contents)

            return {
                "repository": f"{repo_owner}/{repo_name}",
                "branch": branch,
                "files": files,
                "total_files": len(files),
            }

        except Exception as e:
            return {"error": f"Failed to access repository: {str(e)}"}

    def get_dependency_files(
        self, repo_owner: str, repo_name: str, branch: str = "main"
    ) -> Dict[str, Any]:
        """
        Get common dependency manifest files from a repository
        """
        dependency_patterns = [
            "package.json",  # npm
            "package-lock.json",  # npm lockfile
            "yarn.lock",  # yarn lockfile
            "requirements.txt",  # pip
            "Pipfile",  # pipenv
            "Pipfile.lock",  # pipenv lockfile
            "poetry.lock",  # poetry lockfile
            "pyproject.toml",  # modern Python
            "pom.xml",  # Maven
            "build.gradle",  # Gradle
            "gradle.lockfile",  # Gradle lockfile
            "composer.json",  # Composer (PHP)
            "composer.lock",  # Composer lockfile
            "Cargo.toml",  # Rust
            "Cargo.lock",  # Rust lockfile
            "go.mod",  # Go modules
            "go.sum",  # Go modules checksum
            "Gemfile",  # Ruby
            "Gemfile.lock",  # Ruby lockfile
            ".csproj",  # .NET
            "packages.config",  # .NET packages
        ]

        return self.get_repository_files(
            repo_owner, repo_name, branch, dependency_patterns
        )

    def create_branch(
        self, repo_owner: str, repo_name: str, base_branch: str, new_branch: str
    ) -> Dict[str, Any]:
        """
        Create a new branch from base branch
        """
        try:
            repo = self.github.get_repo(f"{repo_owner}/{repo_name}")

            # Get the base branch reference
            base_ref = repo.get_git_ref(f"heads/{base_branch}")
            base_sha = base_ref.object.sha

            # Create new branch
            new_ref = repo.create_git_ref(ref=f"refs/heads/{new_branch}", sha=base_sha)

            return {
                "success": True,
                "branch": new_branch,
                "sha": new_ref.object.sha,
                "url": f"https://github.com/{repo_owner}/{repo_name}/tree/{new_branch}",
            }

        except Exception as e:
            return {"error": f"Failed to create branch: {str(e)}"}

    def update_file(
        self,
        repo_owner: str,
        repo_name: str,
        branch: str,
        file_path: str,
        content: str,
        commit_message: str,
    ) -> Dict[str, Any]:
        """
        Update a file in the repository
        """
        try:
            repo = self.github.get_repo(f"{repo_owner}/{repo_name}")

            # Get the current file to get its SHA
            try:
                file = repo.get_contents(file_path, ref=branch)
                file_sha = file.sha
            except:
                file_sha = None  # File doesn't exist, will create new

            # Update or create the file
            if file_sha:
                result = repo.update_file(
                    path=file_path,
                    message=commit_message,
                    content=content,
                    sha=file_sha,
                    branch=branch,
                )
            else:
                result = repo.create_file(
                    path=file_path,
                    message=commit_message,
                    content=content,
                    branch=branch,
                )

            return {
                "success": True,
                "commit_sha": result["commit"].sha,
                "commit_url": result["commit"].html_url,
            }

        except Exception as e:
            return {"error": f"Failed to update file: {str(e)}"}

    def create_pull_request(
        self,
        repo_owner: str,
        repo_name: str,
        head_branch: str,
        base_branch: str,
        title: str,
        body: str,
    ) -> Dict[str, Any]:
        """
        Create a pull request
        """
        try:
            repo = self.github.get_repo(f"{repo_owner}/{repo_name}")

            pr = repo.create_pull(
                title=title, body=body, head=head_branch, base=base_branch
            )

            return {
                "success": True,
                "pr_number": pr.number,
                "pr_url": pr.html_url,
                "pr_id": pr.id,
            }

        except Exception as e:
            return {"error": f"Failed to create pull request: {str(e)}"}

    def get_repository_info(self, repo_owner: str, repo_name: str) -> Dict[str, Any]:
        """
        Get basic repository information
        """
        try:
            repo = self.github.get_repo(f"{repo_owner}/{repo_name}")

            return {
                "name": repo.name,
                "full_name": repo.full_name,
                "description": repo.description,
                "default_branch": repo.default_branch,
                "language": repo.language,
                "languages": repo.get_languages(),
                "stars": repo.stargazers_count,
                "forks": repo.forks_count,
                "open_issues": repo.open_issues_count,
                "created_at": repo.created_at.isoformat(),
                "updated_at": repo.updated_at.isoformat(),
                "has_issues": repo.has_issues,
                "has_wiki": repo.has_wiki,
                "has_pages": repo.has_pages,
                "archived": repo.archived,
                "disabled": repo.disabled,
                "private": repo.private,
                "html_url": repo.html_url,
                "clone_url": repo.clone_url,
            }

        except Exception as e:
            return {"error": f"Failed to get repository info: {str(e)}"}

    def check_ci_status(
        self, repo_owner: str, repo_name: str, branch: str
    ) -> Dict[str, Any]:
        """
        Check CI/CD status for a branch
        """
        try:
            repo = self.github.get_repo(f"{repo_owner}/{repo_name}")

            # Get the latest commit on the branch
            commits = repo.get_commits(sha=branch)
            latest_commit = commits[0]

            # Get status checks for the commit
            statuses = latest_commit.get_statuses()
            check_runs = latest_commit.get_check_runs()

            ci_results = {
                "commit_sha": latest_commit.sha,
                "commit_message": latest_commit.commit.message,
                "statuses": [],
                "check_runs": [],
                "overall_status": "unknown",
            }

            # Process status checks
            for status in statuses:
                ci_results["statuses"].append(
                    {
                        "context": status.context,
                        "state": status.state,
                        "description": status.description,
                        "target_url": status.target_url,
                    }
                )

            # Process check runs
            for check_run in check_runs:
                ci_results["check_runs"].append(
                    {
                        "name": check_run.name,
                        "status": check_run.status,
                        "conclusion": check_run.conclusion,
                        "started_at": (
                            check_run.started_at.isoformat()
                            if check_run.started_at
                            else None
                        ),
                        "completed_at": (
                            check_run.completed_at.isoformat()
                            if check_run.completed_at
                            else None
                        ),
                        "html_url": check_run.html_url,
                    }
                )

            # Determine overall status
            if ci_results["statuses"] or ci_results["check_runs"]:
                failed_statuses = [
                    s for s in ci_results["statuses"] if s["state"] == "failure"
                ]
                failed_checks = [
                    c for c in ci_results["check_runs"] if c["conclusion"] == "failure"
                ]

                if failed_statuses or failed_checks:
                    ci_results["overall_status"] = "failure"
                else:
                    pending_statuses = [
                        s for s in ci_results["statuses"] if s["state"] == "pending"
                    ]
                    pending_checks = [
                        c
                        for c in ci_results["check_runs"]
                        if c["status"] == "in_progress"
                    ]

                    if pending_statuses or pending_checks:
                        ci_results["overall_status"] = "pending"
                    else:
                        ci_results["overall_status"] = "success"

            return ci_results

        except Exception as e:
            return {"error": f"Failed to check CI status: {str(e)}"}

    def clone_repository(
        self,
        repo_owner: str,
        repo_name: str,
        branch: str = "main",
        local_path: str = None,
    ) -> Dict[str, Any]:
        """
        Clone a repository to local filesystem

        Args:
            repo_owner: Repository owner username
            repo_name: Repository name
            branch: Branch to clone (default: main)
            local_path: Local directory path to clone into

        Returns:
            Dictionary containing clone status and local path
        """
        try:
            import git
            import tempfile
            import os

            # Generate local path if not provided
            if not local_path:
                temp_dir = tempfile.mkdtemp(prefix=f"{repo_owner}_{repo_name}_")
                local_path = os.path.join(temp_dir, repo_name)
            else:
                os.makedirs(local_path, exist_ok=True)

            # Clone the repository
            repo_url = f"https://github.com/{repo_owner}/{repo_name}.git"
            if self.github_token:
                repo_url = f"https://{self.github_token}@github.com/{repo_owner}/{repo_name}.git"

            git.Repo.clone_from(repo_url, local_path, branch=branch)

            return {
                "success": True,
                "local_path": local_path,
                "repository": f"{repo_owner}/{repo_name}",
                "branch": branch,
                "message": f"Repository cloned successfully to {local_path}",
            }

        except Exception as e:
            return {
                "success": False,
                "error": f"Failed to clone repository: {str(e)}",
                "repository": f"{repo_owner}/{repo_name}",
            }

    def create_branch(
        self,
        repo_owner: str,
        repo_name: str,
        base_branch: str = "main",
        new_branch: str = None,
    ) -> Dict[str, Any]:
        """
        Create a new branch from base branch

        Args:
            repo_owner: Repository owner username
            repo_name: Repository name
            base_branch: Base branch to create from (default: main)
            new_branch: Name of new branch to create

        Returns:
            Dictionary containing branch creation status
        """
        try:
            if not new_branch:
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                new_branch = f"dependency-update-{timestamp}"

            repo = self.github.get_repo(f"{repo_owner}/{repo_name}")

            # Get the base branch reference
            base_ref = repo.get_branch(base_branch)

            # Create new branch
            repo.create_git_ref(f"refs/heads/{new_branch}", base_ref.commit.sha)

            return {
                "success": True,
                "new_branch": new_branch,
                "base_branch": base_branch,
                "repository": f"{repo_owner}/{repo_name}",
                "message": f"Branch {new_branch} created successfully from {base_branch}",
            }

        except Exception as e:
            return {
                "success": False,
                "error": f"Failed to create branch: {str(e)}",
                "repository": f"{repo_owner}/{repo_name}",
            }

    def commit_and_push(
        self,
        repo_owner: str,
        repo_name: str,
        branch: str,
        commit_message: str,
        file_changes: Dict[str, str],
    ) -> Dict[str, Any]:
        """
        Commit and push changes to a branch

        Args:
            repo_owner: Repository owner username
            repo_name: Repository name
            branch: Branch to commit to
            commit_message: Commit message
            file_changes: Dictionary of file_path: new_content pairs

        Returns:
            Dictionary containing commit status
        """
        try:
            import git
            import os

            # Find the local repository
            local_path = None
            for root, dirs, files in os.walk("/tmp"):
                if ".git" in dirs and repo_name in root:
                    local_path = root
                    break

            if not local_path:
                return {
                    "success": False,
                    "error": f"Local repository not found for {repo_owner}/{repo_name}",
                }

            # Open the repository
            repo = git.Repo(local_path)

            # Switch to the target branch
            repo.git.checkout(branch)

            # Apply file changes
            for file_path, new_content in file_changes.items():
                full_path = os.path.join(local_path, file_path)
                os.makedirs(os.path.dirname(full_path), exist_ok=True)

                with open(full_path, "w", encoding="utf-8") as f:
                    f.write(new_content)

                # Add to git
                repo.index.add([file_path])

            # Commit changes
            commit = repo.index.commit(commit_message)

            # Push to remote
            origin = repo.remote("origin")
            origin.push(branch)

            return {
                "success": True,
                "commit_sha": commit.hexsha,
                "branch": branch,
                "repository": f"{repo_owner}/{repo_name}",
                "message": f"Changes committed and pushed successfully to {branch}",
                "files_modified": list(file_changes.keys()),
            }

        except Exception as e:
            return {
                "success": False,
                "error": f"Failed to commit and push: {str(e)}",
                "repository": f"{repo_owner}/{repo_name}",
            }

    def run(self, **kwargs) -> Dict[str, Any]:
        """
        Main run method for the tool - routes to appropriate GitHub operation
        """
        operation = kwargs.get("operation")

        if operation == "get_dependency_files":
            return self.get_dependency_files(
                kwargs["repo_owner"], kwargs["repo_name"], kwargs.get("branch", "main")
            )
        elif operation == "get_repository_files":
            return self.get_repository_files(
                kwargs["repo_owner"],
                kwargs["repo_name"],
                kwargs.get("branch", "main"),
                kwargs.get("file_patterns"),
            )
        elif operation == "create_branch":
            return self.create_branch(
                kwargs["repo_owner"],
                kwargs["repo_name"],
                kwargs["base_branch"],
                kwargs["new_branch"],
            )
        elif operation == "update_file":
            return self.update_file(
                kwargs["repo_owner"],
                kwargs["repo_name"],
                kwargs["branch"],
                kwargs["file_path"],
                kwargs["content"],
                kwargs["commit_message"],
            )
        elif operation == "create_pull_request":
            return self.create_pull_request(
                kwargs["repo_owner"],
                kwargs["repo_name"],
                kwargs["head_branch"],
                kwargs["base_branch"],
                kwargs["title"],
                kwargs["body"],
            )
        elif operation == "get_repository_info":
            return self.get_repository_info(kwargs["repo_owner"], kwargs["repo_name"])
        elif operation == "check_ci_status":
            return self.check_ci_status(
                kwargs["repo_owner"], kwargs["repo_name"], kwargs.get("branch", "main")
            )
        else:
            return {"error": f"Unknown operation: {operation}"}
