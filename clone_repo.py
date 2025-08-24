#!/usr/bin/env python3
"""
Simple script to clone a repository into the repo/ folder
"""

import sys
import os

# Add src directory to Python path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "src"))

from src.agents.dependency_agent import DependencySecurityAgent


def main():
    """Clone repository into repo/ folder"""
    try:
        # Initialize the agent
        print("Initializing Dependency Security Agent...")
        agent = DependencySecurityAgent()

        # Clone the repository into the repo/ folder
        print("Cloning facebook/create-react-app into repo/ folder...")

        # Use the GitHub tool to clone the repository
        clone_result = agent.tools.get_tool("github_tool").execute(
            action="clone_repository",
            repo_owner="facebook",
            repo_name="create-react-app",
            branch="main",
            local_path="./repo",
        )

        if clone_result.get("success"):
            print(f"✅ Repository cloned successfully!")
            print(f"📁 Local path: {clone_result.get('local_path')}")
            print(f"🔗 Repository: {clone_result.get('repository')}")
            print(f"🌿 Branch: {clone_result.get('branch')}")

            # List the contents of the repo folder
            print("\n📋 Contents of repo/ folder:")
            repo_path = clone_result.get("local_path")
            if os.path.exists(repo_path):
                for item in os.listdir(repo_path):
                    item_path = os.path.join(repo_path, item)
                    if os.path.isdir(item_path):
                        print(f"📁 {item}/")
                    else:
                        print(f"📄 {item}")
        else:
            print(f"❌ Failed to clone repository: {clone_result.get('error')}")

    except Exception as e:
        print(f"❌ Error: {str(e)}")
        import traceback

        traceback.print_exc()


if __name__ == "__main__":
    main()
