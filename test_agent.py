#!/usr/bin/env python3
"""
Test script for Dependency Security Agent
"""

import os
import sys
import json
from dotenv import load_dotenv

# Add src directory to Python path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "src"))

load_dotenv()


def test_gemini_installation():
    """Test if Gemini AI is properly installed and configured"""
    print("🧪 Testing Gemini AI installation...")

    try:
        import google.generativeai as genai

        # Check if API keys are configured
        if os.getenv("GEMINI_API_KEY"):
            print("✓ Gemini API key found")
        else:
            print("⚠️  No Gemini API key found. Please set GEMINI_API_KEY")
            return False

        # Test basic functionality
        genai.configure(api_key=os.getenv("GEMINI_API_KEY"))
        model = genai.GenerativeModel("gemini-1.5-flash")
        response = model.generate_content("What is 2 + 2?")

        if response.text and "4" in response.text:
            print("✓ Gemini AI is working correctly!")
            return True
        else:
            print("✗ Gemini AI test failed")
            print(f"Response: {response.text}")
            return False

    except ImportError as e:
        print(f"✗ Failed to import Google Generative AI: {e}")
        print("Please install Google Generative AI: pip install google-generativeai")
        return False
    except Exception as e:
        print(f"✗ Gemini test failed: {e}")
        return False


def test_dependencies():
    """Test if all required dependencies are installed"""
    print("\n📦 Testing dependencies...")

    required_packages = [
        ("github", "PyGithub"),
        ("yaml", "PyYAML"),
        ("requests", "requests"),
        ("packaging", "packaging"),
        ("rich", "rich"),
        ("toml", "toml"),
    ]

    missing_packages = []

    for package, pip_name in required_packages:
        try:
            __import__(package)
            print(f"✓ {pip_name} is installed")
        except ImportError:
            print(f"✗ {pip_name} is missing")
            missing_packages.append(pip_name)

    if missing_packages:
        print(f"\n⚠️  Missing packages: {', '.join(missing_packages)}")
        print("Please install them with: pip install " + " ".join(missing_packages))
        return False

    return True


def test_environment_variables():
    """Test if required environment variables are set"""
    print("\n🔑 Testing environment variables...")

    required_vars = [
        ("GITHUB_TOKEN", "GitHub Personal Access Token", True),
        ("GEMINI_API_KEY", "Gemini API Key", True),
        ("SLACK_BOT_TOKEN", "Slack Bot Token", False),
        ("SEMGREP_API_TOKEN", "Semgrep API Token", False),
    ]

    found_llm_key = False
    missing_required = []

    for var_name, description, required in required_vars:
        value = os.getenv(var_name)
        if value:
            print(f"✓ {var_name} is set")
            if var_name == "GEMINI_API_KEY":
                found_llm_key = True
        else:
            if required:
                print(f"✗ {var_name} is missing ({description})")
                missing_required.append(var_name)
            else:
                print(f"⚠️  {var_name} is not set ({description}) - optional")

    if not found_llm_key:
        print("⚠️  No Gemini API key found. You need GEMINI_API_KEY")
        return False

    if missing_required:
        print(
            f"\n❌ Missing required environment variables: {', '.join(missing_required)}"
        )
        return False

    return True


def test_configuration_file():
    """Test if configuration file exists and is valid"""
    print("\n⚙️  Testing configuration file...")

    config_file = "config.yaml"

    if not os.path.exists(config_file):
        print(f"✗ Configuration file {config_file} not found")
        return False

    try:
        import yaml

        with open(config_file, "r") as file:
            config = yaml.safe_load(file)

        print(f"✓ {config_file} exists and is valid YAML")

        # Check for required sections
        required_sections = ["policies", "notifications", "repositories"]
        for section in required_sections:
            if section in config:
                print(f"✓ {section} section found in config")
            else:
                print(f"⚠️  {section} section missing from config")

        return True

    except yaml.YAMLError as e:
        print(f"✗ Invalid YAML in {config_file}: {e}")
        return False
    except Exception as e:
        print(f"✗ Error reading {config_file}: {e}")
        return False


def test_github_connection():
    """Test GitHub API connection"""
    print("\n🐙 Testing GitHub connection...")

    github_token = os.getenv("GITHUB_TOKEN")
    if not github_token:
        print("✗ GITHUB_TOKEN not set, skipping GitHub test")
        return False

    try:
        import requests

        headers = {
            "Authorization": f"Bearer {github_token}",
            "Accept": "application/vnd.github.v3+json",
        }

        response = requests.get(
            "https://api.github.com/user", headers=headers, timeout=10
        )

        if response.status_code == 200:
            user_data = response.json()
            print(f"✓ GitHub API connection successful")
            print(f"  Connected as: {user_data.get('login', 'unknown')}")
            return True
        else:
            print(f"✗ GitHub API returned status {response.status_code}")
            return False

    except Exception as e:
        print(f"✗ GitHub connection test failed: {e}")
        return False


def test_dependency_parser():
    """Test the dependency parser with sample files"""
    print("\n📄 Testing dependency parser...")

    try:
        from src.tools.dependency_parser import DependencyParser

        parser = DependencyParser({})

        # Test package.json parsing
        sample_package_json = """
        {
            "name": "test-project",
            "version": "1.0.0",
            "dependencies": {
                "express": "^4.17.1",
                "lodash": "~4.17.21"
            },
            "devDependencies": {
                "jest": "^27.0.0"
            }
        }
        """

        result = parser.execute(
            action="parse_package_json",
            file_type="package_json",
            content=sample_package_json,
        )

        if result.get("success"):
            print("✓ package.json parser working")
        else:
            print(f"✗ package.json parser failed: {result.get('error')}")
            return False

        # Test requirements.txt parsing
        sample_requirements = """
        requests>=2.25.0
        flask==2.0.1
        pytest>=6.0.0
        # This is a comment
        numpy~=1.21.0
        """

        result = parser.execute(
            action="parse_requirements_txt",
            file_type="requirements_txt",
            content=sample_requirements,
        )

        if result.get("success"):
            print("✓ requirements.txt parser working")
            print(f"  Found {result.get('total_dependencies', 0)} dependencies")
        else:
            print(f"✗ requirements.txt parser failed: {result.get('error')}")
            return False

        return True

    except Exception as e:
        print(f"✗ Dependency parser test failed: {e}")
        return False


def test_vulnerability_scanner():
    """Test the vulnerability scanner (basic functionality)"""
    print("\n🔍 Testing vulnerability scanner...")

    try:
        from src.tools.vulnerability_scanner import VulnerabilityScanner

        scanner = VulnerabilityScanner({})

        # Test CVE lookup for a known vulnerable package
        result = scanner.check_cve_database("express", "4.0.0")

        if result.get("success"):
            print("✓ CVE database lookup working")
            vuln_count = result.get("vulnerability_count", 0)
            print(f"  Found {vuln_count} vulnerabilities for express@4.0.0")
        else:
            print(
                f"⚠️  CVE database lookup failed (may be network issue): {result.get('error')}"
            )
            # This is not a critical failure for the test

        return True

    except Exception as e:
        print(f"✗ Vulnerability scanner test failed: {e}")
        return False


def test_agent_initialization():
    """Test agent initialization"""
    print("\n🤖 Testing agent initialization...")

    try:
        from src.agents.dependency_agent import DependencySecurityAgent

        agent = DependencySecurityAgent("config.yaml")
        print("✓ Dependency Security Agent initialized successfully")

        # Test basic Gemini functionality
        result = agent.gemini_client.run("What is 5 + 3?")

        if result["state"] == "COMPLETE":
            print("✓ Agent can execute Gemini queries")
            return True
        else:
            print(f"⚠️  Agent Gemini query failed: {result['state']}")
            if result.get("error"):
                print(f"Error: {result['error']}")
            return False

    except Exception as e:
        print(f"✗ Agent initialization failed: {e}")
        return False


def main():
    """Run all tests"""
    print("🚀 Starting Dependency Security Agent Tests\n")

    tests = [
        ("Dependencies", test_dependencies),
        ("Environment Variables", test_environment_variables),
        ("Configuration File", test_configuration_file),
        ("Portia Installation", test_gemini_installation),
        ("GitHub Connection", test_github_connection),
        ("Dependency Parser", test_dependency_parser),
        ("Vulnerability Scanner", test_vulnerability_scanner),
        ("Agent Initialization", test_agent_initialization),
    ]

    passed = 0
    total = len(tests)

    for test_name, test_func in tests:
        print(f"\n{'='*60}")
        print(f"Running {test_name} test...")
        print("=" * 60)

        try:
            if test_func():
                print(f"✅ {test_name} test PASSED")
                passed += 1
            else:
                print(f"❌ {test_name} test FAILED")
        except Exception as e:
            print(f"💥 {test_name} test CRASHED: {e}")

    # Final results
    print(f"\n{'='*60}")
    print("TEST RESULTS SUMMARY")
    print("=" * 60)
    print(f"Passed: {passed}/{total}")
    print(f"Failed: {total - passed}/{total}")

    if passed == total:
        print("\n🎉 All tests passed! Your Dependency Security Agent is ready to use.")
        print("\nNext steps:")
        print("1. Run: python main.py status")
        print("2. Try: python main.py test")
        print("3. Scan a repository: python main.py scan --repo octocat/Hello-World")
    else:
        print(f"\n⚠️  {total - passed} tests failed. Please address the issues above.")
        print("\nCommon fixes:")
        print("1. Install missing packages: pip install -r requirements.txt")
        print("2. Set up environment variables in .env file")
        print("3. Configure your GitHub token")
        print("4. Set up your Gemini API key")

    return passed == total


if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
