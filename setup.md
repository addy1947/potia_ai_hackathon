# Dependency Security Agent Setup Guide

This guide will help you set up the Dependency Security Agent with **Google Gemini AI** for intelligent dependency analysis and management.

## Prerequisites

- Python 3.8 or higher
- Git
- Active GitHub account with Personal Access Token
- Google Gemini API key

## Installation Steps

### 1. Clone the Repository

```bash
git clone <your-repo-url>
cd dependency-security-agent
```

### 2. Create Virtual Environment

```bash
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

### 3. Install Dependencies

```bash
pip install -r requirements.txt
```

### 4. Environment Configuration

Create a `.env` file in the project root:

```bash
# Required: Gemini API Key for AI-powered analysis
GEMINI_API_KEY=your_gemini_api_key_here

# Required: GitHub Personal Access Token for repository access
GITHUB_TOKEN=your_github_token_here

# Optional: Slack Bot Token for notifications
SLACK_BOT_TOKEN=your_slack_bot_token_here

# Optional: Semgrep API Token for additional security scanning
SEMGREP_API_TOKEN=your_semgrep_api_token_here
```

### 5. Get Your Gemini API Key

1. Visit [Google AI Studio](https://makersuite.google.com/app/apikey)
2. Sign in with your Google account
3. Click "Create API Key"
4. Copy the generated key to your `.env` file

### 6. Get Your GitHub Token

1. Go to [GitHub Settings > Developer settings > Personal access tokens](https://github.com/settings/tokens)
2. Click "Generate new token (classic)"
3. Select scopes: `repo`, `workflow`, `admin:org`
4. Copy the token to your `.env` file

### 7. Test Installation

```bash
# Run comprehensive test suite
python test_agent.py

# Test Gemini AI configuration
python main.py test
```

## Configuration

### Basic Configuration

The agent uses `config.yaml` for configuration. Key sections include:

```yaml
# Repository Configuration
repositories:
  monitored:
    - owner: "your-org"
      repo: "your-repo"
      branch: "main"

# Security Policies
policies:
  security:
    max_cvss_score: 7.0
    require_human_approval_for_critical: true
    auto_fix_low_severity: true

# Notifications
notifications:
  slack:
    enabled: true
    channels:
      security_alerts: "#security-alerts"
```

## Usage Examples

### Scan Dependencies

```bash
# Scan a specific repository
python main.py scan --repo owner/repo-name

# Scan with verbose output
python main.py scan --repo owner/repo-name --verbose
```

### Update Dependencies

```bash
# Update dependencies in a repository
python main.py update --repo owner/repo-name --branch main
```

### Generate Reports

```bash
# Generate security report
python main.py report --repos owner/repo1,owner/repo2
```

## Troubleshooting

### Common Issues

**"GEMINI_API_KEY environment variable is required"**
- Ensure your `.env` file exists and contains the correct API key
- Verify the key is valid at [Google AI Studio](https://makersuite.google.com/app/apikey)

**"GITHUB_TOKEN environment variable is required"**
- Check that your GitHub token has the correct permissions
- Verify the token hasn't expired

**Import errors**
- Ensure you're in the virtual environment
- Run `pip install -r requirements.txt` again

### Getting Help

- Run `python test_agent.py` to diagnose issues
- Check the logs for detailed error messages
- Verify all environment variables are set correctly

## Next Steps

After successful setup:

1. Configure repositories to monitor in `config.yaml`
2. Set up Slack notifications (optional)
3. Configure security policies based on your requirements
4. Set up automated scanning schedules
5. Monitor the generated reports and alerts

The agent is now ready to help you maintain secure and up-to-date dependencies across your repositories!