"""
Configuration Management Module
Handles loading, validation, and management of configuration files
"""

import os
import yaml
import json
from pathlib import Path
from typing import Dict, Any, Optional, List
from dataclasses import dataclass, field
from dotenv import load_dotenv

@dataclass
class SecurityPolicy:
    """Security policy configuration"""
    max_cvss_score: float = 7.0
    require_human_approval_for_critical: bool = True
    auto_fix_low_severity: bool = True
    block_high_severity: bool = True
    allow_auto_merge_low: bool = False

@dataclass
class VersionPolicy:
    """Version update policy configuration"""
    allow_major_versions: bool = False
    allow_minor_versions: bool = True
    allow_patch_versions: bool = True
    require_tests_passing: bool = True
    max_concurrent_updates: int = 5

@dataclass
class NotificationConfig:
    """Notification configuration"""
    slack_enabled: bool = True
    email_enabled: bool = False
    webhook_enabled: bool = False
    slack_channels: Dict[str, str] = field(default_factory=dict)
    email_recipients: List[str] = field(default_factory=list)
    webhook_urls: List[str] = field(default_factory=list)

@dataclass
class RepositoryConfig:
    """Repository configuration"""
    owner: str
    repo: str
    branch: str = "main"
    auto_update: bool = True
    require_approval: bool = False
    excluded_paths: List[str] = field(default_factory=list)

class ConfigManager:
    """Manages configuration loading, validation, and access"""
    
    def __init__(self, config_path: str = "config.yaml", env_path: str = ".env"):
        """Initialize configuration manager"""
        self.config_path = Path(config_path)
        self.env_path = Path(env_path)
        self.config: Dict[str, Any] = {}
        self._load_environment()
        self._load_config()
        self._validate_config()
    
    def _load_environment(self):
        """Load environment variables from .env file"""
        if self.env_path.exists():
            load_dotenv(self.env_path)
        
        # Set default environment variables if not present
        os.environ.setdefault('GITHUB_TOKEN', '')
        os.environ.setdefault('GEMINI_API_KEY', '')
        os.environ.setdefault('SLACK_BOT_TOKEN', '')
        os.environ.setdefault('SLACK_CHANNEL_ID', '')
    
    def _load_config(self):
        """Load configuration from YAML file"""
        if not self.config_path.exists():
            self.config = self._get_default_config()
            self._save_default_config()
        else:
            try:
                with open(self.config_path, 'r', encoding='utf-8') as file:
                    self.config = yaml.safe_load(file) or {}
            except Exception as e:
                print(f"Error loading config: {e}")
                self.config = self._get_default_config()
    
    def _get_default_config(self) -> Dict[str, Any]:
        """Get default configuration"""
        return {
            "agent": {
                "name": "Dependency Security Agent",
                "version": "1.0.0",
                "description": "Automated dependency security and management"
            },
            "policies": {
                "version_updates": {
                    "allow_major_versions": False,
                    "allow_minor_versions": True,
                    "allow_patch_versions": True,
                    "require_tests_passing": True,
                    "max_concurrent_updates": 5
                },
                "security": {
                    "max_cvss_score": 7.0,
                    "require_human_approval_for_critical": True,
                    "auto_fix_low_severity": True,
                    "block_high_severity": True,
                    "allow_auto_merge_low": False
                },
                "allowed_licenses": [
                    "MIT", "Apache-2.0", "BSD-3-Clause", "BSD-2-Clause", "ISC"
                ],
                "blocked_licenses": [
                    "GPL-3.0", "AGPL-3.0", "Commercial"
                ]
            },
            "package_managers": [
                "npm", "pip", "maven", "gradle", "composer", "cargo", "go", "nuget"
            ],
            "scheduling": {
                "scan_frequency": "daily",
                "report_frequency": "weekly",
                "update_check_time": "02:00"
            },
            "notifications": {
                "slack": {
                    "enabled": True,
                    "channels": {
                        "security_alerts": "#security-alerts",
                        "dependency_updates": "#dev-updates",
                        "reports": "#dependency-reports"
                    }
                },
                "email": {
                    "enabled": False,
                    "smtp_server": "smtp.gmail.com",
                    "smtp_port": 587,
                    "recipients": []
                }
            },
            "reporting": {
                "google_sheets": {
                    "enabled": True,
                    "sheet_name": "Dependency Security Dashboard"
                },
                "notion": {
                    "enabled": False,
                    "page_title": "Dependency Health Report"
                }
            },
            "repositories": {
                "monitored": [],
                "exclude_patterns": ["test/*", "docs/*", "examples/*"]
            }
        }
    
    def _save_default_config(self):
        """Save default configuration to file"""
        try:
            with open(self.config_path, 'w', encoding='utf-8') as file:
                yaml.dump(self.config, file, default_flow_style=False, indent=2)
        except Exception as e:
            print(f"Error saving default config: {e}")
    
    def _validate_config(self):
        """Validate configuration values"""
        # Validate required environment variables
        required_env_vars = ['GITHUB_TOKEN']
        missing_env = [var for var in required_env_vars if not os.getenv(var)]
        
        if missing_env:
            print(f"Warning: Missing required environment variables: {missing_env}")
        
        # Validate configuration structure
        if not isinstance(self.config, dict):
            raise ValueError("Configuration must be a dictionary")
        
        # Validate policies
        policies = self.config.get('policies', {})
        if not isinstance(policies, dict):
            raise ValueError("Policies must be a dictionary")
    
    def get(self, key: str, default: Any = None) -> Any:
        """Get configuration value by key (supports dot notation)"""
        keys = key.split('.')
        value = self.config
        
        for k in keys:
            if isinstance(value, dict) and k in value:
                value = value[k]
            else:
                return default
        
        return value
    
    def set(self, key: str, value: Any):
        """Set configuration value by key (supports dot notation)"""
        keys = key.split('.')
        config = self.config
        
        for k in keys[:-1]:
            if k not in config:
                config[k] = {}
            config = config[k]
        
        config[keys[-1]] = value
    
    def get_security_policy(self) -> SecurityPolicy:
        """Get security policy configuration"""
        security = self.get('policies.security', {})
        return SecurityPolicy(
            max_cvss_score=security.get('max_cvss_score', 7.0),
            require_human_approval_for_critical=security.get('require_human_approval_for_critical', True),
            auto_fix_low_severity=security.get('auto_fix_low_severity', True),
            block_high_severity=security.get('block_high_severity', True),
            allow_auto_merge_low=security.get('allow_auto_merge_low', False)
        )
    
    def get_version_policy(self) -> VersionPolicy:
        """Get version update policy configuration"""
        version = self.get('policies.version_updates', {})
        return VersionPolicy(
            allow_major_versions=version.get('allow_major_versions', False),
            allow_minor_versions=version.get('allow_minor_versions', True),
            allow_patch_versions=version.get('allow_patch_versions', True),
            require_tests_passing=version.get('require_tests_passing', True),
            max_concurrent_updates=version.get('max_concurrent_updates', 5)
        )
    
    def get_notification_config(self) -> NotificationConfig:
        """Get notification configuration"""
        notifications = self.get('notifications', {})
        slack = notifications.get('slack', {})
        email = notifications.get('email', {})
        
        return NotificationConfig(
            slack_enabled=slack.get('enabled', True),
            email_enabled=email.get('enabled', False),
            webhook_enabled=notifications.get('webhook', {}).get('enabled', False),
            slack_channels=slack.get('channels', {}),
            email_recipients=email.get('recipients', []),
            webhook_urls=notifications.get('webhook', {}).get('urls', [])
        )
    
    def get_monitored_repositories(self) -> List[RepositoryConfig]:
        """Get list of monitored repositories"""
        repos = self.get('repositories.monitored', [])
        return [
            RepositoryConfig(
                owner=repo.get('owner', ''),
                repo=repo.get('repo', ''),
                branch=repo.get('branch', 'main'),
                auto_update=repo.get('auto_update', True),
                require_approval=repo.get('require_approval', False),
                excluded_paths=repo.get('excluded_paths', [])
            )
            for repo in repos
        ]
    
    def add_repository(self, owner: str, repo: str, branch: str = "main", 
                      auto_update: bool = True, require_approval: bool = False):
        """Add a repository to monitoring"""
        repos = self.get('repositories.monitored', [])
        
        # Check if repository already exists
        for existing_repo in repos:
            if existing_repo.get('owner') == owner and existing_repo.get('repo') == repo:
                existing_repo.update({
                    'branch': branch,
                    'auto_update': auto_update,
                    'require_approval': require_approval
                })
                break
        else:
            repos.append({
                'owner': owner,
                'repo': repo,
                'branch': branch,
                'auto_update': auto_update,
                'require_approval': require_approval
            })
        
        self.set('repositories.monitored', repos)
        self.save_config()
    
    def remove_repository(self, owner: str, repo: str):
        """Remove a repository from monitoring"""
        repos = self.get('repositories.monitored', [])
        repos = [r for r in repos if not (r.get('owner') == owner and r.get('repo') == repo)]
        self.set('repositories.monitored', repos)
        self.save_config()
    
    def save_config(self):
        """Save current configuration to file"""
        try:
            with open(self.config_path, 'w', encoding='utf-8') as file:
                yaml.dump(self.config, file, default_flow_style=False, indent=2)
        except Exception as e:
            print(f"Error saving config: {e}")
    
    def reload_config(self):
        """Reload configuration from file"""
        self._load_config()
        self._validate_config()
    
    def export_config(self, format: str = "yaml") -> str:
        """Export configuration in specified format"""
        if format.lower() == "json":
            return json.dumps(self.config, indent=2)
        elif format.lower() == "yaml":
            return yaml.dump(self.config, default_flow_style=False, indent=2)
        else:
            raise ValueError(f"Unsupported format: {format}")
    
    def validate_api_keys(self) -> Dict[str, bool]:
        """Validate that required API keys are set"""
        return {
            'github_token': bool(os.getenv('GITHUB_TOKEN')),
            'gemini_api_key': bool(os.getenv('GEMINI_API_KEY')),
            'anthropic_api_key': bool(os.getenv('ANTHROPIC_API_KEY')),
            'slack_bot_token': bool(os.getenv('SLACK_BOT_TOKEN'))
        }
