"""
Notification Tool for Gemini AI Agent
Handles notifications via Slack, email, and other channels
"""

import os
import requests
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from typing import Dict, List, Optional, Any
from ..utils.tool_registry import Tool
from datetime import datetime
import json


class NotificationTool(Tool):
    """Tool for sending notifications through various channels"""

    def __init__(self, config: Dict[str, Any]):
        super().__init__(
            name="notification_tool",
            description="Send notifications via Slack, email, and other channels",
        )
        self.config = config
        # Add required fields for compatibility
        self.id = "notification_tool"
        self.output_schema = {
            "type": "object",
            "properties": {
                "success": {"type": "boolean"},
                "message": {"type": "string"},
                "error": {"type": "string"},
            },
        }
        self.slack_token = os.getenv("SLACK_BOT_TOKEN")
        self.notification_config = config.get("notifications", {})

    def execute(self, **kwargs) -> Any:
        """Execute the notification tool"""
        action = kwargs.get("action", "send_slack_notification")

        if action == "send_slack_notification":
            return self.send_slack_notification(
                kwargs.get("channel"),
                kwargs.get("message"),
                kwargs.get("severity", "info"),
                kwargs.get("attachments"),
            )
        elif action == "send_security_alert":
            return self.send_security_alert(
                kwargs.get("vulnerability_info"), kwargs.get("affected_repos", [])
            )
        elif action == "send_email_notification":
            return self.send_email_notification(
                kwargs.get("recipients"),
                kwargs.get("subject"),
                kwargs.get("message"),
                kwargs.get("severity", "info"),
            )
        elif action == "send_update_notification":
            return self.send_update_notification(
                kwargs.get("repository"), kwargs.get("updates"), kwargs.get("channel")
            )
        else:
            return {
                "error": f"Unknown action: {action}. Supported actions: send_slack_notification, send_security_alert, send_email_notification, send_update_notification"
            }

    def send_slack_notification(
        self,
        channel: str,
        message: str,
        severity: str = "info",
        attachments: List[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Send a notification to Slack

        Args:
            channel: Slack channel (e.g., "#security-alerts")
            message: Main message text
            severity: Severity level (info, warning, error, critical)
            attachments: Optional Slack attachments for rich formatting

        Returns:
            Result of the notification attempt
        """
        if not self.slack_token:
            return {"success": False, "error": "Slack bot token not configured"}

        try:
            # Color coding based on severity
            colors = {
                "info": "#36a64f",  # Green
                "warning": "#ffaa00",  # Orange
                "error": "#ff0000",  # Red
                "critical": "#8B0000",  # Dark Red
            }

            # Build the payload
            payload = {
                "channel": channel,
                "text": message,
                "username": "Dependency Security Agent",
                "icon_emoji": ":shield:",
            }

            # Add attachments if provided, or create a simple colored attachment
            if attachments:
                payload["attachments"] = attachments
            else:
                payload["attachments"] = [
                    {
                        "color": colors.get(severity, "#36a64f"),
                        "text": message,
                        "ts": int(datetime.now().timestamp()),
                    }
                ]

            # Send to Slack
            headers = {
                "Authorization": f"Bearer {self.slack_token}",
                "Content-Type": "application/json",
            }

            response = requests.post(
                "https://slack.com/api/chat.postMessage",
                headers=headers,
                data=json.dumps(payload),
                timeout=30,
            )

            if response.status_code == 200:
                result = response.json()
                if result.get("ok"):
                    return {
                        "success": True,
                        "channel": channel,
                        "timestamp": result.get("ts"),
                        "message_sent": message,
                    }
                else:
                    return {
                        "success": False,
                        "error": result.get("error", "Unknown Slack API error"),
                    }
            else:
                return {
                    "success": False,
                    "error": f"Slack API returned status {response.status_code}",
                }

        except Exception as e:
            return {
                "success": False,
                "error": f"Failed to send Slack notification: {str(e)}",
            }

    def send_security_alert(
        self, vulnerability_info: Dict[str, Any], affected_repos: List[str]
    ) -> Dict[str, Any]:
        """
        Send a security alert notification

        Args:
            vulnerability_info: Information about the vulnerability
            affected_repos: List of affected repositories

        Returns:
            Result of sending the alert
        """
        severity = vulnerability_info.get("severity", {}).get("level", "unknown")
        cve_id = vulnerability_info.get("id", "unknown")
        package_name = vulnerability_info.get("package_name", "unknown")

        # Determine notification severity and channel
        if severity in ["critical", "high"]:
            slack_severity = "critical" if severity == "critical" else "error"
            channel = (
                self.notification_config.get("slack", {})
                .get("channels", {})
                .get("security_alerts", "#security-alerts")
            )
        else:
            slack_severity = "warning"
            channel = (
                self.notification_config.get("slack", {})
                .get("channels", {})
                .get("dependency_updates", "#dev-updates")
            )

        # Format the message
        repo_list = ", ".join(affected_repos[:5])  # Limit to first 5 repos
        if len(affected_repos) > 5:
            repo_list += f" and {len(affected_repos) - 5} more"

        message = f"🚨 Security Alert: {severity.upper()} vulnerability detected"

        # Create rich Slack attachment
        attachment = {
            "color": "#ff0000" if severity == "critical" else "#ffaa00",
            "title": f"Vulnerability Alert: {cve_id}",
            "title_link": f"https://cve.mitre.org/cgi-bin/cvename.cgi?name={cve_id}",
            "fields": [
                {"title": "Package", "value": package_name, "short": True},
                {"title": "Severity", "value": severity.upper(), "short": True},
                {
                    "title": "CVSS Score",
                    "value": str(
                        vulnerability_info.get("severity", {}).get("score", "N/A")
                    ),
                    "short": True,
                },
                {"title": "Affected Repositories", "value": repo_list, "short": False},
            ],
            "footer": "Dependency Security Agent",
            "ts": int(datetime.now().timestamp()),
        }

        # Add summary if available
        if "summary" in vulnerability_info:
            attachment["text"] = vulnerability_info["summary"]

        return self.send_slack_notification(
            channel=channel,
            message=message,
            severity=slack_severity,
            attachments=[attachment],
        )

    def send_update_notification(
        self, updates: List[Dict[str, Any]], repository: str
    ) -> Dict[str, Any]:
        """
        Send notification about dependency updates

        Args:
            updates: List of dependency updates
            repository: Repository name

        Returns:
            Result of sending the notification
        """
        channel = (
            self.notification_config.get("slack", {})
            .get("channels", {})
            .get("dependency_updates", "#dev-updates")
        )

        total_updates = len(updates)
        major_updates = len([u for u in updates if u.get("update_type") == "major"])
        minor_updates = len([u for u in updates if u.get("update_type") == "minor"])
        patch_updates = len([u for u in updates if u.get("update_type") == "patch"])

        message = f"📦 Dependency Updates Available for {repository}"

        # Create Slack attachment
        attachment = {
            "color": "#36a64f",
            "title": f"Dependency Update Summary - {repository}",
            "fields": [
                {"title": "Total Updates", "value": str(total_updates), "short": True},
                {"title": "Major Updates", "value": str(major_updates), "short": True},
                {"title": "Minor Updates", "value": str(minor_updates), "short": True},
                {"title": "Patch Updates", "value": str(patch_updates), "short": True},
            ],
            "footer": "Dependency Security Agent",
            "ts": int(datetime.now().timestamp()),
        }

        # Add details for up to 10 updates
        if updates:
            update_details = []
            for update in updates[:10]:
                package = update.get("package_name", "unknown")
                current = update.get("current_version", "unknown")
                new = update.get("new_version", "unknown")
                update_type = update.get("update_type", "unknown")

                update_details.append(f"• {package}: {current} → {new} ({update_type})")

            if len(updates) > 10:
                update_details.append(f"... and {len(updates) - 10} more updates")

            attachment["text"] = "\n".join(update_details)

        return self.send_slack_notification(
            channel=channel, message=message, severity="info", attachments=[attachment]
        )

    def send_pull_request_notification(
        self, pr_info: Dict[str, Any], repository: str
    ) -> Dict[str, Any]:
        """
        Send notification about created pull requests

        Args:
            pr_info: Pull request information
            repository: Repository name

        Returns:
            Result of sending the notification
        """
        channel = (
            self.notification_config.get("slack", {})
            .get("channels", {})
            .get("dependency_updates", "#dev-updates")
        )

        pr_url = pr_info.get("pr_url", "")
        pr_number = pr_info.get("pr_number", "unknown")
        title = pr_info.get("title", "Dependency Update")

        message = f"🔄 Pull Request Created: {repository}#{pr_number}"

        attachment = {
            "color": "#0066cc",
            "title": title,
            "title_link": pr_url,
            "fields": [
                {"title": "Repository", "value": repository, "short": True},
                {"title": "PR Number", "value": f"#{pr_number}", "short": True},
            ],
            "footer": "Dependency Security Agent",
            "ts": int(datetime.now().timestamp()),
        }

        if "description" in pr_info:
            attachment["text"] = (
                pr_info["description"][:500] + "..."
                if len(pr_info["description"]) > 500
                else pr_info["description"]
            )

        return self.send_slack_notification(
            channel=channel, message=message, severity="info", attachments=[attachment]
        )

    def send_email_notification(
        self, recipient: str, subject: str, body: str, html_body: str = None
    ) -> Dict[str, Any]:
        """
        Send email notification

        Args:
            recipient: Email recipient
            subject: Email subject
            body: Plain text body
            html_body: Optional HTML body

        Returns:
            Result of sending the email
        """
        email_config = self.notification_config.get("email", {})

        if not email_config.get("enabled", False):
            return {"success": False, "error": "Email notifications are disabled"}

        smtp_server = email_config.get("smtp_server", "smtp.gmail.com")
        smtp_port = email_config.get("smtp_port", 587)
        username = os.getenv("EMAIL_USERNAME")
        password = os.getenv("EMAIL_PASSWORD")

        if not username or not password:
            return {"success": False, "error": "Email credentials not configured"}

        try:
            # Create message
            msg = MIMEMultipart("alternative")
            msg["Subject"] = subject
            msg["From"] = username
            msg["To"] = recipient

            # Add plain text part
            text_part = MIMEText(body, "plain")
            msg.attach(text_part)

            # Add HTML part if provided
            if html_body:
                html_part = MIMEText(html_body, "html")
                msg.attach(html_part)

            # Send email
            with smtplib.SMTP(smtp_server, smtp_port) as server:
                server.starttls()
                server.login(username, password)
                server.send_message(msg)

            return {"success": True, "recipient": recipient, "subject": subject}

        except Exception as e:
            return {"success": False, "error": f"Failed to send email: {str(e)}"}

    def send_weekly_report_notification(
        self, report_data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Send weekly dependency health report notification

        Args:
            report_data: Weekly report data

        Returns:
            Result of sending the notification
        """
        channel = (
            self.notification_config.get("slack", {})
            .get("channels", {})
            .get("reports", "#dependency-reports")
        )

        summary = report_data.get("summary", {})
        total_repos = summary.get("total_repositories", 0)
        vulnerable_repos = summary.get("vulnerable_repositories", 0)
        total_vulnerabilities = summary.get("total_vulnerabilities", 0)
        outdated_packages = summary.get("outdated_packages", 0)

        message = f"📊 Weekly Dependency Security Report"

        # Determine color based on health status
        if vulnerable_repos == 0:
            color = "#36a64f"  # Green - all good
        elif vulnerable_repos < total_repos * 0.3:
            color = "#ffaa00"  # Orange - some issues
        else:
            color = "#ff0000"  # Red - many issues

        attachment = {
            "color": color,
            "title": "Weekly Dependency Health Report",
            "fields": [
                {
                    "title": "Monitored Repositories",
                    "value": str(total_repos),
                    "short": True,
                },
                {
                    "title": "Repositories with Vulnerabilities",
                    "value": str(vulnerable_repos),
                    "short": True,
                },
                {
                    "title": "Total Vulnerabilities",
                    "value": str(total_vulnerabilities),
                    "short": True,
                },
                {
                    "title": "Outdated Packages",
                    "value": str(outdated_packages),
                    "short": True,
                },
            ],
            "footer": "Dependency Security Agent - Weekly Report",
            "ts": int(datetime.now().timestamp()),
        }

        # Add severity breakdown if available
        severity_breakdown = summary.get("severity_breakdown", {})
        if severity_breakdown:
            severity_text = []
            for level, count in severity_breakdown.items():
                if count > 0:
                    emoji = {
                        "critical": "🔴",
                        "high": "🟠",
                        "medium": "🟡",
                        "low": "🔵",
                    }.get(level, "⚪")
                    severity_text.append(f"{emoji} {level.title()}: {count}")

            if severity_text:
                attachment["fields"].append(
                    {
                        "title": "Vulnerability Breakdown",
                        "value": "\n".join(severity_text),
                        "short": False,
                    }
                )

        return self.send_slack_notification(
            channel=channel, message=message, severity="info", attachments=[attachment]
        )

    def send_emergency_alert(
        self, cve_id: str, affected_packages: List[str], severity: str = "critical"
    ) -> Dict[str, Any]:
        """
        Send emergency security alert for critical CVEs

        Args:
            cve_id: CVE identifier
            affected_packages: List of affected package names
            severity: Severity level

        Returns:
            Result of sending the emergency alert
        """
        # Send to security alerts channel
        security_channel = (
            self.notification_config.get("slack", {})
            .get("channels", {})
            .get("security_alerts", "#security-alerts")
        )

        message = f"🚨🚨 EMERGENCY SECURITY ALERT 🚨🚨\n{cve_id} - {severity.upper()}"

        package_list = ", ".join(affected_packages[:10])
        if len(affected_packages) > 10:
            package_list += f" and {len(affected_packages) - 10} more"

        attachment = {
            "color": "#8B0000",  # Dark red for emergency
            "title": f"EMERGENCY: {cve_id}",
            "title_link": f"https://cve.mitre.org/cgi-bin/cvename.cgi?name={cve_id}",
            "fields": [
                {"title": "Severity", "value": severity.upper(), "short": True},
                {"title": "Affected Packages", "value": package_list, "short": False},
                {
                    "title": "Action Required",
                    "value": "Immediate review and patching required",
                    "short": False,
                },
            ],
            "footer": "Dependency Security Agent - EMERGENCY ALERT",
            "ts": int(datetime.now().timestamp()),
        }

        slack_result = self.send_slack_notification(
            channel=security_channel,
            message=message,
            severity="critical",
            attachments=[attachment],
        )

        # Also try to send email if configured
        email_recipients = self.notification_config.get("email", {}).get(
            "recipients", []
        )
        email_results = []

        for recipient in email_recipients:
            email_body = f"""
EMERGENCY SECURITY ALERT

CVE: {cve_id}
Severity: {severity.upper()}
Affected Packages: {package_list}

Immediate action required. Please review and patch affected systems.

This is an automated alert from the Dependency Security Agent.
            """.strip()

            email_result = self.send_email_notification(
                recipient=recipient,
                subject=f"EMERGENCY: {cve_id} Security Alert",
                body=email_body,
            )
            email_results.append(email_result)

        return {
            "slack_notification": slack_result,
            "email_notifications": email_results,
            "emergency_alert_sent": True,
        }
