"""
Reporting Tool for Gemini AI Agent
Generates and exports dependency security reports
"""

import json
import csv
from typing import Dict, List, Optional, Any
from ..utils.tool_registry import Tool
from datetime import datetime, timedelta
import requests
import os


class ReportingTool(Tool):
    """Tool for generating and managing dependency security reports"""

    def __init__(self, config: Dict[str, Any]):
        super().__init__(
            name="reporting_tool",
            description="Generate and manage dependency security reports via Google Sheets, Notion, etc.",
        )
        self.config = config
        # Add required fields for compatibility
        self.id = "reporting_tool"
        self.output_schema = {
            "type": "object",
            "properties": {
                "success": {"type": "boolean"},
                "report_data": {"type": "object"},
                "error": {"type": "string"},
            },
        }
        self.reporting_config = config.get("reporting", {})

    def execute(self, **kwargs) -> Any:
        """Execute the reporting tool"""
        action = kwargs.get("action", "generate_security_dashboard")

        if action == "generate_security_dashboard":
            return self.generate_security_dashboard(
                kwargs.get("scan_results", []), kwargs.get("repository_list", [])
            )
        elif action == "export_to_csv":
            return self.export_to_csv(
                kwargs.get("data"), kwargs.get("filename"), kwargs.get("report_type")
            )
        elif action == "export_to_json":
            return self.export_to_json(kwargs.get("data"), kwargs.get("filename"))
        elif action == "generate_weekly_report":
            return self.generate_weekly_report(
                kwargs.get("repositories"),
                kwargs.get("start_date"),
                kwargs.get("end_date"),
            )
        else:
            return {
                "error": f"Unknown action: {action}. Supported actions: generate_security_dashboard, export_to_csv, export_to_json, generate_weekly_report"
            }

    def generate_security_dashboard(
        self, scan_results: List[Dict[str, Any]], repository_list: List[str]
    ) -> Dict[str, Any]:
        """
        Generate a comprehensive security dashboard

        Args:
            scan_results: List of vulnerability scan results for each repository
            repository_list: List of repository names

        Returns:
            Dashboard data structure
        """
        dashboard = {
            "generated_at": datetime.now().isoformat(),
            "summary": {
                "total_repositories": len(repository_list),
                "scanned_repositories": len(
                    [r for r in scan_results if r.get("success", False)]
                ),
                "vulnerable_repositories": 0,
                "total_vulnerabilities": 0,
                "total_packages": 0,
                "outdated_packages": 0,
                "severity_breakdown": {
                    "critical": 0,
                    "high": 0,
                    "medium": 0,
                    "low": 0,
                    "unknown": 0,
                },
            },
            "repositories": {},
            "top_vulnerabilities": [],
            "recommendations": [],
            "trends": {
                "vulnerability_trend": "stable",  # up, down, stable
                "package_health_score": 0,
                "compliance_rate": 0,
            },
        }

        all_vulnerabilities = []

        # Process each repository's scan results
        for i, result in enumerate(scan_results):
            if not result.get("success", False):
                continue

            repo_name = repository_list[i] if i < len(repository_list) else f"repo_{i}"

            repo_data = {
                "name": repo_name,
                "scan_timestamp": result.get(
                    "scan_timestamp", datetime.now().isoformat()
                ),
                "total_packages": result.get("scanned_packages", 0),
                "vulnerable_packages": result.get("vulnerable_packages", 0),
                "vulnerabilities": result.get("total_vulnerabilities", 0),
                "severity_breakdown": {
                    "critical": result.get("critical_vulnerabilities", 0),
                    "high": result.get("high_vulnerabilities", 0),
                    "medium": result.get("medium_vulnerabilities", 0),
                    "low": result.get("low_vulnerabilities", 0),
                },
                "health_score": self._calculate_health_score(result),
                "risk_level": self._determine_risk_level(result),
            }

            dashboard["repositories"][repo_name] = repo_data

            # Update summary statistics
            dashboard["summary"]["total_packages"] += repo_data["total_packages"]
            dashboard["summary"]["total_vulnerabilities"] += repo_data[
                "vulnerabilities"
            ]

            if repo_data["vulnerabilities"] > 0:
                dashboard["summary"]["vulnerable_repositories"] += 1

            # Update severity breakdown
            for severity, count in repo_data["severity_breakdown"].items():
                dashboard["summary"]["severity_breakdown"][severity] += count

            # Collect individual vulnerabilities for top vulnerabilities list
            packages = result.get("packages", {})
            for package_name, package_data in packages.items():
                for vuln in package_data.get("vulnerabilities", []):
                    vuln_copy = vuln.copy()
                    vuln_copy["repository"] = repo_name
                    vuln_copy["package_name"] = package_name
                    all_vulnerabilities.append(vuln_copy)

        # Generate top vulnerabilities (sorted by severity and CVSS score)
        sorted_vulns = sorted(
            all_vulnerabilities,
            key=lambda v: (
                {"critical": 4, "high": 3, "medium": 2, "low": 1, "unknown": 0}.get(
                    v.get("severity", {}).get("level", "unknown"), 0
                ),
                v.get("severity", {}).get("score", 0),
            ),
            reverse=True,
        )

        dashboard["top_vulnerabilities"] = sorted_vulns[:20]  # Top 20 most severe

        # Calculate trends and scores
        dashboard["trends"]["package_health_score"] = (
            self._calculate_overall_health_score(dashboard)
        )
        dashboard["trends"]["compliance_rate"] = self._calculate_compliance_rate(
            dashboard
        )

        # Generate recommendations
        dashboard["recommendations"] = self._generate_dashboard_recommendations(
            dashboard
        )

        return dashboard

    def create_google_sheets_report(
        self, dashboard_data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Create or update a Google Sheets report with dashboard data

        Args:
            dashboard_data: Dashboard data to populate in sheets

        Returns:
            Result of the sheet creation/update
        """
        # This is a simplified implementation - in practice, you'd use Google Sheets API
        # For now, we'll return a structured format that could be used with the API

        sheets_config = self.reporting_config.get("google_sheets", {})
        if not sheets_config.get("enabled", False):
            return {"success": False, "error": "Google Sheets reporting is disabled"}

        # Prepare sheets data structure
        sheets_data = {
            "spreadsheet_name": sheets_config.get(
                "sheet_name", "Dependency Security Dashboard"
            ),
            "sheets": [
                {
                    "name": "Summary",
                    "data": self._format_summary_sheet_data(dashboard_data),
                },
                {
                    "name": "Repository Details",
                    "data": self._format_repository_sheet_data(dashboard_data),
                },
                {
                    "name": "Top Vulnerabilities",
                    "data": self._format_vulnerabilities_sheet_data(dashboard_data),
                },
                {
                    "name": "Trends",
                    "data": self._format_trends_sheet_data(dashboard_data),
                },
            ],
            "last_updated": datetime.now().isoformat(),
        }

        # In a real implementation, you would:
        # 1. Authenticate with Google Sheets API
        # 2. Create or update the spreadsheet
        # 3. Populate the data

        return {
            "success": True,
            "spreadsheet_data": sheets_data,
            "message": "Google Sheets data prepared (integration needed for actual API calls)",
            "url": f"https://docs.google.com/spreadsheets/d/{sheets_config.get('spreadsheet_id', 'YOUR_SHEET_ID')}",
        }

    def create_notion_report(self, dashboard_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Create or update a Notion page with dashboard data

        Args:
            dashboard_data: Dashboard data to populate in Notion

        Returns:
            Result of the Notion page creation/update
        """
        notion_config = self.reporting_config.get("notion", {})
        if not notion_config.get("enabled", False):
            return {"success": False, "error": "Notion reporting is disabled"}

        notion_api_key = os.getenv("NOTION_API_KEY")
        database_id = os.getenv("NOTION_DATABASE_ID")

        if not notion_api_key or not database_id:
            return {"success": False, "error": "Notion API credentials not configured"}

        # Prepare Notion page content
        notion_page = {
            "title": f"Dependency Security Report - {datetime.now().strftime('%Y-%m-%d')}",
            "content": self._format_notion_content(dashboard_data),
            "database_id": database_id,
        }

        # In a real implementation, you would make API calls to Notion
        return {
            "success": True,
            "notion_page": notion_page,
            "message": "Notion page data prepared (integration needed for actual API calls)",
        }

    def generate_weekly_report(
        self, weekly_data: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """
        Generate a weekly trend report

        Args:
            weekly_data: List of daily dashboard data for the week

        Returns:
            Weekly report data
        """
        if not weekly_data:
            return {"success": False, "error": "No data provided for weekly report"}

        # Calculate week-over-week trends
        current_week = weekly_data[-7:] if len(weekly_data) >= 7 else weekly_data
        previous_week = weekly_data[-14:-7] if len(weekly_data) >= 14 else []

        weekly_report = {
            "report_period": {
                "start_date": (
                    current_week[0].get("generated_at", "unknown")
                    if current_week
                    else "unknown"
                ),
                "end_date": (
                    current_week[-1].get("generated_at", "unknown")
                    if current_week
                    else "unknown"
                ),
                "days_included": len(current_week),
            },
            "summary": self._calculate_weekly_summary(current_week),
            "trends": self._calculate_weekly_trends(current_week, previous_week),
            "top_issues": self._identify_top_weekly_issues(current_week),
            "improvements": self._identify_improvements(current_week, previous_week),
            "recommendations": self._generate_weekly_recommendations(
                current_week, previous_week
            ),
        }

        return {
            "success": True,
            "weekly_report": weekly_report,
            "generated_at": datetime.now().isoformat(),
        }

    def export_csv_report(self, dashboard_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Export dashboard data as CSV format

        Args:
            dashboard_data: Dashboard data to export

        Returns:
            CSV data structure
        """
        csv_data = {
            "summary_csv": self._format_summary_csv(dashboard_data),
            "repositories_csv": self._format_repositories_csv(dashboard_data),
            "vulnerabilities_csv": self._format_vulnerabilities_csv(dashboard_data),
        }

        return {
            "success": True,
            "csv_data": csv_data,
            "filename": f"dependency_security_report_{datetime.now().strftime('%Y%m%d')}.csv",
        }

    def _calculate_health_score(self, scan_result: Dict[str, Any]) -> float:
        """Calculate health score for a repository (0-100)"""
        total_packages = scan_result.get("scanned_packages", 1)
        vulnerable_packages = scan_result.get("vulnerable_packages", 0)
        critical_vulns = scan_result.get("critical_vulnerabilities", 0)
        high_vulns = scan_result.get("high_vulnerabilities", 0)
        medium_vulns = scan_result.get("medium_vulnerabilities", 0)

        # Start with 100 and subtract points for issues
        score = 100.0

        # Subtract points based on vulnerability ratio
        vuln_ratio = vulnerable_packages / total_packages if total_packages > 0 else 0
        score -= vuln_ratio * 30  # Up to 30 points for vulnerability ratio

        # Subtract points for high-severity vulnerabilities
        score -= critical_vulns * 20  # 20 points per critical vulnerability
        score -= high_vulns * 10  # 10 points per high vulnerability
        score -= medium_vulns * 2  # 2 points per medium vulnerability

        return max(0.0, min(100.0, score))

    def _determine_risk_level(self, scan_result: Dict[str, Any]) -> str:
        """Determine risk level for a repository"""
        critical_vulns = scan_result.get("critical_vulnerabilities", 0)
        high_vulns = scan_result.get("high_vulnerabilities", 0)
        health_score = self._calculate_health_score(scan_result)

        if critical_vulns > 0 or health_score < 30:
            return "critical"
        elif high_vulns > 0 or health_score < 60:
            return "high"
        elif health_score < 80:
            return "medium"
        else:
            return "low"

    def _calculate_overall_health_score(self, dashboard: Dict[str, Any]) -> float:
        """Calculate overall health score across all repositories"""
        repo_scores = []
        for repo_data in dashboard["repositories"].values():
            repo_scores.append(repo_data.get("health_score", 0))

        return sum(repo_scores) / len(repo_scores) if repo_scores else 0

    def _calculate_compliance_rate(self, dashboard: Dict[str, Any]) -> float:
        """Calculate compliance rate (percentage of repositories with no critical/high vulnerabilities)"""
        total_repos = dashboard["summary"]["total_repositories"]
        if total_repos == 0:
            return 100.0

        compliant_repos = 0
        for repo_data in dashboard["repositories"].values():
            if (
                repo_data["severity_breakdown"]["critical"] == 0
                and repo_data["severity_breakdown"]["high"] == 0
            ):
                compliant_repos += 1

        return (compliant_repos / total_repos) * 100

    def _generate_dashboard_recommendations(
        self, dashboard: Dict[str, Any]
    ) -> List[str]:
        """Generate recommendations based on dashboard data"""
        recommendations = []
        summary = dashboard["summary"]

        if summary["severity_breakdown"]["critical"] > 0:
            recommendations.append(
                f"URGENT: {summary['severity_breakdown']['critical']} critical vulnerabilities require immediate attention"
            )

        if summary["severity_breakdown"]["high"] > 0:
            recommendations.append(
                f"HIGH PRIORITY: {summary['severity_breakdown']['high']} high-severity vulnerabilities should be addressed within 7 days"
            )

        vulnerable_ratio = (
            summary["vulnerable_repositories"] / summary["total_repositories"]
            if summary["total_repositories"] > 0
            else 0
        )
        if vulnerable_ratio > 0.5:
            recommendations.append(
                f"More than 50% of repositories have vulnerabilities. Consider implementing automated dependency updates."
            )

        health_score = dashboard["trends"]["package_health_score"]
        if health_score < 70:
            recommendations.append(
                f"Overall package health score is {health_score:.1f}/100. Focus on updating vulnerable dependencies."
            )

        compliance_rate = dashboard["trends"]["compliance_rate"]
        if compliance_rate < 80:
            recommendations.append(
                f"Compliance rate is {compliance_rate:.1f}%. Aim to get all repositories free of critical/high vulnerabilities."
            )

        return recommendations

    def _format_summary_sheet_data(self, dashboard: Dict[str, Any]) -> List[List[str]]:
        """Format data for the summary sheet"""
        summary = dashboard["summary"]
        return [
            ["Metric", "Value", "Status"],
            ["Total Repositories", str(summary["total_repositories"]), ""],
            ["Scanned Repositories", str(summary["scanned_repositories"]), ""],
            ["Vulnerable Repositories", str(summary["vulnerable_repositories"]), ""],
            ["Total Vulnerabilities", str(summary["total_vulnerabilities"]), ""],
            [
                "Critical Vulnerabilities",
                str(summary["severity_breakdown"]["critical"]),
                "🔴" if summary["severity_breakdown"]["critical"] > 0 else "✅",
            ],
            [
                "High Vulnerabilities",
                str(summary["severity_breakdown"]["high"]),
                "🟠" if summary["severity_breakdown"]["high"] > 0 else "✅",
            ],
            [
                "Medium Vulnerabilities",
                str(summary["severity_breakdown"]["medium"]),
                "🟡" if summary["severity_breakdown"]["medium"] > 0 else "✅",
            ],
            [
                "Low Vulnerabilities",
                str(summary["severity_breakdown"]["low"]),
                "🔵" if summary["severity_breakdown"]["low"] > 0 else "✅",
            ],
            [
                "Package Health Score",
                f"{dashboard['trends']['package_health_score']:.1f}/100",
                "",
            ],
            ["Compliance Rate", f"{dashboard['trends']['compliance_rate']:.1f}%", ""],
            ["Report Generated", dashboard["generated_at"], ""],
        ]

    def _format_repository_sheet_data(
        self, dashboard: Dict[str, Any]
    ) -> List[List[str]]:
        """Format data for the repository details sheet"""
        headers = [
            "Repository",
            "Total Packages",
            "Vulnerable Packages",
            "Total Vulnerabilities",
            "Critical",
            "High",
            "Medium",
            "Low",
            "Health Score",
            "Risk Level",
        ]
        rows = [headers]

        for repo_name, repo_data in dashboard["repositories"].items():
            row = [
                repo_name,
                str(repo_data["total_packages"]),
                str(repo_data["vulnerable_packages"]),
                str(repo_data["vulnerabilities"]),
                str(repo_data["severity_breakdown"]["critical"]),
                str(repo_data["severity_breakdown"]["high"]),
                str(repo_data["severity_breakdown"]["medium"]),
                str(repo_data["severity_breakdown"]["low"]),
                f"{repo_data['health_score']:.1f}",
                repo_data["risk_level"].upper(),
            ]
            rows.append(row)

        return rows

    def _format_vulnerabilities_sheet_data(
        self, dashboard: Dict[str, Any]
    ) -> List[List[str]]:
        """Format data for the vulnerabilities sheet"""
        headers = [
            "CVE ID",
            "Package",
            "Repository",
            "Severity",
            "CVSS Score",
            "Summary",
            "Fixed Versions",
        ]
        rows = [headers]

        for vuln in dashboard["top_vulnerabilities"]:
            fixed_versions = ", ".join(vuln.get("fixed_versions", []))
            row = [
                vuln.get("id", "N/A"),
                vuln.get("package_name", "N/A"),
                vuln.get("repository", "N/A"),
                vuln.get("severity", {}).get("level", "unknown").upper(),
                str(vuln.get("severity", {}).get("score", "N/A")),
                (
                    vuln.get("summary", "")[:100] + "..."
                    if len(vuln.get("summary", "")) > 100
                    else vuln.get("summary", "")
                ),
                fixed_versions,
            ]
            rows.append(row)

        return rows

    def _format_trends_sheet_data(self, dashboard: Dict[str, Any]) -> List[List[str]]:
        """Format data for the trends sheet"""
        return [
            ["Metric", "Value", "Trend"],
            [
                "Package Health Score",
                f"{dashboard['trends']['package_health_score']:.1f}/100",
                dashboard["trends"].get("vulnerability_trend", "stable"),
            ],
            [
                "Compliance Rate",
                f"{dashboard['trends']['compliance_rate']:.1f}%",
                "stable",
            ],
            ["Generated At", dashboard["generated_at"], ""],
        ]

    def _format_notion_content(self, dashboard: Dict[str, Any]) -> Dict[str, Any]:
        """Format content for Notion page"""
        return {
            "summary_section": {
                "type": "heading_2",
                "content": "Executive Summary",
                "data": dashboard["summary"],
            },
            "repositories_section": {
                "type": "heading_2",
                "content": "Repository Analysis",
                "data": dashboard["repositories"],
            },
            "vulnerabilities_section": {
                "type": "heading_2",
                "content": "Top Vulnerabilities",
                "data": dashboard["top_vulnerabilities"][:10],
            },
            "recommendations_section": {
                "type": "heading_2",
                "content": "Recommendations",
                "data": dashboard["recommendations"],
            },
        }

    def _calculate_weekly_summary(
        self, week_data: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """Calculate summary statistics for the week"""
        if not week_data:
            return {}

        latest = week_data[-1]["summary"] if week_data else {}

        return {
            "average_vulnerabilities_per_day": sum(
                d.get("summary", {}).get("total_vulnerabilities", 0) for d in week_data
            )
            / len(week_data),
            "peak_vulnerabilities": max(
                d.get("summary", {}).get("total_vulnerabilities", 0) for d in week_data
            ),
            "repositories_scanned": latest.get("total_repositories", 0),
            "final_vulnerability_count": latest.get("total_vulnerabilities", 0),
            "final_health_score": (
                week_data[-1].get("trends", {}).get("package_health_score", 0)
                if week_data
                else 0
            ),
        }

    def _calculate_weekly_trends(
        self, current_week: List[Dict[str, Any]], previous_week: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """Calculate week-over-week trends"""
        if not current_week:
            return {}

        current_vulns = (
            current_week[-1].get("summary", {}).get("total_vulnerabilities", 0)
        )
        current_health = (
            current_week[-1].get("trends", {}).get("package_health_score", 0)
        )

        trends = {
            "vulnerability_change": 0,
            "health_score_change": 0,
            "vulnerability_trend": "stable",
            "health_trend": "stable",
        }

        if previous_week:
            previous_vulns = (
                previous_week[-1].get("summary", {}).get("total_vulnerabilities", 0)
            )
            previous_health = (
                previous_week[-1].get("trends", {}).get("package_health_score", 0)
            )

            trends["vulnerability_change"] = current_vulns - previous_vulns
            trends["health_score_change"] = current_health - previous_health

            if trends["vulnerability_change"] > 0:
                trends["vulnerability_trend"] = "up"
            elif trends["vulnerability_change"] < 0:
                trends["vulnerability_trend"] = "down"

            if trends["health_score_change"] > 0:
                trends["health_trend"] = "up"
            elif trends["health_score_change"] < 0:
                trends["health_trend"] = "down"

        return trends

    def _identify_top_weekly_issues(
        self, week_data: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """Identify the top issues from the week"""
        if not week_data:
            return []

        latest_data = week_data[-1]
        issues = []

        # Critical vulnerabilities
        critical_count = (
            latest_data.get("summary", {})
            .get("severity_breakdown", {})
            .get("critical", 0)
        )
        if critical_count > 0:
            issues.append(
                {
                    "type": "critical_vulnerabilities",
                    "count": critical_count,
                    "priority": "urgent",
                    "description": f"{critical_count} critical vulnerabilities require immediate attention",
                }
            )

        # Low health score repositories
        low_health_repos = []
        for repo_name, repo_data in latest_data.get("repositories", {}).items():
            if repo_data.get("health_score", 100) < 50:
                low_health_repos.append(repo_name)

        if low_health_repos:
            issues.append(
                {
                    "type": "low_health_repositories",
                    "count": len(low_health_repos),
                    "priority": "high",
                    "description": f"{len(low_health_repos)} repositories have health scores below 50%",
                    "affected_repos": low_health_repos[:5],  # Limit to first 5
                }
            )

        return sorted(
            issues,
            key=lambda x: {"urgent": 3, "high": 2, "medium": 1, "low": 0}.get(
                x["priority"], 0
            ),
            reverse=True,
        )

    def _identify_improvements(
        self, current_week: List[Dict[str, Any]], previous_week: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """Identify improvements made during the week"""
        improvements = []

        if not current_week or not previous_week:
            return improvements

        current_vulns = (
            current_week[-1].get("summary", {}).get("total_vulnerabilities", 0)
        )
        previous_vulns = (
            previous_week[-1].get("summary", {}).get("total_vulnerabilities", 0)
        )

        if current_vulns < previous_vulns:
            improvements.append(
                {
                    "type": "vulnerability_reduction",
                    "description": f"Reduced total vulnerabilities from {previous_vulns} to {current_vulns}",
                    "impact": previous_vulns - current_vulns,
                }
            )

        current_health = (
            current_week[-1].get("trends", {}).get("package_health_score", 0)
        )
        previous_health = (
            previous_week[-1].get("trends", {}).get("package_health_score", 0)
        )

        if current_health > previous_health:
            improvements.append(
                {
                    "type": "health_score_improvement",
                    "description": f"Improved overall health score from {previous_health:.1f} to {current_health:.1f}",
                    "impact": current_health - previous_health,
                }
            )

        return improvements

    def _generate_weekly_recommendations(
        self, current_week: List[Dict[str, Any]], previous_week: List[Dict[str, Any]]
    ) -> List[str]:
        """Generate recommendations for the upcoming week"""
        recommendations = []

        if not current_week:
            return recommendations

        latest = current_week[-1]
        critical_vulns = (
            latest.get("summary", {}).get("severity_breakdown", {}).get("critical", 0)
        )

        if critical_vulns > 0:
            recommendations.append(
                "Priority 1: Address all critical vulnerabilities immediately"
            )

        health_score = latest.get("trends", {}).get("package_health_score", 0)
        if health_score < 70:
            recommendations.append(
                "Priority 2: Focus on improving overall package health score through dependency updates"
            )

        vulnerable_repos = latest.get("summary", {}).get("vulnerable_repositories", 0)
        total_repos = latest.get("summary", {}).get("total_repositories", 1)

        if vulnerable_repos / total_repos > 0.5:
            recommendations.append(
                "Priority 3: Implement automated dependency scanning for remaining repositories"
            )

        return recommendations

    def _format_summary_csv(self, dashboard: Dict[str, Any]) -> str:
        """Format summary data as CSV"""
        lines = ["Metric,Value"]
        summary = dashboard["summary"]

        lines.extend(
            [
                f"Total Repositories,{summary['total_repositories']}",
                f"Vulnerable Repositories,{summary['vulnerable_repositories']}",
                f"Total Vulnerabilities,{summary['total_vulnerabilities']}",
                f"Critical Vulnerabilities,{summary['severity_breakdown']['critical']}",
                f"High Vulnerabilities,{summary['severity_breakdown']['high']}",
                f"Medium Vulnerabilities,{summary['severity_breakdown']['medium']}",
                f"Low Vulnerabilities,{summary['severity_breakdown']['low']}",
                f"Health Score,{dashboard['trends']['package_health_score']:.1f}",
                f"Compliance Rate,{dashboard['trends']['compliance_rate']:.1f}%",
            ]
        )

        return "\n".join(lines)

    def _format_repositories_csv(self, dashboard: Dict[str, Any]) -> str:
        """Format repository data as CSV"""
        lines = [
            "Repository,Total Packages,Vulnerable Packages,Vulnerabilities,Critical,High,Medium,Low,Health Score,Risk Level"
        ]

        for repo_name, repo_data in dashboard["repositories"].items():
            line = f"{repo_name},{repo_data['total_packages']},{repo_data['vulnerable_packages']},{repo_data['vulnerabilities']},{repo_data['severity_breakdown']['critical']},{repo_data['severity_breakdown']['high']},{repo_data['severity_breakdown']['medium']},{repo_data['severity_breakdown']['low']},{repo_data['health_score']:.1f},{repo_data['risk_level']}"
            lines.append(line)

        return "\n".join(lines)

    def _format_vulnerabilities_csv(self, dashboard: Dict[str, Any]) -> str:
        """Format vulnerabilities data as CSV"""
        lines = ["CVE ID,Package,Repository,Severity,CVSS Score,Summary"]

        for vuln in dashboard["top_vulnerabilities"]:
            summary = (
                vuln.get("summary", "").replace(",", ";").replace("\n", " ")
            )  # Clean CSV
            line = f"{vuln.get('id', 'N/A')},{vuln.get('package_name', 'N/A')},{vuln.get('repository', 'N/A')},{vuln.get('severity', {}).get('level', 'unknown')},{vuln.get('severity', {}).get('score', 'N/A')},{summary}"
            lines.append(line)

        return "\n".join(lines)

    def run(self, **kwargs) -> Dict[str, Any]:
        """
        Main run method for the reporting tool
        """
        operation = kwargs.get("operation")

        if operation == "generate_dashboard":
            return {
                "success": True,
                "dashboard": self.generate_security_dashboard(
                    kwargs["scan_results"], kwargs["repository_list"]
                ),
            }
        elif operation == "create_sheets_report":
            return self.create_google_sheets_report(kwargs["dashboard_data"])
        elif operation == "create_notion_report":
            return self.create_notion_report(kwargs["dashboard_data"])
        elif operation == "generate_weekly_report":
            return self.generate_weekly_report(kwargs["weekly_data"])
        elif operation == "export_csv":
            return self.export_csv_report(kwargs["dashboard_data"])
        else:
            return {"error": f"Unknown operation: {operation}"}
