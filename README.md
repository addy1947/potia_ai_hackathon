# Dependency Security Agent

A powerful, AI-powered dependency security and management agent that automatically scans, analyzes, and manages dependencies across multiple repositories. Built with **Google Gemini AI** and **Portia-ai sdk** for intelligent analysis and decision-making.

## 🚀 Features

- **AI-Powered Analysis**: Uses Google Gemini AI for intelligent dependency analysis and recommendations
- **Multi-Repository Support**: Monitor and manage dependencies across multiple GitHub repositories
- **Automated Security Scanning**: Detect vulnerabilities using Semgrep and CVE databases
- **Policy Enforcement**: Configurable security and update policies
- **Smart Notifications**: Slack and email notifications with intelligent alerting
- **Comprehensive Reporting**: Generate detailed security dashboards and reports
- **Multi-Package Manager Support**: npm, pip, Maven, Gradle, Composer, Cargo, Go modules, and more

## 🛠️ Technology Stack

- **AI Engine**: Google Gemini AI (replacing OpenAI/Portia)
- **Language**: Python 3.8+
- **Package Managers**: npm, pip, Maven, Gradle, Composer, Cargo, Go modules
- **Security Tools**: Semgrep, CVE databases
- **Notifications**: Slack, Email
- **Reporting**: CSV, JSON, Google Sheets integration

## 🛠️ Comprehensive Tool List: Documents all Portia AI tools and integrations including:

- Semgrep for security scanning
- Bright Data for CVE intelligence
- GitHub API for automation
- Slack/Teams for notifications
- Google Sheets/Notion for reporting
- Support for 8+ package managers

## 🧠 How It Works: Powered by Portia AI SDK

The Dependency Security Agent leverages the **Portia AI SDK** to provide a robust, extensible, and intelligent automation framework for dependency management and security. Here’s how it works in Portia terms:

- **Tools Abstraction**: Each core function (dependency scanning, updating, reporting, notifications, etc.) is implemented as a Portia "Tool". Tools are Python classes with a defined name, description, input schema, and output schema, making them discoverable and callable by the agent. This modular approach allows easy extension and integration with new services or data sources.

- **Plans and Plan Runs**: When a user initiates an action (e.g., scan a repo), the agent uses Portia’s planning engine to generate a structured "Plan". This plan sequences the necessary tool calls and tracks their execution in a "PlanRun" object, providing full visibility and traceability of the agent’s reasoning and actions.

- **Clarifications**: If a tool requires additional information (e.g., missing credentials, ambiguous input), Portia’s "Clarification" mechanism interrupts the plan run and requests structured input from the user or another system. This ensures secure, just-in-time authentication and robust error handling.

- **Secure, Authenticated Tool Calls**: Portia’s tool abstraction supports just-in-time authentication, so sensitive operations (like updating dependencies or posting to Slack) are performed securely, with token refresh and minimal permissions.

- **Extensibility**: New tools can be added by subclassing Portia’s Tool base class, defining their schemas and logic. The agent can then automatically discover and use these tools in future plans.

- **Cloud and Local Execution**: The agent can run plans locally or leverage Portia Cloud for remote execution, persistent plan run storage, and advanced features like historical tracking and multi-agent orchestration.

**In summary:** The agent’s intelligence, security, and extensibility are powered by Portia’s SDK abstractions—tools, plans, plan runs, and clarifications—enabling safe, transparent, and customizable automation for dependency management across your organization.