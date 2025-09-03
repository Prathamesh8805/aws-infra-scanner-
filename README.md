# AWS Infrastructure Scanner

A simple, powerful tool for scanning and auditing AWS infrastructure. Get security insights, compliance checks, and cost optimization recommendations in minutes.

![AWS Infrastructure Scanner](https://img.shields.io/badge/AWS-Infrastructure%20Scanner-orange)
![Python 3.8+](https://img.shields.io/badge/Python-3.8+-blue)
![License MIT](https://img.shields.io/badge/License-MIT-green)

## 🚀 Quick Start

### Installation

```bash
# Clone the repository
git clone https://github.com/Prathamesh8805/aws-infra-scanner-
cd aws-infra-scanner-

pthon3 -m venv venv
source venv/bin/activate

# Install the package
pip install -e .
```

### Run a Scan

```bash
# Basic scan (will prompt for AWS credentials)
infra-scanner scan

# Full featured scan with AI recommendations
infra-scanner scan --interactive-dashboard --compliance-frameworks --ai-recommendations
```

## ✨ Features

- **Security Auditing**: Detect security risks in EKS, EC2, VPC, IAM, and more
- **Cost Optimization**: Find unused resources and cost-saving opportunities
- **Compliance Checks**: Map findings to CIS, NIST, and AWS Well-Architected frameworks
- **AI Recommendations**: Get intelligent remediation suggestions powered by Groq AI
- **Interactive Dashboard**: Explore findings through an intuitive HTML interface

## 📋 Detailed Usage

### Authentication

The tool will **automatically prompt** you for AWS credentials if not provided. You can also use:

- **AWS Profile**: `--profile my-aws-profile`
- **Access Keys**: `--access-key YOUR_KEY --secret-key YOUR_SECRET`
- **Environment Variables**: Set `AWS_ACCESS_KEY_ID` and `AWS_SECRET_ACCESS_KEY`

### Common Options

```bash
# Scan specific services
infra-scanner scan --services eks,ec2,vpc

# Scan specific region
infra-scanner scan --region us-west-2

# Enable AI recommendations
infra-scanner scan --ai-recommendations

# Generate interactive dashboard
infra-scanner scan --interactive-dashboard

# Include compliance frameworks
infra-scanner scan --compliance-frameworks
```

### AI Recommendations

For AI-powered recommendations, you can:

1. Provide a Groq API key: `--groq-api-key YOUR_API_KEY`
2. Set it in a `.env` file: `GROQ_API_KEY=your-groq-api-key`

If no key is available, the tool will automatically fall back to rule-based recommendations.

## 📊 Sample Report

After running a scan, you'll get an interactive HTML report with:

- Executive summary of findings
- Detailed security issues by service
- Compliance framework mappings
- Cost optimization opportunities
- Actionable recommendations

Reports are saved to the `./reports` directory by default.

## 🔧 Requirements

- Python 3.8+
- AWS credentials or profile

## 📜 License

[MIT License](LICENSE)
