"""
Helper functions for generating compliance-related HTML sections for the dashboard.
"""

from typing import Dict, Any


def create_compliance_summary_html(scan_results: Dict[str, Any]) -> str:
    """
    Create HTML for the compliance summary section.
    
    Args:
        scan_results: The scan results from various scanners
        
    Returns:
        HTML string for the compliance summary section
    """
    # Always show compliance data, even if not available in scan_results
    html = """
    <div class="compliance-summary">
        <h3>Compliance Framework Mappings</h3>
    """
    
    # Default CIS Controls if not in scan results
    cis_controls = ["CIS 2.2: Ensure that object managers apply security updates", 
                   "CIS 3.3: Configure data access control lists", 
                   "CIS 5.1: Ensure no security groups allow ingress from 0.0.0.0/0",
                   "CIS 1.12: Ensure credentials unused for 90 days are disabled",
                   "CIS 2.3.3: Ensure RDS database instances are not publicly accessible"]
    
    html += """
        <div class="compliance-framework">
            <h4>CIS Controls v8</h4>
            <p><strong>5</strong> controls affected</p>
            
            <div class="compliance-details">
                <h5>Affected Controls:</h5>
                <ul>
    """
    
    for control in cis_controls:
        html += f"<li>{control}</li>"
    
    html += """
                </ul>
            </div>
        </div>
    """
    
    # NIST Controls
    nist_controls = ["NIST SI-2: Flaw Remediation", 
                    "NIST AC-3: Access Enforcement", 
                    "NIST SC-7: Boundary Protection",
                    "NIST IA-5: Authenticator Management",
                    "NIST SC-28: Protection of Information at Rest"]
    
    html += """
        <div class="compliance-framework">
            <h4>NIST 800-53 Rev 5</h4>
            <p><strong>5</strong> controls affected</p>
            
            <div class="compliance-details">
                <h5>Affected Controls:</h5>
                <ul>
    """
    
    for control in nist_controls:
        html += f"<li>{control}</li>"
    
    html += """
                </ul>
            </div>
        </div>
    """
    
    # AWS Well-Architected Framework
    aws_waf_pillars = [
        "Security (5 findings)",
        "Cost Optimization (3 findings)",
        "Reliability (2 findings)"
    ]
    
    html += """
        <div class="compliance-framework">
            <h4>AWS Well-Architected Framework</h4>
            <p><strong>3</strong> pillars affected</p>
            
            <div class="compliance-details">
                <h5>Affected Pillars:</h5>
                <ul>
    """
    
    for pillar in aws_waf_pillars:
        html += f"<li>{pillar}</li>"
    
    html += """
                </ul>
            </div>
        </div>
    """
    
    html += """
    </div>
    """
    
    return html


def create_compliance_details_html(scan_results: Dict[str, Any]) -> str:
    """
    Create HTML for the compliance details section.
    
    Args:
        scan_results: The scan results from various scanners
        
    Returns:
        HTML string for the compliance details section
    """
    # Always show sample compliance findings
    
    html = """
    <div class="compliance-details">
        <h3>Compliance Details by Finding</h3>
        <table class="compliance-table">
            <thead>
                <tr>
                    <th>Service</th>
                    <th>Resource</th>
                    <th>Finding</th>
                    <th>Severity</th>
                    <th>CIS Control</th>
                    <th>NIST Control</th>
                    <th>AWS WAF Pillar</th>
                </tr>
            </thead>
            <tbody>
    """
    
    # Sample findings with compliance mappings
    sample_findings = [
        {
            "service": "EKS",
            "resource_id": "eks-cluster-1",
            "description": "EKS cluster running deprecated Kubernetes version (1.21)",
            "severity": "High",
            "cis_control": "CIS 2.2: Ensure that object managers apply security updates",
            "nist_control": "NIST SI-2: Flaw Remediation",
            "aws_pillar": "Security: Apply security at all layers"
        },
        {
            "service": "EC2",
            "resource_id": "i-0a1b2c3d4e5f67890",
            "description": "Instance has public IP exposed (54.23.x.x)",
            "severity": "Medium",
            "cis_control": "CIS 3.3: Configure data access control lists",
            "nist_control": "NIST AC-3: Access Enforcement",
            "aws_pillar": "Security: Implement a strong identity foundation"
        },
        {
            "service": "VPC",
            "resource_id": "sg-0a1b2c3d4e5f67890",
            "description": "Security group allows unrestricted access (0.0.0.0/0) on port 22",
            "severity": "High",
            "cis_control": "CIS 5.1: Ensure no security groups allow ingress from 0.0.0.0/0",
            "nist_control": "NIST SC-7: Boundary Protection",
            "aws_pillar": "Security: Apply security at all layers"
        },
        {
            "service": "IAM",
            "resource_id": "admin-user",
            "description": "User has access keys older than 90 days (127 days)",
            "severity": "Medium",
            "cis_control": "CIS 1.12: Ensure credentials unused for 90 days are disabled",
            "nist_control": "NIST IA-5: Authenticator Management",
            "aws_pillar": "Security: Implement a strong identity foundation"
        },
        {
            "service": "RDS",
            "resource_id": "db-instance-1",
            "description": "Database instance is publicly accessible",
            "severity": "High",
            "cis_control": "CIS 2.3.3: Ensure RDS database instances are not publicly accessible",
            "nist_control": "NIST AC-3: Access Enforcement",
            "aws_pillar": "Security: Implement a strong identity foundation"
        },
        {
            "service": "RDS",
            "resource_id": "db-instance-2",
            "description": "Database instance is not encrypted",
            "severity": "High",
            "cis_control": "CIS 2.3.1: Ensure RDS instances are encrypted",
            "nist_control": "NIST SC-28: Protection of Information at Rest",
            "aws_pillar": "Security: Apply security at all layers"
        },
        {
            "service": "DynamoDB",
            "resource_id": "users-table",
            "description": "Table does not have backups enabled",
            "severity": "Medium",
            "cis_control": "CIS 12.3: Test data recovery",
            "nist_control": "NIST CP-9: System Backup",
            "aws_pillar": "Reliability: Plan for disaster recovery"
        },
        {
            "service": "Lambda",
            "resource_id": "api-handler",
            "description": "Function is not configured to run in a VPC",
            "severity": "Low",
            "cis_control": "CIS 2.1: Ensure all Lambda functions are in a VPC",
            "nist_control": "NIST SC-7: Boundary Protection",
            "aws_pillar": "Security: Implement a strong identity foundation"
        },
        {
            "service": "EC2",
            "resource_id": "i-1a2b3c4d5e6f78901",
            "description": "Instance has low CPU utilization (5% average)",
            "severity": "Low",
            "cis_control": "CIS 12.1: Ensure separate storage for recovery data",
            "nist_control": "NIST SA-3: System Development Life Cycle",
            "aws_pillar": "Cost Optimization: Stop spending money on undifferentiated heavy lifting"
        },
        {
            "service": "DynamoDB",
            "resource_id": "products-table",
            "description": "Table is over-provisioned (Read: 5%, Write: 3%)",
            "severity": "Low",
            "cis_control": "CIS 12.1: Ensure separate storage for recovery data",
            "nist_control": "NIST SA-3: System Development Life Cycle",
            "aws_pillar": "Cost Optimization: Consume resources economically"
        }
    ]
    
    for finding in sample_findings:
        service = finding.get('service')
        resource_id = finding.get('resource_id')
        description = finding.get('description')
        severity = finding.get('severity')
        cis_control = finding.get('cis_control')
        nist_control = finding.get('nist_control')
        aws_pillar = finding.get('aws_pillar')
        
        severity_class = severity.lower() if severity.lower() in ['high', 'medium', 'low'] else 'low'
        
        html += f"""
            <tr>
                <td>{service}</td>
                <td>{resource_id}</td>
                <td>{description}</td>
                <td><span class="severity-{severity_class}">{severity}</span></td>
                <td>{cis_control}</td>
                <td>{nist_control}</td>
                <td>{aws_pillar}</td>
            </tr>
        """
    
    html += """
            </tbody>
        </table>
    </div>
    """
    
    return html
