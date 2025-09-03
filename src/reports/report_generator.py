import os
import json
import datetime
from typing import Dict, Any
import jinja2
import weasyprint
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib import colors

def generate_report(
    results: Dict[str, Any],
    output_path: str,
    format: str = "html",
    environment: str = "unknown",
    region: str = "unknown",
) -> str:
    """
    Generate a report from scan results
    
    Args:
        results: Scan results from scanners
        output_path: Path to save the report
        format: Report format (html or pdf)
        environment: Environment name
        region: AWS region
        
    Returns:
        Path to the generated report
    """
    if format.lower() == "html":
        return generate_html_report(results, output_path, environment, region)
    elif format.lower() == "pdf":
        return generate_pdf_report(results, output_path, environment, region)
    else:
        raise ValueError(f"Unsupported report format: {format}")

def generate_html_report(
    results: Dict[str, Any],
    output_path: str,
    environment: str,
    region: str,
) -> str:
    """Generate an HTML report"""
    # Create Jinja2 environment
    template_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "templates")
    os.makedirs(template_dir, exist_ok=True)
    
    # Create template file if it doesn't exist
    template_path = os.path.join(template_dir, "report_template.html")
    if not os.path.exists(template_path):
        with open(template_path, "w") as f:
            f.write("""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>AWS Infrastructure Scan Report</title>
    <style>
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            line-height: 1.6;
            margin: 0;
            padding: 0;
            color: #333;
            background-color: #f8f9fa;
        }
        .container {
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
        }
        header {
            background-color: #232f3e;
            color: white;
            padding: 25px;
            margin-bottom: 30px;
            border-radius: 5px;
            box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
        }
        h1, h2, h3 {
            margin-top: 0;
            font-weight: 600;
        }
        .summary {
            background-color: white;
            padding: 25px;
            border-radius: 5px;
            margin-bottom: 30px;
            box-shadow: 0 2px 4px rgba(0, 0, 0, 0.05);
        }
        .service-section {
            margin-bottom: 40px;
            background-color: white;
            border-radius: 5px;
            padding: 25px;
            box-shadow: 0 2px 4px rgba(0, 0, 0, 0.05);
        }
        table {
            width: 100%;
            border-collapse: collapse;
            margin-bottom: 20px;
            border-radius: 5px;
            overflow: hidden;
            box-shadow: 0 0 20px rgba(0, 0, 0, 0.05);
        }
        th, td {
            padding: 15px;
            border-bottom: 1px solid #eee;
            text-align: left;
        }
        th {
            background-color: #f2f2f2;
            font-weight: 600;
        }
        tr:hover {
            background-color: #f8f9fa;
        }
        .footer {
            margin-top: 50px;
            text-align: center;
            color: #777;
            font-size: 0.9em;
            padding: 20px;
        }
        .resource-count {
            font-weight: bold;
            color: #0073bb;
        }
        .alert {
            padding: 15px;
            margin-bottom: 20px;
            border: 1px solid transparent;
            border-radius: 4px;
            box-shadow: 0 2px 4px rgba(0, 0, 0, 0.05);
        }
        .alert-warning {
            color: #8a6d3b;
            background-color: #fcf8e3;
            border-color: #faebcc;
        }
        .alert-danger {
            color: #a94442;
            background-color: #f2dede;
            border-color: #ebccd1;
        }
        .security-issue {
            color: #a94442;
            font-weight: bold;
        }
        .remediation {
            background-color: #dff0d8;
            border: 1px solid #d6e9c6;
            color: #3c763d;
            padding: 10px;
            margin-top: 10px;
            border-radius: 4px;
        }
        .collapsible {
            background-color: #f8f9fa;
            color: #444;
            cursor: pointer;
            padding: 18px;
            width: 100%;
            border: none;
            text-align: left;
            outline: none;
            font-size: 15px;
            margin-bottom: 5px;
            border-radius: 5px;
            transition: all 0.3s ease;
            border-left: 4px solid #ddd;
        }
        .collapsible.security-risk {
            border-left: 4px solid #a94442;
        }
        .active, .collapsible:hover {
            background-color: #e9ecef;
        }
        .content {
            padding: 0 18px;
            max-height: 0;
            overflow: hidden;
            transition: max-height 0.2s ease-out;
            background-color: white;
            border-radius: 0 0 5px 5px;
        }
        .badge {
            display: inline-block;
            padding: 3px 7px;
            font-size: 12px;
            font-weight: 700;
            line-height: 1;
            color: #fff;
            text-align: center;
            white-space: nowrap;
            vertical-align: baseline;
            border-radius: 10px;
            margin-left: 5px;
        }
        .badge-warning {
            background-color: #f0ad4e;
        }
        .badge-danger {
            background-color: #d9534f;
        }
        .badge-info {
            background-color: #5bc0de;
        }
        .severity-high {
            background-color: #d9534f;
            color: white;
            padding: 3px 7px;
            border-radius: 3px;
            font-size: 12px;
        }
        .severity-medium {
            background-color: #f0ad4e;
            color: white;
            padding: 3px 7px;
            border-radius: 3px;
            font-size: 12px;
        }
        .severity-low {
            background-color: #5bc0de;
            color: white;
            padding: 3px 7px;
            border-radius: 3px;
            font-size: 12px;
        }
        .tabs {
            display: flex;
            margin-bottom: 20px;
            border-bottom: 1px solid #ddd;
        }
        .tab {
            background-color: #f8f9fa;
            border: none;
            outline: none;
            cursor: pointer;
            padding: 10px 15px;
            margin-right: 2px;
            font-size: 14px;
            transition: 0.3s;
            border-radius: 5px 5px 0 0;
        }
        .tab:hover {
            background-color: #e9ecef;
        }
        .active-tab {
            background-color: #fff;
            border: 1px solid #ddd;
            border-bottom: 1px solid #fff;
            margin-bottom: -1px;
            font-weight: bold;
        }
        .tab-content {
            padding: 20px;
            border: 1px solid #ddd;
            border-top: none;
            border-radius: 0 0 5px 5px;
        }
        code {
            display: block;
            padding: 10px;
            background-color: #f8f9fa;
            border: 1px solid #ddd;
            border-radius: 4px;
            font-family: monospace;
            white-space: pre-wrap;
            margin: 10px 0;
        }
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>AWS Infrastructure Scan Report</h1>
            <p>Environment: {{ environment }} | Region: {{ region }} | Date: {{ timestamp }}</p>
        </header>
        
        <div class="summary">
            <h2>Executive Summary</h2>
            <p>This report provides a comprehensive overview of the AWS infrastructure in the {{ environment }} environment, region {{ region }}.</p>
            
            <h3>Resources Scanned:</h3>
            <ul>
                {% if 'eks' in results %}
                <li>EKS Clusters: <span class="resource-count">{{ results.eks.results.count }}</span></li>
                {% endif %}
                
                {% if 'ec2' in results %}
                <li>EC2 Instances: <span class="resource-count">{{ results.ec2.results.instance_count }}</span></li>
                <li>Security Groups: <span class="resource-count">{{ results.ec2.results.security_group_count }}</span></li>
                {% endif %}
                
                {% if 'vpc' in results %}
                <li>VPCs: <span class="resource-count">{{ results.vpc.results.vpc_count }}</span></li>
                {% endif %}
                
                {% if 'dynamodb' in results %}
                <li>DynamoDB Tables: <span class="resource-count">{{ results.dynamodb.results.table_count }}</span></li>
                {% endif %}
                
                {% if 'iam' in results %}
                <li>IAM Users: <span class="resource-count">{{ results.iam.results.user_count }}</span></li>
                <li>IAM Roles: <span class="resource-count">{{ results.iam.results.role_count }}</span></li>
                {% endif %}
                
                {% if 'cost' in results %}
                <li>Potential Monthly Savings: <span class="resource-count">${{ results.cost.results.total_potential_savings }}</span></li>
                {% endif %}
            </ul>
            
            {% if 'eks' in results and results.eks.results.deprecated_count > 0 %}
            <div class="alert alert-warning">
                <h4>⚠️ Warning: {{ results.eks.results.deprecated_count }} EKS clusters are running deprecated versions</h4>
            </div>
            {% endif %}
            
            {% if 'ec2' in results and results.ec2.results.public_ip_count > 0 %}
            <div class="alert alert-warning">
                <h4>⚠️ Warning: {{ results.ec2.results.public_ip_count }} EC2 instances have public IP addresses</h4>
                <p>Instances with public IPs are directly accessible from the internet and may be vulnerable to attacks if not properly secured.</p>
            </div>
            {% endif %}
            
            {% if 'ec2' in results and results.ec2.results.open_security_group_count > 0 %}
            <div class="alert alert-warning">
                <h4>⚠️ Warning: {{ results.ec2.results.open_security_group_count }} security groups have potentially risky open ports</h4>
            </div>
            {% endif %}
            
            {% if 'iam' in results and results.iam.results.users_with_old_keys_count > 0 %}
            <div class="alert alert-warning">
                <h4>⚠️ Warning: {{ results.iam.results.users_with_old_keys_count }} IAM users have access keys older than 90 days</h4>
            </div>
            {% endif %}
        </div>
        
        {% if 'eks' in results %}
        <div class="service-section">
            <h2>EKS Clusters</h2>
            {% if results.eks.results.clusters %}
                {% for cluster in results.eks.results.clusters %}
                <button class="collapsible">{{ cluster.name }} ({{ cluster.status }})</button>
                <div class="content">
                    <h3>Cluster Details</h3>
                    <table>
                        <tr>
                            <th>Property</th>
                            <th>Value</th>
                        </tr>
                        <tr>
                            <td>ARN</td>
                            <td>{{ cluster.arn }}</td>
                        </tr>
                        <tr>
                            <td>Created At</td>
                            <td>{{ cluster.createdAt }}</td>
                        </tr>
                        <tr>
                            <td>Kubernetes Version</td>
                            <td>{{ cluster.version }}</td>
                        </tr>
                        <tr>
                            <td>Endpoint</td>
                            <td>{{ cluster.endpoint }}</td>
                        </tr>
                        <tr>
                            <td>Role ARN</td>
                            <td>{{ cluster.roleArn }}</td>
                        </tr>
                    </table>
                    
                    <h3>Nodegroups ({{ cluster.nodegroups|length }})</h3>
                    {% for nodegroup in cluster.nodegroups %}
                    <h4>{{ nodegroup.nodegroupName }}</h4>
                    <table>
                        <tr>
                            <th>Property</th>
                            <th>Value</th>
                        </tr>
                        <tr>
                            <td>Status</td>
                            <td>{{ nodegroup.status }}</td>
                        </tr>
                        <tr>
                            <td>Instance Types</td>
                            <td>{{ nodegroup.instanceTypes|join(', ') }}</td>
                        </tr>
                        <tr>
                            <td>Capacity Type</td>
                            <td>{{ nodegroup.capacityType }}</td>
                        </tr>
                    </table>
                    {% endfor %}
                    
                    <h3>Addons ({{ cluster.addons|length }})</h3>
                    {% for addon in cluster.addons %}
                    <table>
                        <tr>
                            <th>Name</th>
                            <th>Version</th>
                            <th>Status</th>
                        </tr>
                        <tr>
                            <td>{{ addon.addonName }}</td>
                            <td>{{ addon.addonVersion }}</td>
                            <td>{{ addon.status }}</td>
                        </tr>
                    </table>
                    {% endfor %}
                </div>
                {% endfor %}
            {% else %}
                <p>No EKS clusters found in this region.</p>
            {% endif %}
        </div>
        {% endif %}
        
        {% if 'ec2' in results %}
        <div class="service-section">
            <h2>EC2 Resources</h2>
            
            <h3>EC2 Instances</h3>
            
            <div class="tabs">
                <button class="tab active-tab" data-tab="all-instances">All Instances ({{ results.ec2.results.instance_count }})</button>
                <button class="tab" data-tab="public-instances">Instances with Public IPs ({{ results.ec2.results.public_ip_count }})</button>
                {% if results.ec2.results.orphaned_instance_count > 0 %}
                <button class="tab" data-tab="orphaned-instances">Orphaned Instances ({{ results.ec2.results.orphaned_instance_count }})</button>
                {% endif %}
            </div>
            
            <div id="all-instances" class="tab-content">
                {% if results.ec2.results.instances %}
                    {% for instance in results.ec2.results.instances %}
                        {% set has_public_ip = instance.PublicIpAddress is defined %}
                        <button class="collapsible {% if has_public_ip %}security-risk{% endif %}">
                            {{ instance.InstanceId }} ({{ instance.State.Name }})
                            {% if has_public_ip %}<span class="badge badge-warning">PUBLIC IP</span>{% endif %}
                        </button>
                        <div class="content">
                            <table>
                                <tr>
                                    <th>Property</th>
                                    <th>Value</th>
                                </tr>
                                <tr>
                                    <td>Instance Type</td>
                                    <td>{{ instance.InstanceType }}</td>
                                </tr>
                                <tr>
                                    <td>Launch Time</td>
                                    <td>{{ instance.LaunchTime }}</td>
                                </tr>
                                <tr>
                                    <td>VPC ID</td>
                                    <td>{{ instance.VpcId }}</td>
                                </tr>
                                <tr>
                                    <td>Subnet ID</td>
                                    <td>{{ instance.SubnetId }}</td>
                                </tr>
                                <tr>
                                    <td>Private IP</td>
                                    <td>{{ instance.PrivateIpAddress }}</td>
                                </tr>
                                {% if instance.PublicIpAddress %}
                                <tr class="security-issue">
                                    <td>Public IP</td>
                                    <td>{{ instance.PublicIpAddress }}</td>
                                </tr>
                                {% endif %}
                            </table>
                            
                            <h4>Security Groups</h4>
                            <table>
                                <tr>
                                    <th>Group ID</th>
                                    <th>Group Name</th>
                                </tr>
                                {% for sg in instance.SecurityGroups %}
                                <tr>
                                    <td>{{ sg.GroupId }}</td>
                                    <td>{{ sg.GroupName }}</td>
                                </tr>
                                {% endfor %}
                            </table>
                            
                            <h4>Tags</h4>
                            {% if instance.Tags %}
                            <table>
                                <tr>
                                    <th>Key</th>
                                    <th>Value</th>
                                </tr>
                                {% for tag in instance.Tags %}
                                <tr>
                                    <td>{{ tag.Key }}</td>
                                    <td>{{ tag.Value }}</td>
                                </tr>
                                {% endfor %}
                            </table>
                            {% else %}
                            <p>No tags found for this instance.</p>
                            {% endif %}
                            
                            {% if instance.PublicIpAddress %}
                            <div class="remediation">
                                <h4>📋 Remediation Advice:</h4>
                                <ul>
                                    <li>Consider using private IPs and a bastion host or VPN for access</li>
                                    <li>If public IP is required, ensure security groups are properly restricted</li>
                                    <li>Use Network ACLs as an additional layer of security</li>
                                    <li>Consider using Elastic Load Balancers for web applications instead of direct public IPs</li>
                                </ul>
                                <p><strong>AWS CLI Command to remove public IP:</strong></p>
                                <code>aws ec2 modify-instance-attribute --instance-id {{ instance.InstanceId }} --no-associate-public-ip-address</code>
                            </div>
                            {% endif %}
                        </div>
                    {% endfor %}
                {% else %}
                    <p>No EC2 instances found in this region.</p>
                {% endif %}
            </div>
            
            <div id="public-instances" class="tab-content" style="display:none;">
                {% if results.ec2.results.instances_with_public_ip %}
                    {% for public_instance in results.ec2.results.instances_with_public_ip %}
                        {% set full_instance = none %}
                        {% for instance in results.ec2.results.instances %}
                            {% if instance.InstanceId == public_instance.InstanceId %}
                                {% set full_instance = instance %}
                            {% endif %}
                        {% endfor %}
                        
                        {% if full_instance %}
                            <button class="collapsible security-risk">
                                {{ public_instance.InstanceId }} ({{ public_instance.State }})
                                <span class="badge badge-warning">PUBLIC IP: {{ public_instance.PublicIpAddress }}</span>
                            </button>
                            <div class="content">
                                <table>
                                    <tr>
                                        <th>Property</th>
                                        <th>Value</th>
                                    </tr>
                                    <tr>
                                        <td>Instance Type</td>
                                        <td>{{ full_instance.InstanceType }}</td>
                                    </tr>
                                    <tr>
                                        <td>Launch Time</td>
                                        <td>{{ full_instance.LaunchTime }}</td>
                                    </tr>
                                    <tr>
                                        <td>VPC ID</td>
                                        <td>{{ full_instance.VpcId }}</td>
                                    </tr>
                                    <tr>
                                        <td>Subnet ID</td>
                                        <td>{{ full_instance.SubnetId }}</td>
                                    </tr>
                                    <tr>
                                        <td>Private IP</td>
                                        <td>{{ full_instance.PrivateIpAddress }}</td>
                                    </tr>
                                    <tr class="security-issue">
                                        <td>Public IP</td>
                                        <td>{{ public_instance.PublicIpAddress }}</td>
                                    </tr>
                                </table>
                                
                                <h4>Security Groups</h4>
                                <table>
                                    <tr>
                                        <th>Group ID</th>
                                        <th>Group Name</th>
                                    </tr>
                                    {% for sg in full_instance.SecurityGroups %}
                                    <tr>
                                        <td>{{ sg.GroupId }}</td>
                                        <td>{{ sg.GroupName }}</td>
                                    </tr>
                                    {% endfor %}
                                </table>
                                
                                <div class="remediation">
                                    <h4>📋 Remediation Advice:</h4>
                                    <ul>
                                        <li>Consider using private IPs and a bastion host or VPN for access</li>
                                        <li>If public IP is required, ensure security groups are properly restricted</li>
                                        <li>Use Network ACLs as an additional layer of security</li>
                                        <li>Consider using Elastic Load Balancers for web applications instead of direct public IPs</li>
                                    </ul>
                                    <p><strong>AWS CLI Command to remove public IP:</strong></p>
                                    <code>aws ec2 modify-instance-attribute --instance-id {{ public_instance.InstanceId }} --no-associate-public-ip-address</code>
                                </div>
                            </div>
                        {% endif %}
                    {% endfor %}
                {% else %}
                    <p>No instances with public IPs found.</p>
                {% endif %}
            </div>
            
            {% if results.ec2.results.orphaned_instance_count > 0 %}
            <div id="orphaned-instances" class="tab-content" style="display:none;">
                {% if results.ec2.results.orphaned_instances %}
                    <div class="alert alert-warning">
                        <h4>⚠️ Warning: {{ results.ec2.results.orphaned_instance_count }} orphaned instances found</h4>
                        <p>These instances are not managed by Auto Scaling Groups or EKS and might be forgotten resources.</p>
                    </div>
                    
                    {% for orphaned in results.ec2.results.orphaned_instances %}
                        <button class="collapsible">
                            {{ orphaned.InstanceId }} ({{ orphaned.InstanceType }})
                        </button>
                        <div class="content">
                            <table>
                                <tr>
                                    <th>Property</th>
                                    <th>Value</th>
                                </tr>
                                <tr>
                                    <td>Instance Type</td>
                                    <td>{{ orphaned.InstanceType }}</td>
                                </tr>
                                <tr>
                                    <td>Launch Time</td>
                                    <td>{{ orphaned.LaunchTime }}</td>
                                </tr>
                                <tr>
                                    <td>State</td>
                                    <td>{{ orphaned.State }}</td>
                                </tr>
                            </table>
                            
                            <div class="remediation">
                                <h4>📋 Remediation Advice:</h4>
                                <ul>
                                    <li>Verify if this instance is still needed</li>
                                    <li>Consider terminating if not needed to save costs</li>
                                    <li>If needed, consider adding it to an Auto Scaling Group for better management</li>
                                </ul>
                            </div>
                        </div>
                    {% endfor %}
                {% else %}
                    <p>No orphaned instances found.</p>
                {% endif %}
            </div>
            {% endif %}
            {% else %}
                <p>No EC2 instances found in this region.</p>
            {% endif %}
            
            <h3>Security Groups ({{ results.ec2.results.security_group_count }})</h3>
            
            <div class="alert alert-danger">
                <h4>🔒 Security Risk: {{ results.ec2.results.open_security_group_count }} security groups have potentially risky open ports</h4>
                <p>Security groups with open ports (0.0.0.0/0) can expose your infrastructure to unauthorized access and potential attacks.</p>
            </div>
            
            <div class="tabs">
                <button class="tab active-tab" data-tab="all-sg">All Security Groups ({{ results.ec2.results.security_group_count }})</button>
                <button class="tab" data-tab="risky-sg">Risky Security Groups ({{ results.ec2.results.open_security_group_count }})</button>
            </div>
            
            <div id="all-sg" class="tab-content">
                {% if results.ec2.results.security_groups %}
                    {% for sg in results.ec2.results.security_groups %}
                        {% set is_risky = false %}
                        {% for open_sg in results.ec2.results.open_security_groups %}
                            {% if open_sg.GroupId == sg.GroupId %}
                                {% set is_risky = true %}
                            {% endif %}
                        {% endfor %}
                        
                        <button class="collapsible {% if is_risky %}security-risk{% endif %}">
                            {{ sg.GroupName }} ({{ sg.GroupId }})
                            {% if is_risky %}<span class="badge badge-danger">SECURITY RISK</span>{% endif %}
                        </button>
                        <div class="content">
                            <h4>Inbound Rules</h4>
                            <table>
                                <tr>
                                    <th>Protocol</th>
                                    <th>Port Range</th>
                                    <th>Source</th>
                                    <th>Description</th>
                                    <th>Risk</th>
                                </tr>
                                {% for rule in sg.IpPermissions %}
                                <tr>
                                    <td>{{ rule.IpProtocol if rule.IpProtocol != "-1" else "All" }}</td>
                                    <td>
                                        {% if rule.FromPort == rule.ToPort %}
                                            {{ rule.FromPort if rule.FromPort else "All" }}
                                        {% elif rule.FromPort and rule.ToPort %}
                                            {{ rule.FromPort }}-{{ rule.ToPort }}
                                        {% else %}
                                            All
                                        {% endif %}
                                    </td>
                                    <td>
                                        {% if rule.IpRanges %}
                                            {% for ip_range in rule.IpRanges %}
                                                {% if ip_range.CidrIp == "0.0.0.0/0" %}
                                                    <span class="security-issue">{{ ip_range.CidrIp }}</span><br>
                                                {% else %}
                                                    {{ ip_range.CidrIp }}<br>
                                                {% endif %}
                                            {% endfor %}
                                        {% endif %}
                                        {% if rule.UserIdGroupPairs %}
                                            {% for group in rule.UserIdGroupPairs %}
                                                {{ group.GroupId }}<br>
                                            {% endfor %}
                                        {% endif %}
                                    </td>
                                    <td>
                                        {% if rule.IpRanges and rule.IpRanges[0].Description %}
                                            {{ rule.IpRanges[0].Description }}
                                        {% endif %}
                                    </td>
                                    <td>
                                        {% for ip_range in rule.IpRanges %}
                                            {% if ip_range.CidrIp == "0.0.0.0/0" %}
                                                {% if rule.IpProtocol == "tcp" %}
                                                    {% if rule.FromPort <= 22 <= rule.ToPort %}
                                                        <span class="severity-high">HIGH</span> SSH port open to the world
                                                    {% elif rule.FromPort <= 3389 <= rule.ToPort %}
                                                        <span class="severity-high">HIGH</span> RDP port open to the world
                                                    {% elif rule.FromPort <= 3306 <= rule.ToPort %}
                                                        <span class="severity-high">HIGH</span> MySQL port open to the world
                                                    {% elif rule.FromPort <= 5432 <= rule.ToPort %}
                                                        <span class="severity-high">HIGH</span> PostgreSQL port open to the world
                                                    {% elif rule.FromPort <= 80 <= rule.ToPort or rule.FromPort <= 443 <= rule.ToPort %}
                                                        <span class="severity-medium">MEDIUM</span> Web ports open to the world
                                                    {% else %}
                                                        <span class="severity-medium">MEDIUM</span> Port open to the world
                                                    {% endif %}
                                                {% elif rule.IpProtocol == "-1" %}
                                                    <span class="severity-high">HIGH</span> All traffic allowed from anywhere
                                                {% else %}
                                                    <span class="severity-medium">MEDIUM</span> Protocol open to the world
                                                {% endif %}
                                            {% endif %}
                                        {% endfor %}
                                    </td>
                                </tr>
                                {% endfor %}
                            </table>
                            
                            {% set has_security_issues = false %}
                            {% for rule in sg.IpPermissions %}
                                {% for ip_range in rule.IpRanges %}
                                    {% if ip_range.CidrIp == "0.0.0.0/0" %}
                                        {% set has_security_issues = true %}
                                    {% endif %}
                                {% endfor %}
                            {% endfor %}
                            
                            {% if has_security_issues %}
                                <div class="remediation">
                                    <h4>📋 Remediation Advice:</h4>
                                    <ul>
                                        <li>Restrict access to specific IP ranges instead of using 0.0.0.0/0</li>
                                        <li>Use security group references to allow access only from specific resources</li>
                                        <li>For SSH/RDP access, consider using a bastion host or VPN</li>
                                        <li>Implement the principle of least privilege by allowing only necessary ports</li>
                                    </ul>
                                    <p><strong>AWS CLI Command:</strong></p>
                                    <code>aws ec2 revoke-security-group-ingress --group-id {{ sg.GroupId }} --ip-permissions '[{"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22, "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}]'</code>
                                </div>
                            {% endif %}
                        </div>
                    {% endfor %}
                {% else %}
                    <p>No security groups found in this region.</p>
                {% endif %}
            </div>
            
            <div id="risky-sg" class="tab-content" style="display:none;">
                {% if results.ec2.results.open_security_groups %}
                    {% for sg in results.ec2.results.open_security_groups %}
                        {% set full_sg = none %}
                        {% for full_sg_item in results.ec2.results.security_groups %}
                            {% if full_sg_item.GroupId == sg.GroupId %}
                                {% set full_sg = full_sg_item %}
                            {% endif %}
                        {% endfor %}
                        
                        {% if full_sg %}
                            <button class="collapsible security-risk">
                                {{ full_sg.GroupName }} ({{ full_sg.GroupId }})
                                <span class="badge badge-danger">SECURITY RISK</span>
                            </button>
                            <div class="content">
                                <h4>Security Risk Details</h4>
                                <p><strong>Open Ports:</strong> 
                                    {% for port in sg.OpenPorts %}
                                        <span class="badge {% if port in [22, 3389, 3306, 5432] %}badge-danger{% else %}badge-warning{% endif %}">{{ port }}</span>
                                    {% endfor %}
                                </p>
                                
                                <h4>Inbound Rules</h4>
                                <table>
                                    <tr>
                                        <th>Protocol</th>
                                        <th>Port Range</th>
                                        <th>Source</th>
                                        <th>Description</th>
                                        <th>Risk</th>
                                    </tr>
                                    {% for rule in full_sg.IpPermissions %}
                                    <tr>
                                        <td>{{ rule.IpProtocol if rule.IpProtocol != "-1" else "All" }}</td>
                                        <td>
                                            {% if rule.FromPort == rule.ToPort %}
                                                {{ rule.FromPort if rule.FromPort else "All" }}
                                            {% elif rule.FromPort and rule.ToPort %}
                                                {{ rule.FromPort }}-{{ rule.ToPort }}
                                            {% else %}
                                                All
                                            {% endif %}
                                        </td>
                                        <td>
                                            {% if rule.IpRanges %}
                                                {% for ip_range in rule.IpRanges %}
                                                    {% if ip_range.CidrIp == "0.0.0.0/0" %}
                                                        <span class="security-issue">{{ ip_range.CidrIp }}</span><br>
                                                    {% else %}
                                                        {{ ip_range.CidrIp }}<br>
                                                    {% endif %}
                                                {% endfor %}
                                            {% endif %}
                                            {% if rule.UserIdGroupPairs %}
                                                {% for group in rule.UserIdGroupPairs %}
                                                    {{ group.GroupId }}<br>
                                                {% endfor %}
                                            {% endif %}
                                        </td>
                                        <td>
                                            {% if rule.IpRanges and rule.IpRanges[0].Description %}
                                                {{ rule.IpRanges[0].Description }}
                                            {% endif %}
                                        </td>
                                        <td>
                                            {% for ip_range in rule.IpRanges %}
                                                {% if ip_range.CidrIp == "0.0.0.0/0" %}
                                                    {% if rule.IpProtocol == "tcp" %}
                                                        {% if rule.FromPort <= 22 <= rule.ToPort %}
                                                            <span class="severity-high">HIGH</span> SSH port open to the world
                                                        {% elif rule.FromPort <= 3389 <= rule.ToPort %}
                                                            <span class="severity-high">HIGH</span> RDP port open to the world
                                                        {% elif rule.FromPort <= 3306 <= rule.ToPort %}
                                                            <span class="severity-high">HIGH</span> MySQL port open to the world
                                                        {% elif rule.FromPort <= 5432 <= rule.ToPort %}
                                                            <span class="severity-high">HIGH</span> PostgreSQL port open to the world
                                                        {% elif rule.FromPort <= 80 <= rule.ToPort or rule.FromPort <= 443 <= rule.ToPort %}
                                                            <span class="severity-medium">MEDIUM</span> Web ports open to the world
                                                        {% else %}
                                                            <span class="severity-medium">MEDIUM</span> Port open to the world
                                                        {% endif %}
                                                    {% elif rule.IpProtocol == "-1" %}
                                                        <span class="severity-high">HIGH</span> All traffic allowed from anywhere
                                                    {% else %}
                                                        <span class="severity-medium">MEDIUM</span> Protocol open to the world
                                                    {% endif %}
                                                {% endif %}
                                            {% endfor %}
                                        </td>
                                    </tr>
                                    {% endfor %}
                                </table>
                                
                                <div class="remediation">
                                    <h4>📋 Remediation Advice:</h4>
                                    <ul>
                                        <li>Restrict access to specific IP ranges instead of using 0.0.0.0/0</li>
                                        <li>Use security group references to allow access only from specific resources</li>
                                        <li>For SSH/RDP access, consider using a bastion host or VPN</li>
                                        <li>Implement the principle of least privilege by allowing only necessary ports</li>
                                    </ul>
                                    <p><strong>AWS CLI Command:</strong></p>
                                    <code>aws ec2 revoke-security-group-ingress --group-id {{ full_sg.GroupId }} --ip-permissions '[{"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22, "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}]'</code>
                                </div>
                            </div>
                        {% endif %}
                    {% endfor %}
                {% else %}
                    <p>No security groups with open ports found.</p>
                {% endif %}
            </div>
            {% else %}
                <p>No security groups found in this region.</p>
            {% endif %}
        </div>
        {% endif %}
        
        {% if 'vpc' in results %}
        <div class="service-section">
            <h2>VPC Resources</h2>
            {% if results.vpc.results.vpcs %}
                {% for vpc_detail in results.vpc.results.vpcs %}
                <button class="collapsible">{{ vpc_detail.vpc.VpcId }} ({{ vpc_detail.vpc.CidrBlock }})</button>
                <div class="content">
                    <h3>VPC Details</h3>
                    <table>
                        <tr>
                            <th>Property</th>
                            <th>Value</th>
                        </tr>
                        <tr>
                            <td>CIDR Block</td>
                            <td>{{ vpc_detail.vpc.CidrBlock }}</td>
                        </tr>
                        <tr>
                            <td>State</td>
                            <td>{{ vpc_detail.vpc.State }}</td>
                        </tr>
                        <tr>
                            <td>Default VPC</td>
                            <td>{{ vpc_detail.vpc.IsDefault }}</td>
                        </tr>
                    </table>
                    
                    <h3>Subnets ({{ vpc_detail.subnets|length }})</h3>
                    {% if vpc_detail.subnets %}
                    <table>
                        <tr>
                            <th>Subnet ID</th>
                            <th>CIDR Block</th>
                            <th>AZ</th>
                            <th>Public</th>
                        </tr>
                        {% for subnet in vpc_detail.subnets %}
                        <tr>
                            <td>{{ subnet.SubnetId }}</td>
                            <td>{{ subnet.CidrBlock }}</td>
                            <td>{{ subnet.AvailabilityZone }}</td>
                            <td>{{ subnet.MapPublicIpOnLaunch }}</td>
                        </tr>
                        {% endfor %}
                    </table>
                    {% else %}
                    <p>No subnets found for this VPC.</p>
                    {% endif %}
                    
                    <h3>Route Tables ({{ vpc_detail.route_tables|length }})</h3>
                    {% if vpc_detail.route_tables %}
                        {% for rt in vpc_detail.route_tables %}
                        <h4>{{ rt.RouteTableId }}</h4>
                        <table>
                            <tr>
                                <th>Destination</th>
                                <th>Target</th>
                                <th>Status</th>
                            </tr>
                            {% for route in rt.Routes %}
                            <tr>
                                <td>{{ route.DestinationCidrBlock if 'DestinationCidrBlock' in route else route.DestinationIpv6CidrBlock }}</td>
                                <td>
                                    {% if 'GatewayId' in route %}
                                        Gateway: {{ route.GatewayId }}
                                    {% elif 'NatGatewayId' in route %}
                                        NAT: {{ route.NatGatewayId }}
                                    {% elif 'InstanceId' in route %}
                                        Instance: {{ route.InstanceId }}
                                    {% else %}
                                        Local
                                    {% endif %}
                                </td>
                                <td>{{ route.State }}</td>
                            </tr>
                            {% endfor %}
                        </table>
                        {% endfor %}
                    {% else %}
                    <p>No route tables found for this VPC.</p>
                    {% endif %}
                </div>
                {% endfor %}
            {% else %}
                <p>No VPCs found in this region.</p>
            {% endif %}
        </div>
        {% endif %}
        
        {% if 'dynamodb' in results %}
        <div class="service-section">
            <h2>DynamoDB Tables</h2>
            {% if results.dynamodb.results.tables %}
                {% for table in results.dynamodb.results.tables %}
                <button class="collapsible">{{ table.TableName }}</button>
                <div class="content">
                    <h3>Table Details</h3>
                    <table>
                        <tr>
                            <th>Property</th>
                            <th>Value</th>
                        </tr>
                        <tr>
                            <td>Status</td>
                            <td>{{ table.TableStatus }}</td>
                        </tr>
                        <tr>
                            <td>Creation Date</td>
                            <td>{{ table.CreationDateTime }}</td>
                        </tr>
                        <tr>
                            <td>Item Count</td>
                            <td>{{ table.ItemCount }}</td>
                        </tr>
                        <tr>
                            <td>Size (Bytes)</td>
                            <td>{{ table.TableSizeBytes }}</td>
                        </tr>
                    </table>
                    
                    <h3>Key Schema</h3>
                    <table>
                        <tr>
                            <th>Attribute Name</th>
                            <th>Key Type</th>
                        </tr>
                        {% for key in table.KeySchema %}
                        <tr>
                            <td>{{ key.AttributeName }}</td>
                            <td>{{ key.KeyType }}</td>
                        </tr>
                        {% endfor %}
                    </table>
                    
                    <h3>Provisioning</h3>
                    {% if table.BillingModeSummary and table.BillingModeSummary.BillingMode == 'PAY_PER_REQUEST' %}
                    <p>Billing Mode: On-Demand (PAY_PER_REQUEST)</p>
                    {% elif table.ProvisionedThroughput %}
                    <table>
                        <tr>
                            <th>Metric</th>
                            <th>Value</th>
                        </tr>
                        <tr>
                            <td>Read Capacity Units</td>
                            <td>{{ table.ProvisionedThroughput.ReadCapacityUnits }}</td>
                        </tr>
                        <tr>
                            <td>Write Capacity Units</td>
                            <td>{{ table.ProvisionedThroughput.WriteCapacityUnits }}</td>
                        </tr>
                    </table>
                    {% endif %}
                </div>
                {% endfor %}
            {% else %}
                <p>No DynamoDB tables found in this region.</p>
            {% endif %}
        </div>
        {% endif %}
        
        {% if 'iam' in results %}
        <div class="service-section">
            <h2>IAM Resources</h2>
            
            <h3>Users with Old Access Keys ({{ results.iam.results.users_with_old_keys_count }})</h3>
            {% if results.iam.results.users_with_old_keys %}
                {% for user in results.iam.results.users_with_old_keys %}
                <button class="collapsible">{{ user.UserName }}</button>
                <div class="content">
                    <table>
                        <tr>
                            <th>Access Key ID</th>
                            <th>Created</th>
                            <th>Age (Days)</th>
                        </tr>
                        {% for key in user.OldAccessKeys %}
                        <tr>
                            <td>{{ key.AccessKeyId }}</td>
                            <td>{{ key.CreateDate }}</td>
                            <td>{{ key.AgeDays }}</td>
                        </tr>
                        {% endfor %}
                    </table>
                </div>
                {% endfor %}
            {% else %}
                <p>No users with old access keys found.</p>
            {% endif %}
            
            <h3>Permissive Roles ({{ results.iam.results.permissive_role_count }})</h3>
            {% if results.iam.results.permissive_roles %}
                {% for role in results.iam.results.permissive_roles %}
                <button class="collapsible">{{ role.RoleName }}</button>
                <div class="content">
                    <h4>Permissive Statements</h4>
                    {% for statement in role.PermissiveStatements %}
                    <table>
                        <tr>
                            <th>Policy Name</th>
                            <th>Policy Type</th>
                            <th>Details</th>
                        </tr>
                        <tr>
                            <td>{{ statement.PolicyName }}</td>
                            <td>{{ statement.PolicyType }}</td>
                            <td>
                                {% if statement.PolicyType == 'Managed' %}
                                    {{ statement.Reason }}
                                {% else %}
                                    Action: {{ statement.Statement.Action }}<br>
                                    Resource: {{ statement.Statement.Resource }}
                                {% endif %}
                            </td>
                        </tr>
                    </table>
                    {% endfor %}
                </div>
                {% endfor %}
            {% else %}
                <p>No permissive roles found.</p>
            {% endif %}
        </div>
        {% endif %}
        
        {% if 'cost' in results %}
        <div class="service-section">
            <h2>Cost Optimization</h2>
            
            <h3>Cost by Service</h3>
            <table>
                <tr>
                    <th>Service</th>
                    <th>Amount</th>
                </tr>
                {% for service_cost in results.cost.results.cost_by_service %}
                <tr>
                    <td>{{ service_cost.service }}</td>
                    <td>${{ service_cost.amount }}</td>
                </tr>
                {% endfor %}
            </table>
            
            <h3>Savings Recommendations</h3>
            {% if results.cost.results.savings_recommendations %}
                {% for rec in results.cost.results.savings_recommendations %}
                <button class="collapsible">{{ rec.recommendation_type }} - ${{ rec.estimated_monthly_savings }} monthly savings</button>
                <div class="content">
                    <table>
                        <tr>
                            <th>Service</th>
                            <th>Details</th>
                            <th>Monthly Savings</th>
                        </tr>
                        <tr>
                            <td>{{ rec.service }}</td>
                            <td>{{ rec.details }}</td>
                            <td>${{ rec.estimated_monthly_savings }}</td>
                        </tr>
                    </table>
                </div>
                {% endfor %}
            {% else %}
                <p>No savings recommendations found.</p>
            {% endif %}
            
            <h3>Cost Anomalies</h3>
            {% if results.cost.results.cost_anomalies %}
                <table>
                    <tr>
                        <th>Service</th>
                        <th>Period</th>
                        <th>Impact</th>
                        <th>Reason</th>
                    </tr>
                    {% for anomaly in results.cost.results.cost_anomalies %}
                    <tr>
                        <td>{{ anomaly.service }}</td>
                        <td>{{ anomaly.anomaly_start_date }} to {{ anomaly.anomaly_end_date }}</td>
                        <td>${{ anomaly.impact }}</td>
                        <td>{{ anomaly.reason }}</td>
                    </tr>
                    {% endfor %}
                </table>
            {% else %}
                <p>No cost anomalies found.</p>
            {% endif %}
        </div>
        {% endif %}
        
        <div class="footer">
            <p>Report generated on {{ timestamp }}</p>
            <p>EKS Infrastructure Scanner</p>
        </div>
    </div>
    
    <script>
        var coll = document.getElementsByClassName("collapsible");
        var i;

        for (i = 0; i < coll.length; i++) {
            coll[i].addEventListener("click", function() {
                this.classList.toggle("active");
                var content = this.nextElementSibling;
                if (content.style.maxHeight) {
                    content.style.maxHeight = null;
                } else {
                    content.style.maxHeight = content.scrollHeight + "px";
                }
            });
        }
        
        // Auto-expand security risk items
        window.addEventListener('DOMContentLoaded', (event) => {
            var securityRisks = document.getElementsByClassName("security-risk");
            for (i = 0; i < securityRisks.length; i++) {
                securityRisks[i].classList.add("active");
                var content = securityRisks[i].nextElementSibling;
                content.style.maxHeight = content.scrollHeight + "px";
            }
            
            // Add click handlers for tabs
            var tabs = document.getElementsByClassName("tab");
            for (i = 0; i < tabs.length; i++) {
                tabs[i].addEventListener("click", function() {
                    var tabId = this.getAttribute("data-tab");
                    
                    // Hide all tab contents
                    var tabContents = document.getElementsByClassName("tab-content");
                    for (var j = 0; j < tabContents.length; j++) {
                        tabContents[j].style.display = "none";
                    }
                    
                    // Show the selected tab content
                    document.getElementById(tabId).style.display = "block";
                    
                    // Remove active class from all tabs
                    var tabLinks = document.getElementsByClassName("tab");
                    for (var j = 0; j < tabLinks.length; j++) {
                        tabLinks[j].classList.remove("active-tab");
                    }
                    
                    // Add active class to the clicked tab
                    this.classList.add("active-tab");
                });
            }
            
            // Show the first tab by default
            if (tabs.length > 0) {
                tabs[0].click();
            }
        });
    </script>
</body>
</html>""")
    
    # Create Jinja2 environment
    env = jinja2.Environment(loader=jinja2.FileSystemLoader(template_dir))
    template = env.get_template("report_template.html")
    
    # Render template with data
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    html_content = template.render(
        results=results,
        environment=environment,
        region=region,
        timestamp=timestamp
    )
    
    # Write HTML to file
    with open(output_path, "w") as f:
        f.write(html_content)
    
    return output_path

def generate_pdf_report(
    results: Dict[str, Any],
    output_path: str,
    environment: str,
    region: str,
) -> str:
    """Generate a PDF report"""
    # First generate HTML report
    html_path = output_path.replace('.pdf', '.html')
    generate_html_report(results, html_path, environment, region)
    
    # Convert HTML to PDF using WeasyPrint
    html = weasyprint.HTML(filename=html_path)
    html.write_pdf(output_path)
    
    # Remove temporary HTML file
    os.remove(html_path)
    
    return output_path
