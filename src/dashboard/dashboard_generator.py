import os
import json
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from plotly.subplots import make_subplots
from typing import Dict, Any, List, Optional
from src.dashboard.dashboard_helpers import (
    create_executive_summary_html,
    create_detailed_findings_html,
    create_recommendations_html
)
from src.dashboard.dashboard_compliance_helpers import (
    create_compliance_summary_html,
    create_compliance_details_html
)
from src.dashboard.dashboard_cost_helpers import (
    create_cost_optimization_summary_html,
    create_cost_optimization_details_html
)

class DashboardGenerator:
    """
    Generates interactive dashboard visualizations for AWS infrastructure scan results.
    """
    
    def __init__(self):
        """
        Initialize the dashboard generator.
        """
        pass
    
    def generate_dashboard(self, 
                          scan_results: Dict[str, Any], 
                          output_path: str,
                          environment: str,
                          region: str,
                          ai_key: Optional[str] = None) -> str:
        # Store scan_results for use in other methods
        self.scan_results = scan_results
        """
        Generate an interactive HTML dashboard from scan results.
        
        Args:
            scan_results: The scan results from various scanners
            output_path: Path to save the dashboard HTML file
            environment: The environment name (e.g., dev, prod)
            region: The AWS region
            
        Returns:
            Path to the generated dashboard HTML file
        """
        # Create directory if it doesn't exist
        os.makedirs(os.path.dirname(output_path), exist_ok=True)
        
        # Create the dashboard HTML without charts
        dashboard_html = self._create_dashboard_html([], environment, region)
        
        # Write to file
        with open(output_path, 'w') as f:
            f.write(dashboard_html)
        
        return output_path
    
    def _create_summary_chart(self, scan_results: Dict[str, Any]) -> Optional[go.Figure]:
        """
        Create a summary chart showing resource counts and issues.
        """
        try:
            # Extract resource counts
            resource_types = []
            resource_counts = []
            issue_counts = []
            
            if 'eks' in scan_results:
                resource_types.append('EKS Clusters')
                resource_counts.append(scan_results['eks'].get('results', {}).get('count', 0))
                issue_counts.append(scan_results['eks'].get('results', {}).get('deprecated_count', 0))
            
            if 'ec2' in scan_results:
                resource_types.append('EC2 Instances')
                resource_counts.append(scan_results['ec2'].get('results', {}).get('instance_count', 0))
                issue_counts.append(scan_results['ec2'].get('results', {}).get('public_ip_count', 0))
                
                resource_types.append('Security Groups')
                resource_counts.append(scan_results['ec2'].get('results', {}).get('security_group_count', 0))
                issue_counts.append(scan_results['ec2'].get('results', {}).get('open_security_group_count', 0))
            
            if 'vpc' in scan_results:
                resource_types.append('VPCs')
                resource_counts.append(scan_results['vpc'].get('results', {}).get('vpc_count', 0))
                issue_counts.append(0)  # No specific issue count for VPCs
            
            if 'dynamodb' in scan_results:
                resource_types.append('DynamoDB Tables')
                resource_counts.append(scan_results['dynamodb'].get('results', {}).get('table_count', 0))
                issue_counts.append(scan_results['dynamodb'].get('results', {}).get('low_usage_table_count', 0))
            
            if 'iam' in scan_results:
                resource_types.append('IAM Users')
                resource_counts.append(scan_results['iam'].get('results', {}).get('user_count', 0))
                issue_counts.append(scan_results['iam'].get('results', {}).get('users_with_old_keys_count', 0))
                
                resource_types.append('IAM Roles')
                resource_counts.append(scan_results['iam'].get('results', {}).get('role_count', 0))
                issue_counts.append(scan_results['iam'].get('results', {}).get('permissive_role_count', 0))
            
            if not resource_types:
                return None
            
            # Create figure with two subplots
            fig = make_subplots(
                rows=1, cols=2,
                subplot_titles=("Resource Counts", "Issues Found"),
                specs=[[{"type": "bar"}, {"type": "bar"}]]
            )
            
            # Add resource count bars
            fig.add_trace(
                go.Bar(
                    x=resource_types,
                    y=resource_counts,
                    name="Resources",
                    marker_color='#1f77b4'
                ),
                row=1, col=1
            )
            
            # Add issue count bars
            fig.add_trace(
                go.Bar(
                    x=resource_types,
                    y=issue_counts,
                    name="Issues",
                    marker_color='#d62728'
                ),
                row=1, col=2
            )
            
            # Update layout
            fig.update_layout(
                title_text="Infrastructure Summary",
                height=400,
                showlegend=False
            )
            
            return fig
        except Exception as e:
            print(f"Error creating summary chart: {str(e)}")
            return None
    
    def _create_security_chart(self, scan_results: Dict[str, Any]) -> Optional[go.Figure]:
        """
        Create a chart showing security issues by category.
        """
        try:
            # Collect security issues
            security_categories = []
            security_counts = []
            
            # EC2 security issues
            if 'ec2' in scan_results:
                ec2_results = scan_results['ec2'].get('results', {})
                
                # Public IP instances
                public_ip_count = ec2_results.get('public_ip_count', 0)
                if public_ip_count > 0:
                    security_categories.append('Public IP Instances')
                    security_counts.append(public_ip_count)
                
                # Open security groups
                open_sg_count = ec2_results.get('open_security_group_count', 0)
                if open_sg_count > 0:
                    security_categories.append('Open Security Groups')
                    security_counts.append(open_sg_count)
            
            # EKS security issues
            if 'eks' in scan_results:
                eks_results = scan_results['eks'].get('results', {})
                
                # Deprecated clusters
                deprecated_count = eks_results.get('deprecated_count', 0)
                if deprecated_count > 0:
                    security_categories.append('Deprecated EKS Clusters')
                    security_counts.append(deprecated_count)
            
            # IAM security issues
            if 'iam' in scan_results:
                iam_results = scan_results['iam'].get('results', {})
                
                # Old access keys
                old_keys_count = iam_results.get('users_with_old_keys_count', 0)
                if old_keys_count > 0:
                    security_categories.append('Old Access Keys')
                    security_counts.append(old_keys_count)
                
                # Permissive roles
                permissive_role_count = iam_results.get('permissive_role_count', 0)
                if permissive_role_count > 0:
                    security_categories.append('Permissive IAM Roles')
                    security_counts.append(permissive_role_count)
            
            if not security_categories:
                return None
            
            # Create pie chart for security issues
            fig = go.Figure(data=[go.Pie(
                labels=security_categories,
                values=security_counts,
                hole=.3,
                marker_colors=['#d62728', '#ff7f0e', '#2ca02c', '#9467bd', '#8c564b']
            )])
            
            fig.update_layout(
                title_text="Security Issues by Category",
                height=400
            )
            
            return fig
        except Exception as e:
            print(f"Error creating security chart: {str(e)}")
            return None
    
    def _create_eks_chart(self, eks_results: Dict[str, Any]) -> Optional[go.Figure]:
        """
        Create charts for EKS scan results.
        """
        try:
            results = eks_results.get('results', {})
            clusters = results.get('clusters', [])
            
            if not clusters:
                return None
            
            # Create figure with subplots
            fig = make_subplots(
                rows=1, cols=2,
                subplot_titles=("EKS Cluster Versions", "Problematic Pods by Cluster"),
                specs=[[{"type": "pie"}, {"type": "bar"}]]
            )
            
            # Collect cluster versions
            versions = {}
            for cluster in clusters:
                version = cluster.get('version', 'Unknown')
                versions[version] = versions.get(version, 0) + 1
            
            # Add cluster versions pie chart
            fig.add_trace(
                go.Pie(
                    labels=list(versions.keys()),
                    values=list(versions.values()),
                    name="Cluster Versions"
                ),
                row=1, col=1
            )
            
            # Collect problematic pods by cluster
            cluster_names = []
            problematic_pod_counts = []
            
            for cluster in clusters:
                cluster_name = cluster.get('name', 'Unknown')
                k8s_resources = cluster.get('kubernetes_resources', {})
                problematic_pods = k8s_resources.get('problematic_pods', [])
                
                cluster_names.append(cluster_name)
                problematic_pod_counts.append(len(problematic_pods))
            
            # Add problematic pods bar chart
            fig.add_trace(
                go.Bar(
                    x=cluster_names,
                    y=problematic_pod_counts,
                    name="Problematic Pods"
                ),
                row=1, col=2
            )
            
            # Update layout
            fig.update_layout(
                title_text="EKS Cluster Analysis",
                height=400
            )
            
            return fig
        except Exception as e:
            print(f"Error creating EKS chart: {str(e)}")
            return None
    
    def _create_ec2_chart(self, ec2_results: Dict[str, Any]) -> Optional[go.Figure]:
        """
        Create charts for EC2 scan results.
        """
        try:
            results = ec2_results.get('results', {})
            
            # Create figure with subplots
            fig = make_subplots(
                rows=1, cols=2,
                subplot_titles=("EC2 Instance Categories", "Security Group Analysis"),
                specs=[[{"type": "pie"}, {"type": "bar"}]]
            )
            
            # Collect EC2 instance categories
            instance_count = results.get('instance_count', 0)
            public_ip_count = results.get('public_ip_count', 0)
            orphaned_instance_count = results.get('orphaned_instance_count', 0)
            low_cpu_instance_count = results.get('low_cpu_instance_count', 0)
            
            # Calculate private instances (not public)
            private_ip_count = instance_count - public_ip_count
            
            # Add EC2 instance categories pie chart
            fig.add_trace(
                go.Pie(
                    labels=["Private IP Instances", "Public IP Instances", "Orphaned Instances", "Low CPU Instances"],
                    values=[private_ip_count, public_ip_count, orphaned_instance_count, low_cpu_instance_count],
                    name="Instance Categories"
                ),
                row=1, col=1
            )
            
            # Security group analysis
            sg_count = results.get('security_group_count', 0)
            open_sg_count = results.get('open_security_group_count', 0)
            closed_sg_count = sg_count - open_sg_count
            
            # Add security group bar chart
            fig.add_trace(
                go.Bar(
                    x=["Open Security Groups", "Secure Security Groups"],
                    y=[open_sg_count, closed_sg_count],
                    marker_color=['#d62728', '#2ca02c'],
                    name="Security Groups"
                ),
                row=1, col=2
            )
            
            # Update layout
            fig.update_layout(
                title_text="EC2 Instance and Security Group Analysis",
                height=400
            )
            
            return fig
        except Exception as e:
            print(f"Error creating EC2 chart: {str(e)}")
            return None
    
    def _create_vpc_chart(self, vpc_results: Dict[str, Any]) -> Optional[go.Figure]:
        """
        Create charts for VPC scan results.
        """
        try:
            results = vpc_results.get('results', {})
            vpcs = results.get('vpcs', [])
            
            if not vpcs:
                return None
            
            # Collect VPC data
            vpc_names = []
            subnet_counts = []
            route_table_counts = []
            
            for vpc in vpcs:
                vpc_names.append(vpc.get('vpc_id', 'Unknown'))
                subnet_counts.append(len(vpc.get('subnets', [])))
                route_table_counts.append(len(vpc.get('route_tables', [])))
            
            # Create figure
            fig = go.Figure()
            
            # Add subnet counts
            fig.add_trace(
                go.Bar(
                    x=vpc_names,
                    y=subnet_counts,
                    name="Subnets"
                )
            )
            
            # Add route table counts
            fig.add_trace(
                go.Bar(
                    x=vpc_names,
                    y=route_table_counts,
                    name="Route Tables"
                )
            )
            
            # Update layout
            fig.update_layout(
                title_text="VPC Analysis",
                xaxis_title="VPC ID",
                yaxis_title="Count",
                barmode='group',
                height=400
            )
            
            return fig
        except Exception as e:
            print(f"Error creating VPC chart: {str(e)}")
            return None
    
    def _create_dynamodb_chart(self, dynamodb_results: Dict[str, Any]) -> Optional[go.Figure]:
        """
        Create charts for DynamoDB scan results.
        """
        try:
            results = dynamodb_results.get('results', {})
            
            # Collect DynamoDB data
            on_demand_count = results.get('on_demand_count', 0)
            provisioned_count = results.get('provisioned_count', 0)
            low_usage_count = results.get('low_usage_table_count', 0)
            
            # Create figure with subplots
            fig = make_subplots(
                rows=1, cols=2,
                subplot_titles=("Table Capacity Modes", "Table Usage"),
                specs=[[{"type": "pie"}, {"type": "pie"}]]
            )
            
            # Add capacity mode pie chart
            fig.add_trace(
                go.Pie(
                    labels=["On-Demand", "Provisioned"],
                    values=[on_demand_count, provisioned_count],
                    name="Capacity Modes"
                ),
                row=1, col=1
            )
            
            # Add usage pie chart
            normal_usage_count = (on_demand_count + provisioned_count) - low_usage_count
            fig.add_trace(
                go.Pie(
                    labels=["Normal Usage", "Low Usage"],
                    values=[normal_usage_count, low_usage_count],
                    name="Table Usage"
                ),
                row=1, col=2
            )
            
            # Update layout
            fig.update_layout(
                title_text="DynamoDB Table Analysis",
                height=400
            )
            
            return fig
        except Exception as e:
            print(f"Error creating DynamoDB chart: {str(e)}")
            return None
    
    def _create_iam_chart(self, iam_results: Dict[str, Any]) -> Optional[go.Figure]:
        """
        Create charts for IAM scan results.
        """
        try:
            results = iam_results.get('results', {})
            
            # Collect IAM data
            user_count = results.get('user_count', 0)
            role_count = results.get('role_count', 0)
            users_with_old_keys_count = results.get('users_with_old_keys_count', 0)
            permissive_role_count = results.get('permissive_role_count', 0)
            
            # Calculate users with current keys
            users_with_current_keys = user_count - users_with_old_keys_count
            
            # Calculate roles with proper permissions
            roles_with_proper_permissions = role_count - permissive_role_count
            
            # Create figure with subplots
            fig = make_subplots(
                rows=1, cols=2,
                subplot_titles=("IAM User Access Keys", "IAM Role Permissions"),
                specs=[[{"type": "pie"}, {"type": "pie"}]]
            )
            
            # Add user access keys pie chart
            fig.add_trace(
                go.Pie(
                    labels=["Current Keys", "Old Keys (>90 days)"],
                    values=[users_with_current_keys, users_with_old_keys_count],
                    marker_colors=['#2ca02c', '#d62728'],
                    name="Access Keys"
                ),
                row=1, col=1
            )
            
            # Add role permissions pie chart
            fig.add_trace(
                go.Pie(
                    labels=["Proper Permissions", "Overly Permissive"],
                    values=[roles_with_proper_permissions, permissive_role_count],
                    marker_colors=['#2ca02c', '#d62728'],
                    name="Role Permissions"
                ),
                row=1, col=2
            )
            
            # Update layout
            fig.update_layout(
                title_text="IAM Analysis",
                height=400
            )
            
            return fig
        except Exception as e:
            print(f"Error creating IAM chart: {str(e)}")
            return None
    
    def _create_cost_chart(self, cost_results: Dict[str, Any]) -> Optional[go.Figure]:
        """
        Create charts for cost scan results.
        """
        try:
            results = cost_results.get('results', {})
            
            # Check if we have cost data
            if 'cost_by_service' not in results:
                return None
            
            cost_by_service = results.get('cost_by_service', {})
            
            # Extract service names and costs
            services = []
            costs = []
            
            for service, cost in cost_by_service.items():
                services.append(service)
                costs.append(cost)
            
            # Create bar chart
            fig = go.Figure(data=[
                go.Bar(
                    x=services,
                    y=costs,
                    name="Cost by Service"
                )
            ])
            
            # Update layout
            fig.update_layout(
                title_text="Cost Analysis by Service",
                xaxis_title="AWS Service",
                yaxis_title="Monthly Cost ($)",
                height=400
            )
            
            return fig
        except Exception as e:
            print(f"Error creating cost chart: {str(e)}")
            return None
    
    def _create_recommendations_chart(self, ai_analysis: Dict[str, Any]) -> Optional[go.Figure]:
        """
        Create a chart showing AI recommendations by category and severity.
        """
        try:
            recommendations = ai_analysis.get('recommendations', [])
            
            if not recommendations:
                return None
            
            # Collect recommendation data
            categories = {}
            severities = {'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
            
            for rec in recommendations:
                category = rec.get('category', 'Unknown')
                severity = rec.get('severity', 'Unknown')
                
                # Count by category
                categories[category] = categories.get(category, 0) + 1
                
                # Count by severity
                if severity in severities:
                    severities[severity] += 1
            
            # Create figure with subplots
            fig = make_subplots(
                rows=1, cols=2,
                subplot_titles=("Recommendations by Category", "Recommendations by Severity"),
                specs=[[{"type": "pie"}, {"type": "pie"}]]
            )
            
            # Add category pie chart
            fig.add_trace(
                go.Pie(
                    labels=list(categories.keys()),
                    values=list(categories.values()),
                    name="Categories"
                ),
                row=1, col=1
            )
            
            # Add severity pie chart
            fig.add_trace(
                go.Pie(
                    labels=list(severities.keys()),
                    values=list(severities.values()),
                    marker_colors=['#d62728', '#ff7f0e', '#2ca02c'],
                    name="Severities"
                ),
                row=1, col=2
            )
            
            # Update layout
            fig.update_layout(
                title_text="AI Recommendations Analysis",
                height=400
            )
            
            return fig
        except Exception as e:
            print(f"Error creating recommendations chart: {str(e)}")
            return None
    
    def _create_dashboard_html(self, figures: List[go.Figure], environment: str, region: str) -> str:
        """
        Create the HTML for the dashboard.
        """
        # Get scan results from class instance
        scan_results = getattr(self, 'scan_results', {})
        
        # Start with HTML header
        html = f"""
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>AWS Infrastructure Scan Dashboard - {environment}</title>
            <script src="https://cdn.plot.ly/plotly-latest.min.js"></script>
            <style>
                body {{
                    font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                    margin: 0;
                    padding: 0;
                    background-color: #f8f9fa;
                }}
                .container {{
                    max-width: 1200px;
                    margin: 0 auto;
                    padding: 20px;
                }}
                header {{
                    background-color: #232f3e;
                    color: white;
                    padding: 25px;
                    margin-bottom: 30px;
                    border-radius: 5px;
                    box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
                }}
                h1, h2, h3, h4 {{
                    margin-top: 0;
                    font-weight: 600;
                }}
                .chart-container {{
                    background-color: white;
                    border-radius: 5px;
                    padding: 20px;
                    margin-bottom: 30px;
                    box-shadow: 0 2px 4px rgba(0, 0, 0, 0.05);
                }}
                .section {{
                    background-color: white;
                    border-radius: 5px;
                    padding: 20px;
                    margin-bottom: 30px;
                    box-shadow: 0 2px 4px rgba(0, 0, 0, 0.05);
                }}
                .footer {{
                    margin-top: 50px;
                    text-align: center;
                    color: #777;
                    font-size: 0.9em;
                    padding: 20px;
                }}
                .tabs {{
                    display: flex;
                    margin-bottom: 20px;
                    border-bottom: 1px solid #ddd;
                }}
                .tab {{
                    background-color: #f8f9fa;
                    border: none;
                    outline: none;
                    cursor: pointer;
                    padding: 10px 15px;
                    margin-right: 2px;
                    font-size: 14px;
                    transition: 0.3s;
                    border-radius: 5px 5px 0 0;
                }}
                .tab:hover {{
                    background-color: #e9ecef;
                }}
                .active-tab {{
                    background-color: #fff;
                    border: 1px solid #ddd;
                    border-bottom: 1px solid #fff;
                    margin-bottom: -1px;
                    font-weight: bold;
                }}
                .tab-content {{
                    padding: 20px;
                    border: 1px solid #ddd;
                    border-top: none;
                    border-radius: 0 0 5px 5px;
                }}
                table {{
                    width: 100%;
                    border-collapse: collapse;
                    margin-bottom: 20px;
                    border-radius: 5px;
                    overflow: hidden;
                    box-shadow: 0 0 20px rgba(0, 0, 0, 0.05);
                }}
                th, td {{
                    padding: 15px;
                    border-bottom: 1px solid #eee;
                    text-align: left;
                }}
                th {{
                    background-color: #f2f2f2;
                    font-weight: 600;
                }}
                tr:hover {{
                    background-color: #f8f9fa;
                }}
                .severity-high {{
                    background-color: #d9534f;
                    color: white;
                    padding: 3px 7px;
                    border-radius: 3px;
                    font-size: 12px;
                }}
                .severity-medium {{
                    background-color: #f0ad4e;
                    color: white;
                    padding: 3px 7px;
                    border-radius: 3px;
                    font-size: 12px;
                }}
                .severity-low {{
                    background-color: #5bc0de;
                    color: white;
                    padding: 3px 7px;
                    border-radius: 3px;
                    font-size: 12px;
                }}
                .collapsible {{
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
                }}
                .collapsible.security-risk {{
                    border-left: 4px solid #a94442;
                }}
                .active, .collapsible:hover {{
                    background-color: #e9ecef;
                }}
                .content {{
                    padding: 0 18px;
                    max-height: 0;
                    overflow: hidden;
                    transition: max-height 0.2s ease-out;
                    background-color: white;
                    border-radius: 0 0 5px 5px;
                }}
                .badge {{
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
                }}
                .badge-warning {{
                    background-color: #f0ad4e;
                }}
                .badge-danger {{
                    background-color: #d9534f;
                }}
                .badge-info {{
                    background-color: #5bc0de;
                }}
                .recommendation {{
                    background-color: white;
                    border-radius: 5px;
                    padding: 20px;
                    margin-bottom: 20px;
                    box-shadow: 0 2px 4px rgba(0, 0, 0, 0.05);
                    border-left: 4px solid #5bc0de;
                }}
                .recommendation.high {{
                    border-left: 4px solid #d9534f;
                }}
                .recommendation.medium {{
                    border-left: 4px solid #f0ad4e;
                }}
                .recommendation.low {{
                    border-left: 4px solid #5bc0de;
                }}
                .steps {{
                    background-color: #f8f9fa;
                    padding: 15px;
                    border-radius: 5px;
                    margin-top: 15px;
                }}
                .commands {{
                    background-color: #f0f7ff;
                    padding: 15px;
                    border-radius: 5px;
                    margin-top: 15px;
                }}
                .best-practices {{
                    background-color: #f0fff0;
                    padding: 15px;
                    border-radius: 5px;
                    margin-top: 15px;
                }}
                .best-practices li, .steps li {{
                    white-space: normal;
                    word-break: break-word;
                    margin-bottom: 8px;
                }}
                .commands code {{
                    white-space: pre-wrap;
                    word-break: break-word;
                }}
                code {{
                    display: block;
                    padding: 10px;
                    background-color: #f8f9fa;
                    border: 1px solid #ddd;
                    border-radius: 4px;
                    font-family: monospace;
                    white-space: pre-wrap;
                    margin: 10px 0;
                }}
                .summary-box {{
                    background-color: #f8f9fa;
                    border-left: 4px solid #0073bb;
                    padding: 15px;
                    margin-bottom: 20px;
                    border-radius: 5px;
                }}
                .warning-box {{
                    background-color: #fcf8e3;
                    border-left: 4px solid #f0ad4e;
                    padding: 15px;
                    margin-bottom: 20px;
                    border-radius: 5px;
                }}
                .danger-box {{
                    background-color: #f2dede;
                    border-left: 4px solid #d9534f;
                    padding: 15px;
                    margin-bottom: 20px;
                    border-radius: 5px;
                }}
                .compliance-framework {{
                    background-color: white;
                    border-radius: 5px;
                    padding: 15px;
                    margin-bottom: 20px;
                    box-shadow: 0 2px 4px rgba(0, 0, 0, 0.05);
                    border-left: 4px solid #0073bb;
                }}
                .compliance-details {{
                    background-color: #f8f9fa;
                    padding: 15px;
                    border-radius: 5px;
                    margin-top: 15px;
                }}
                .compliance-table {{
                    width: 100%;
                    border-collapse: collapse;
                    margin-top: 20px;
                }}
                .compliance-table th {{
                    background-color: #f2f2f2;
                    padding: 10px;
                    text-align: left;
                }}
                .compliance-table td {{
                    padding: 10px;
                    border-bottom: 1px solid #ddd;
                }}
                .compliance-section {{
                    margin-bottom: 30px;
                }}
                .cost-savings-summary {{
                    background-color: #f8f9fa;
                    border-radius: 5px;
                    padding: 20px;
                    margin-bottom: 20px;
                }}
                .savings-metrics {{
                    display: flex;
                    justify-content: space-around;
                    flex-wrap: wrap;
                    margin-bottom: 20px;
                }}
                .metric {{
                    text-align: center;
                    padding: 15px;
                    background-color: white;
                    border-radius: 5px;
                    box-shadow: 0 2px 4px rgba(0, 0, 0, 0.05);
                    min-width: 150px;
                    margin: 10px;
                }}
                .metric.highlight {{
                    background-color: #e8f4f8;
                    border-left: 4px solid #0073bb;
                }}
                .metric-value {{
                    display: block;
                    font-size: 24px;
                    font-weight: bold;
                    color: #333;
                    margin-bottom: 5px;
                }}
                .metric-label {{
                    display: block;
                    font-size: 14px;
                    color: #666;
                }}
                .cost-recommendations {{
                    width: 100%;
                    border-collapse: collapse;
                    margin-top: 20px;
                }}
                .cost-recommendations th {{
                    background-color: #f2f2f2;
                    padding: 10px;
                    text-align: left;
                }}
                .cost-recommendations td {{
                    padding: 10px;
                    border-bottom: 1px solid #ddd;
                }}
                .cost-recommendations td.savings {{
                    font-weight: bold;
                    color: #28a745;
                }}
                .implementation-details {{
                    margin-top: 30px;
                }}
                .implementation-card {{
                    background-color: white;
                    border-radius: 5px;
                    padding: 15px;
                    margin-bottom: 15px;
                    box-shadow: 0 2px 4px rgba(0, 0, 0, 0.05);
                }}
                .effort-low {{
                    color: #28a745;
                    font-weight: bold;
                }}
                .effort-medium {{
                    color: #f0ad4e;
                    font-weight: bold;
                }}
                .effort-high {{
                    color: #d9534f;
                    font-weight: bold;
                }}
                .cost-section {{
                    margin-bottom: 30px;
                }}
                .cost-table {{
                    width: 100%;
                    border-collapse: collapse;
                    margin-top: 20px;
                }}
                .cost-table th {{
                    background-color: #f2f2f2;
                    padding: 10px;
                    text-align: left;
                }}
                .cost-table td {{
                    padding: 10px;
                    border-bottom: 1px solid #ddd;
                }}
                .section-reference {{
                    background-color: #f8f9fa;
                    border-left: 4px solid #0073bb;
                    padding: 15px;
                    margin-bottom: 20px;
                    border-radius: 5px;
                }}
            </style>
        </head>
        <body>
            <div class="container">
                <header>
                    <h1>AWS Infrastructure Scan Report</h1>
                    <p>Environment: {environment} | Region: {region} | Generated: {pd.Timestamp.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
                </header>
                
                <!-- Executive Summary Section -->
                <div class="section">
                    <h2>Executive Summary</h2>
                    {create_executive_summary_html(scan_results)}
                </div>
        """
        
        # Add tabs for different sections
        html += """
                <div class="section">
                    <div class="tabs">
                        <button class="tab active-tab" data-tab="findings">Detailed Findings</button>
                        <button class="tab" data-tab="recommendations">Recommendations</button>
                        <button class="tab" data-tab="compliance">Compliance Frameworks</button>
                        <button class="tab" data-tab="cost">Cost Optimization</button>
                    </div>
                    
                    <!-- Detailed Findings Tab -->
                    <div id="findings" class="tab-content" style="display:block;">
        """
        
        # Add detailed findings tables
        html += create_detailed_findings_html(scan_results)
        
        html += """
                    </div>
                    
                    <!-- Recommendations Tab -->
                    <div id="recommendations" class="tab-content" style="display:none;">
        """
        
        # Add recommendations
        html += create_recommendations_html(scan_results)
        
        html += """
                    </div>
                    
                    <!-- Compliance Frameworks Tab -->
                    <div id="compliance" class="tab-content" style="display:none;">
                        <!-- Compliance Summary Section -->
                        <div class="compliance-section">
                            <h3>Compliance Framework Mappings</h3>
                            <p>This section maps scan findings to industry-standard compliance frameworks:</p>
"""
        
        # Add compliance summary HTML
        html += create_compliance_summary_html(scan_results)
        
        html += """
                        </div>
                        
                        <!-- Compliance Details Section -->
                        <div class="compliance-section">
                            <h3>Detailed Compliance Findings</h3>
"""
        
        # Add compliance details HTML
        html += create_compliance_details_html(scan_results)
        
        html += """
                        </div>
                    </div>
                    
                    <!-- Cost Optimization Tab -->
                    <div id="cost" class="tab-content" style="display:none;">
                        <!-- Cost Optimization Summary Section -->
                        <div class="cost-section">
                            <h3>Cost Optimization Overview</h3>
                            <p>This section provides an overview of your AWS infrastructure costs and optimization opportunities:</p>
"""
        
        # Add cost optimization summary HTML
        html += create_cost_optimization_summary_html(scan_results)
        
        html += """
                        </div>
                        
                        <!-- Cost Optimization Details Section -->
                        <div class="cost-section">
                            <h3>Cost Optimization Recommendations</h3>
"""
        
        # Add cost optimization details HTML
        html += create_cost_optimization_details_html(scan_results)
        
        html += """
                        </div>
                    </div>
                </div>
        """
        
        # Add JavaScript for tab switching
        html += """
                <script>
                    // Tab switching
                    var tabs = document.getElementsByClassName("tab");
                    for (var i = 0; i < tabs.length; i++) {
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
                            for (var j = 0; j < tabs.length; j++) {
                                tabs[j].classList.remove("active-tab");
                            }
                            
                            // Add active class to the clicked tab
                            this.classList.add("active-tab");
                        });
                    }
                    
                    // Collapsible sections
                    var coll = document.getElementsByClassName("collapsible");
                    for (var i = 0; i < coll.length; i++) {
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
                        for (var i = 0; i < securityRisks.length; i++) {
                            securityRisks[i].classList.add("active");
                            var content = securityRisks[i].nextElementSibling;
                            content.style.maxHeight = content.scrollHeight + "px";
                        }
                    });
                </script>
        """
        
        # Add footer and close HTML
        html += """
                <div class="footer">
                    <p>EKS Infrastructure Scanner - Comprehensive Security Report</p>
                </div>
            </div>
        </body>
        </html>
        """
        
        return html
