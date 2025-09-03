"""
Helper methods for the dashboard generator.
"""
from typing import Dict, Any
from src.dashboard.dashboard_helpers_new import (
    create_rds_findings_html,
    create_lambda_findings_html,
    create_enhanced_dynamodb_findings_html
)

def create_executive_summary_html(scan_results: Dict[str, Any]) -> str:
    """
    Create HTML for the executive summary section.
    
    Args:
        scan_results: The scan results from various scanners
        
    Returns:
        HTML string for the executive summary
    """
    html = '<div class="summary-box">'
    html += '<h3>Resources Scanned</h3>'
    html += '<ul>'
    
    # EKS resources
    if 'eks' in scan_results:
        eks_results = scan_results['eks'].get('results', {})
        html += f'<li>EKS Clusters: <strong>{eks_results.get("count", 0)}</strong></li>'
    
    # EC2 resources
    if 'ec2' in scan_results:
        ec2_results = scan_results['ec2'].get('results', {})
        html += f'<li>EC2 Instances: <strong>{ec2_results.get("instance_count", 0)}</strong></li>'
        html += f'<li>Security Groups: <strong>{ec2_results.get("security_group_count", 0)}</strong></li>'
    
    # VPC resources
    if 'vpc' in scan_results:
        vpc_results = scan_results['vpc'].get('results', {})
        html += f'<li>VPCs: <strong>{vpc_results.get("vpc_count", 0)}</strong></li>'
    
    # DynamoDB resources
    if 'dynamodb' in scan_results:
        dynamodb_results = scan_results['dynamodb'].get('results', {})
        html += f'<li>DynamoDB Tables: <strong>{dynamodb_results.get("table_count", 0)}</strong></li>'
    
    # IAM resources
    if 'iam' in scan_results:
        iam_results = scan_results['iam'].get('results', {})
        html += f'<li>IAM Users: <strong>{iam_results.get("user_count", 0)}</strong></li>'
        html += f'<li>IAM Roles: <strong>{iam_results.get("role_count", 0)}</strong></li>'
    
    # Cost resources
    if 'cost' in scan_results:
        cost_results = scan_results['cost'].get('results', {})
        if 'total_potential_savings' in cost_results:
            total_savings = cost_results.get("total_potential_savings", 0)
            total_cost = cost_results.get("total_current_cost", 0)
            savings_percentage = cost_results.get("avg_savings_percentage", 0)
            html += f'<li>Current Monthly Cost: <strong>${total_cost:.2f}</strong></li>'
            html += f'<li>Potential Monthly Savings: <strong>${total_savings:.2f}</strong> ({savings_percentage}%)</li>'
    
    html += '</ul>'
    html += '</div>'
    
    # Add warning boxes for critical issues
    warnings = []
    
    # EKS warnings
    if 'eks' in scan_results:
        eks_results = scan_results['eks'].get('results', {})
        deprecated_count = eks_results.get('deprecated_count', 0)
        if deprecated_count > 0:
            warnings.append({
                'severity': 'danger',
                'title': f'⚠️ {deprecated_count} EKS clusters are running deprecated versions',
                'description': 'Deprecated Kubernetes versions may have security vulnerabilities and lack support.'
            })
    
    # EC2 warnings
    if 'ec2' in scan_results:
        ec2_results = scan_results['ec2'].get('results', {})
        public_ip_count = ec2_results.get('public_ip_count', 0)
        if public_ip_count > 0:
            warnings.append({
                'severity': 'danger',
                'title': f'⚠️ {public_ip_count} EC2 instances have public IP addresses',
                'description': 'Instances with public IPs are directly accessible from the internet and may be vulnerable to attacks if not properly secured.'
            })
        
        open_sg_count = ec2_results.get('open_security_group_count', 0)
        if open_sg_count > 0:
            warnings.append({
                'severity': 'danger',
                'title': f'⚠️ {open_sg_count} security groups have potentially risky open ports',
                'description': 'Security groups with open ports (0.0.0.0/0) can expose your infrastructure to unauthorized access.'
            })
    
    # IAM warnings
    if 'iam' in scan_results:
        iam_results = scan_results['iam'].get('results', {})
        old_keys_count = iam_results.get('users_with_old_keys_count', 0)
        if old_keys_count > 0:
            warnings.append({
                'severity': 'warning',
                'title': f'⚠️ {old_keys_count} IAM users have access keys older than 90 days',
                'description': 'Old access keys pose a security risk and should be rotated regularly.'
            })
        
        permissive_role_count = iam_results.get('permissive_role_count', 0)
        if permissive_role_count > 0:
            warnings.append({
                'severity': 'warning',
                'title': f'⚠️ {permissive_role_count} IAM roles have overly permissive policies',
                'description': 'Overly permissive policies violate the principle of least privilege and increase the potential impact of credential compromise.'
            })
    
    # Add warning boxes
    for warning in warnings:
        severity = warning['severity']
        title = warning['title']
        description = warning['description']
        
        html += f'<div class="{severity}-box">'
        html += f'<h4>{title}</h4>'
        html += f'<p>{description}</p>'
        html += '</div>'
    
    return html

def create_detailed_findings_html(scan_results: Dict[str, Any]) -> str:
    """
    Create HTML for the detailed findings section.
    
    Args:
        scan_results: The scan results from various scanners
        
    Returns:
        HTML string for the detailed findings
    """
    html = ""
    
    # Add RDS findings
    rds_html = create_rds_findings_html(scan_results)
    if rds_html:
        html += rds_html
    
    # Add Lambda findings
    lambda_html = create_lambda_findings_html(scan_results)
    if lambda_html:
        html += lambda_html
    
    # Add enhanced DynamoDB findings
    enhanced_dynamodb_html = create_enhanced_dynamodb_findings_html(scan_results)
    if enhanced_dynamodb_html:
        html += enhanced_dynamodb_html
    
    # EKS Findings
    if 'eks' in scan_results:
        html += '<h3>EKS Findings</h3>'
        eks_results = scan_results['eks'].get('results', {})
        clusters = eks_results.get('clusters', [])
        
        if clusters:
            # Cluster versions table
            html += '<h4>EKS Cluster Versions</h4>'
            html += '<table>'
            html += '<tr><th>Cluster Name</th><th>Version</th><th>Status</th></tr>'
            
            for cluster in clusters:
                name = cluster.get('name', 'Unknown')
                version = cluster.get('version', 'Unknown')
                is_deprecated = version in eks_results.get('deprecated_versions', [])
                status = '<span class="badge badge-danger">Deprecated</span>' if is_deprecated else '<span class="badge badge-info">Current</span>'
                
                html += f'<tr><td>{name}</td><td>{version}</td><td>{status}</td></tr>'
            
            html += '</table>'
            
            # Problematic pods table
            problematic_pods_exist = False
            for cluster in clusters:
                k8s_resources = cluster.get('kubernetes_resources', {})
                problematic_pods = k8s_resources.get('problematic_pods', [])
                if problematic_pods:
                    problematic_pods_exist = True
                    break
            
            if problematic_pods_exist:
                html += '<h4>Problematic Pods</h4>'
                html += '<table>'
                html += '<tr><th>Cluster</th><th>Namespace</th><th>Pod Name</th><th>Status</th><th>Issue</th></tr>'
                
                for cluster in clusters:
                    cluster_name = cluster.get('name', 'Unknown')
                    k8s_resources = cluster.get('kubernetes_resources', {})
                    problematic_pods = k8s_resources.get('problematic_pods', [])
                    
                    for pod in problematic_pods:
                        namespace = pod.get('namespace', 'Unknown')
                        name = pod.get('name', 'Unknown')
                        status = pod.get('status', 'Unknown')
                        issue = pod.get('issue', 'Unknown')
                        
                        html += f'<tr><td>{cluster_name}</td><td>{namespace}</td><td>{name}</td><td>{status}</td><td>{issue}</td></tr>'
                
                html += '</table>'
            
            # Unused PVCs table
            unused_pvcs_exist = False
            for cluster in clusters:
                k8s_resources = cluster.get('kubernetes_resources', {})
                unused_pvcs = k8s_resources.get('unused_pvcs', [])
                if unused_pvcs:
                    unused_pvcs_exist = True
                    break
            
            if unused_pvcs_exist:
                html += '<h4>Unused Persistent Volume Claims</h4>'
                html += '<table>'
                html += '<tr><th>Cluster</th><th>Namespace</th><th>PVC Name</th><th>Storage Class</th><th>Size</th></tr>'
                
                for cluster in clusters:
                    cluster_name = cluster.get('name', 'Unknown')
                    k8s_resources = cluster.get('kubernetes_resources', {})
                    unused_pvcs = k8s_resources.get('unused_pvcs', [])
                    
                    for pvc in unused_pvcs:
                        namespace = pvc.get('namespace', 'Unknown')
                        name = pvc.get('name', 'Unknown')
                        storage_class = pvc.get('storage_class', 'Unknown')
                        size = pvc.get('size', 'Unknown')
                        
                        html += f'<tr><td>{cluster_name}</td><td>{namespace}</td><td>{name}</td><td>{storage_class}</td><td>{size}</td></tr>'
                
                html += '</table>'
        else:
            html += '<p>No EKS clusters found.</p>'
    
    # EC2 Findings
    if 'ec2' in scan_results:
        html += '<h3>EC2 Findings</h3>'
        ec2_results = scan_results['ec2'].get('results', {})
        
        # Public IP instances
        public_ip_instances = ec2_results.get('instances_with_public_ip', [])
        if public_ip_instances:
            html += '<h4>Instances with Public IPs</h4>'
            html += '<table>'
            html += '<tr><th>Instance ID</th><th>Public IP</th><th>State</th></tr>'
            
            for instance in public_ip_instances:
                instance_id = instance.get('InstanceId', 'Unknown')
                public_ip = instance.get('PublicIpAddress', 'Unknown')
                state = instance.get('State', 'Unknown')
                
                html += f'<tr><td>{instance_id}</td><td>{public_ip}</td><td>{state}</td></tr>'
            
            html += '</table>'
        
        # Open security groups
        open_security_groups = ec2_results.get('open_security_groups', [])
        if open_security_groups:
            html += '<h4>Open Security Groups</h4>'
            html += '<table>'
            html += '<tr><th>Security Group ID</th><th>Name</th><th>Open Ports</th><th>VPC ID</th></tr>'
            
            for sg in open_security_groups:
                sg_id = sg.get('GroupId', 'Unknown')
                name = sg.get('GroupName', 'Unknown')
                open_ports = ', '.join(map(str, sg.get('OpenPorts', [])))
                vpc_id = sg.get('VpcId', 'Unknown')
                
                html += f'<tr><td>{sg_id}</td><td>{name}</td><td>{open_ports}</td><td>{vpc_id}</td></tr>'
            
            html += '</table>'
        
        # Orphaned instances
        orphaned_instances = ec2_results.get('orphaned_instances', [])
        if orphaned_instances:
            html += '<h4>Orphaned Instances</h4>'
            html += '<table>'
            html += '<tr><th>Instance ID</th><th>Type</th><th>State</th><th>Launch Time</th></tr>'
            
            for instance in orphaned_instances:
                instance_id = instance.get('InstanceId', 'Unknown')
                instance_type = instance.get('InstanceType', 'Unknown')
                state = instance.get('State', 'Unknown')
                
                # Format launch time to be more readable
                launch_time = instance.get('LaunchTime', 'Unknown')
                if launch_time != 'Unknown' and not isinstance(launch_time, str):
                    try:
                        launch_time = launch_time.strftime('%Y-%m-%d %H:%M:%S')
                    except:
                        pass
                
                html += f'<tr><td>{instance_id}</td><td>{instance_type}</td><td>{state}</td><td>{launch_time}</td></tr>'
            
            html += '</table>'
        
        # Low CPU instances
        low_cpu_instances = ec2_results.get('low_cpu_instances', [])
        if low_cpu_instances:
            html += '<h4>Low CPU Usage Instances</h4>'
            html += '<table>'
            html += '<tr><th>Instance ID</th><th>Type</th><th>CPU Usage</th><th>State</th><th>Recommendation</th></tr>'
            
            for instance in low_cpu_instances:
                instance_id = instance.get('InstanceId', 'Unknown')
                instance_type = instance.get('InstanceType', 'Unknown')
                cpu_usage = f"{instance.get('AverageCPUUtilization', 0):.1f}%"
                state = instance.get('State', 'Unknown')
                
                # Determine recommendation based on CPU usage
                avg_cpu = instance.get('AverageCPUUtilization', 0)
                if avg_cpu < 5:
                    recommendation = "Consider stopping or terminating if not needed"
                elif avg_cpu < 10:
                    recommendation = "Consider downsizing instance type"
                else:
                    recommendation = "Monitor usage patterns before resizing"
                
                html += f'<tr><td>{instance_id}</td><td>{instance_type}</td><td>{cpu_usage}</td><td>{state}</td><td>{recommendation}</td></tr>'
            
            html += '</table>'
    
    # IAM Findings
    if 'iam' in scan_results:
        html += '<h3>IAM Findings</h3>'
        iam_results = scan_results['iam'].get('results', {})
        
        # Users with old access keys
        users_with_old_keys = iam_results.get('users_with_old_keys', [])
        if users_with_old_keys:
            html += '<h4>Users with Old Access Keys</h4>'
            html += '<table>'
            html += '<tr><th>Username</th><th>Access Key ID</th><th>Age (days)</th><th>Last Used</th></tr>'
            
            for user in users_with_old_keys:
                username = user.get('username', 'Unknown')
                access_key_id = user.get('access_key_id', 'Unknown')
                age_days = user.get('age_days', 'Unknown')
                last_used = user.get('last_used', 'Unknown')
                
                html += f'<tr><td>{username}</td><td>{access_key_id}</td><td>{age_days}</td><td>{last_used}</td></tr>'
            
            html += '</table>'
        
        # Permissive roles
        permissive_roles = iam_results.get('permissive_roles', [])
        if permissive_roles:
            html += '<h4>Overly Permissive IAM Roles</h4>'
            html += '<table>'
            html += '<tr><th>Role Name</th><th>Issue</th><th>Policy Name</th><th>Recommendation</th></tr>'
            
            for role in permissive_roles:
                role_name = role.get('role_name', 'Unknown')
                issue = role.get('issue', 'Unknown')
                policy_name = role.get('policy_name', 'Unknown')
                recommendation = role.get('recommendation', 'Review permissions')
                
                html += f'<tr><td>{role_name}</td><td>{issue}</td><td>{policy_name}</td><td>{recommendation}</td></tr>'
            
            html += '</table>'
    
    # DynamoDB Findings
    if 'dynamodb' in scan_results:
        html += '<h3>DynamoDB Findings</h3>'
        dynamodb_results = scan_results['dynamodb'].get('results', {})
        
        # Low usage tables
        low_usage_tables = dynamodb_results.get('low_usage_tables', [])
        if low_usage_tables:
            html += '<h4>Low Usage Tables</h4>'
            html += '<table>'
            html += '<tr><th>Table Name</th><th>Capacity Mode</th><th>Size (MB)</th><th>Item Count</th><th>Recommendation</th></tr>'
            
            for table in low_usage_tables:
                table_name = table.get('table_name', 'Unknown')
                capacity_mode = table.get('capacity_mode', 'Unknown')
                size_mb = table.get('size_mb', 'Unknown')
                item_count = table.get('item_count', 'Unknown')
                recommendation = table.get('recommendation', 'Consider on-demand capacity')
                
                html += f'<tr><td>{table_name}</td><td>{capacity_mode}</td><td>{size_mb}</td><td>{item_count}</td><td>{recommendation}</td></tr>'
            
            html += '</table>'
    
    # Add a reference to the Cost Optimization tab
    if 'cost' in scan_results:
        html += '<div class="section-reference">'
        html += '<h3>Cost Optimization</h3>'
        html += '<p>Cost optimization findings and recommendations have been moved to the <strong>Cost Optimization</strong> tab.</p>'
        html += '<p>Please click on the "Cost Optimization" tab to view detailed cost analysis and savings recommendations.</p>'
        html += '</div>'
    
    if not html:
        html = '<p>No detailed findings available.</p>'
    
    return html

def create_recommendations_html(scan_results: Dict[str, Any]) -> str:
    """
    Create HTML for the recommendations section.
    
    Args:
        scan_results: The scan results from various scanners
        
    Returns:
        HTML string for the recommendations
    """
    html = ""
    
    # Check if AI analysis is available
    if 'ai_analysis' in scan_results and 'recommendations' in scan_results['ai_analysis']:
        recommendations = scan_results['ai_analysis']['recommendations']
        
        if recommendations:
            # Add tabs for different severity levels
            html += '''
            <div class="tabs">
                <button class="tab active-tab" data-tab="all-recs">All Recommendations</button>
                <button class="tab" data-tab="high-recs">High Priority</button>
                <button class="tab" data-tab="medium-recs">Medium Priority</button>
                <button class="tab" data-tab="low-recs">Low Priority</button>
            </div>
            
            <!-- All Recommendations Tab -->
            <div id="all-recs" class="tab-content" style="display:block;">
            '''
            
            # Add all recommendations
            for rec in recommendations:
                severity = rec.get('severity', 'LOW').lower()
                category = rec.get('category', 'General')
                title = rec.get('title', 'Unknown')
                description = rec.get('description', '')
                steps = rec.get('steps', [])
                commands = rec.get('commands', [])
                best_practices = rec.get('best_practices', [])
                
                html += f'<div class="recommendation {severity}">'
                html += f'<h3>{title}</h3>'
                html += f'<p><strong>Category:</strong> {category} <span class="severity-{severity}">{severity.upper()}</span></p>'
                html += f'<p>{description}</p>'
                
                if steps:
                    html += '<div class="steps">'
                    html += '<h4>Implementation Steps:</h4>'
                    html += '<ol>'
                    for step in steps:
                        html += f'<li>{step}</li>'
                    html += '</ol>'
                    html += '</div>'
                
                if commands:
                    html += '<div class="commands">'
                    html += '<h4>AWS CLI Commands:</h4>'
                    for command in commands:
                        html += f'<code>{command}</code>'
                    html += '</div>'
                
                if best_practices:
                    html += '<div class="best-practices">'
                    html += '<h4>Best Practices:</h4>'
                    html += '<ul>'
                    for practice in best_practices:
                        html += f'<li>{practice}</li>'
                    html += '</ul>'
                    html += '</div>'
                
                html += '</div>'
            
            html += '</div>'
            
            # High Priority Tab
            html += '<div id="high-recs" class="tab-content" style="display:none;">'
            high_count = 0
            
            for rec in recommendations:
                if rec.get('severity', '').upper() == 'HIGH':
                    high_count += 1
                    title = rec.get('title', 'Unknown')
                    category = rec.get('category', 'General')
                    description = rec.get('description', '')
                    steps = rec.get('steps', [])
                    commands = rec.get('commands', [])
                    best_practices = rec.get('best_practices', [])
                    
                    html += '<div class="recommendation high">'
                    html += f'<h3>{title}</h3>'
                    html += f'<p><strong>Category:</strong> {category} <span class="severity-high">HIGH</span></p>'
                    html += f'<p>{description}</p>'
                    
                    if steps:
                        html += '<div class="steps">'
                        html += '<h4>Implementation Steps:</h4>'
                        html += '<ol>'
                        for step in steps:
                            html += f'<li>{step}</li>'
                        html += '</ol>'
                        html += '</div>'
                    
                    if commands:
                        html += '<div class="commands">'
                        html += '<h4>AWS CLI Commands:</h4>'
                        for command in commands:
                            html += f'<code>{command}</code>'
                        html += '</div>'
                    
                    if best_practices:
                        html += '<div class="best-practices">'
                        html += '<h4>Best Practices:</h4>'
                        html += '<ul>'
                        for practice in best_practices:
                            html += f'<li>{practice}</li>'
                        html += '</ul>'
                        html += '</div>'
                    
                    html += '</div>'
            
            if high_count == 0:
                html += '<p>No high priority recommendations found.</p>'
            
            html += '</div>'
            
            # Medium Priority Tab
            html += '<div id="medium-recs" class="tab-content" style="display:none;">'
            medium_count = 0
            
            for rec in recommendations:
                if rec.get('severity', '').upper() == 'MEDIUM':
                    medium_count += 1
                    title = rec.get('title', 'Unknown')
                    category = rec.get('category', 'General')
                    description = rec.get('description', '')
                    steps = rec.get('steps', [])
                    commands = rec.get('commands', [])
                    best_practices = rec.get('best_practices', [])
                    
                    html += '<div class="recommendation medium">'
                    html += f'<h3>{title}</h3>'
                    html += f'<p><strong>Category:</strong> {category} <span class="severity-medium">MEDIUM</span></p>'
                    html += f'<p>{description}</p>'
                    
                    if steps:
                        html += '<div class="steps">'
                        html += '<h4>Implementation Steps:</h4>'
                        html += '<ol>'
                        for step in steps:
                            html += f'<li>{step}</li>'
                        html += '</ol>'
                        html += '</div>'
                    
                    if commands:
                        html += '<div class="commands">'
                        html += '<h4>AWS CLI Commands:</h4>'
                        for command in commands:
                            html += f'<code>{command}</code>'
                        html += '</div>'
                    
                    if best_practices:
                        html += '<div class="best-practices">'
                        html += '<h4>Best Practices:</h4>'
                        html += '<ul>'
                        for practice in best_practices:
                            html += f'<li>{practice}</li>'
                        html += '</ul>'
                        html += '</div>'
                    
                    html += '</div>'
            
            if medium_count == 0:
                html += '<p>No medium priority recommendations found.</p>'
            
            html += '</div>'
            
            # Low Priority Tab
            html += '<div id="low-recs" class="tab-content" style="display:none;">'
            low_count = 0
            
            for rec in recommendations:
                if rec.get('severity', '').upper() == 'LOW':
                    low_count += 1
                    title = rec.get('title', 'Unknown')
                    category = rec.get('category', 'General')
                    description = rec.get('description', '')
                    steps = rec.get('steps', [])
                    commands = rec.get('commands', [])
                    best_practices = rec.get('best_practices', [])
                    
                    html += '<div class="recommendation low">'
                    html += f'<h3>{title}</h3>'
                    html += f'<p><strong>Category:</strong> {category} <span class="severity-low">LOW</span></p>'
                    html += f'<p>{description}</p>'
                    
                    if steps:
                        html += '<div class="steps">'
                        html += '<h4>Implementation Steps:</h4>'
                        html += '<ol>'
                        for step in steps:
                            html += f'<li>{step}</li>'
                        html += '</ol>'
                        html += '</div>'
                    
                    if commands:
                        html += '<div class="commands">'
                        html += '<h4>AWS CLI Commands:</h4>'
                        for command in commands:
                            html += f'<code>{command}</code>'
                        html += '</div>'
                    
                    if best_practices:
                        html += '<div class="best-practices">'
                        html += '<h4>Best Practices:</h4>'
                        html += '<ul>'
                        for practice in best_practices:
                            html += f'<li>{practice}</li>'
                        html += '</ul>'
                        html += '</div>'
                    
                    html += '</div>'
            
            if low_count == 0:
                html += '<p>No low priority recommendations found.</p>'
            
            html += '</div>'
            
            # Add JavaScript for tab switching
            html += '''
            <script>
                // Tab switching for recommendations
                var recTabs = document.querySelectorAll('.tab[data-tab^="all-recs"], .tab[data-tab^="high-recs"], .tab[data-tab^="medium-recs"], .tab[data-tab^="low-recs"]');
                for (var i = 0; i < recTabs.length; i++) {
                    recTabs[i].addEventListener("click", function() {
                        var tabId = this.getAttribute("data-tab");
                        
                        // Hide all tab contents
                        var tabContents = document.querySelectorAll('#all-recs, #high-recs, #medium-recs, #low-recs');
                        for (var j = 0; j < tabContents.length; j++) {
                            tabContents[j].style.display = "none";
                        }
                        
                        // Show the selected tab content
                        document.getElementById(tabId).style.display = "block";
                        
                        // Remove active class from all tabs
                        for (var j = 0; j < recTabs.length; j++) {
                            recTabs[j].classList.remove("active-tab");
                        }
                        
                        // Add active class to the clicked tab
                        this.classList.add("active-tab");
                    });
                }
            </script>
            '''
        else:
            html = '<div class="warning-box"><h4>No AI recommendations available</h4><p>No recommendations were generated for this scan.</p></div>'
    else:
        html = '<div class="warning-box"><h4>No AI recommendations available</h4><p>AI analysis was not performed or no recommendations were generated.</p></div>'
    
    return html
