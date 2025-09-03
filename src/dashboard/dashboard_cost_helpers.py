"""
Helper methods for creating cost optimization section in the dashboard.
"""
from typing import Dict, Any

def create_cost_optimization_summary_html(scan_results: Dict[str, Any]) -> str:
    """
    Create HTML for the cost optimization summary section.
    
    Args:
        scan_results: The scan results from various scanners
        
    Returns:
        HTML string for the cost optimization summary section
    """
    if 'cost' not in scan_results:
        return "<p>No cost optimization data available.</p>"
    
    cost_results = scan_results['cost'].get('results', {})
    
    html = """
    <div class="cost-optimization-summary">
        <h3>Cost Optimization Overview</h3>
    """
    
    # Add cost metrics summary
    total_current_cost = cost_results.get("total_current_cost", 0)
    total_potential_savings = cost_results.get("total_potential_savings", 0)
    avg_savings_percentage = cost_results.get("avg_savings_percentage", 0)
    
    html += f"""
        <div class="cost-savings-summary">
            <div class="savings-metrics">
                <div class="metric">
                    <span class="metric-value">${total_current_cost:.2f}</span>
                    <span class="metric-label">Current Monthly Cost</span>
                </div>
                <div class="metric highlight">
                    <span class="metric-value">${total_potential_savings:.2f}</span>
                    <span class="metric-label">Potential Monthly Savings</span>
                </div>
                <div class="metric">
                    <span class="metric-value">{avg_savings_percentage}%</span>
                    <span class="metric-label">Average Savings</span>
                </div>
            </div>
        </div>
    """
    
    # Cost by service
    cost_by_service = cost_results.get('cost_by_service', [])
    if cost_by_service:
        html += """
        <h4>Cost Distribution by Service</h4>
        <table class="cost-table">
            <tr>
                <th>Service</th>
                <th>Monthly Cost ($)</th>
                <th>Percentage of Total</th>
            </tr>
        """
        
        # Calculate total cost for percentage
        total_cost = sum(item.get('amount', 0) for item in cost_by_service)
        
        for item in cost_by_service:
            service = item.get('service', 'Unknown')
            amount = item.get('amount', 0)
            percentage = (amount / total_cost * 100) if total_cost > 0 else 0
            
            html += f"""
            <tr>
                <td>{service}</td>
                <td>${amount:.2f}</td>
                <td>{percentage:.1f}%</td>
            </tr>
            """
        
        html += """
        </table>
        """
    
    # Cost by region
    cost_by_region = cost_results.get('cost_by_region', [])
    if cost_by_region:
        html += """
        <h4>Cost Distribution by Region</h4>
        <table class="cost-table">
            <tr>
                <th>Region</th>
                <th>Monthly Cost ($)</th>
                <th>Percentage of Total</th>
            </tr>
        """
        
        # Calculate total cost for percentage
        total_cost = sum(item.get('amount', 0) for item in cost_by_region)
        
        for item in cost_by_region:
            region = item.get('region', 'Unknown')
            amount = item.get('amount', 0)
            percentage = (amount / total_cost * 100) if total_cost > 0 else 0
            
            html += f"""
            <tr>
                <td>{region}</td>
                <td>${amount:.2f}</td>
                <td>{percentage:.1f}%</td>
            </tr>
            """
        
        html += """
        </table>
        """
    
    html += """
    </div>
    """
    
    return html

def create_cost_optimization_details_html(scan_results: Dict[str, Any]) -> str:
    """
    Create HTML for the cost optimization details section.
    
    Args:
        scan_results: The scan results from various scanners
        
    Returns:
        HTML string for the cost optimization details section
    """
    if 'cost' not in scan_results:
        return "<p>No cost optimization data available.</p>"
    
    cost_results = scan_results['cost'].get('results', {})
    savings_recommendations = cost_results.get('savings_recommendations', [])
    
    if not savings_recommendations:
        return "<p>No cost optimization recommendations available.</p>"
    
    html = """
    <div class="cost-optimization-details">
        <h3>Cost Optimization Recommendations</h3>
        <p>The following recommendations can help you optimize your AWS infrastructure costs:</p>
        
        <table class="cost-recommendations">
            <tr>
                <th>Service</th>
                <th>Resource Type</th>
                <th>Resource ID</th>
                <th>Current Cost</th>
                <th>Potential Savings</th>
                <th>Savings %</th>
                <th>Recommendation</th>
                <th>Effort</th>
            </tr>
    """
    
    for rec in savings_recommendations:
        service = rec.get('service', 'Unknown')
        resource_type = rec.get('resource_type', 'Unknown')
        resource_id = rec.get('resource_id', 'Unknown')
        current_cost = rec.get('current_cost', 0)
        potential_savings = rec.get('potential_savings', 0)
        savings_percentage = rec.get('savings_percentage', 0)
        recommendation = rec.get('recommendation', 'Unknown')
        implementation_effort = rec.get('implementation_effort', 'Medium')
        
        # Format the effort level with appropriate styling
        effort_class = implementation_effort.lower() if implementation_effort in ['Low', 'Medium', 'High'] else ''
        effort_html = f'<span class="effort-{effort_class}">{implementation_effort}</span>'
        
        html += f"""
        <tr>
            <td>{service}</td>
            <td>{resource_type}</td>
            <td>{resource_id}</td>
            <td>${current_cost:.2f}</td>
            <td class="savings">${potential_savings:.2f}</td>
            <td>{savings_percentage}%</td>
            <td>{recommendation}</td>
            <td>{effort_html}</td>
        </tr>
        """
    
    html += """
        </table>
        
        <div class="implementation-details">
            <h4>Implementation Details</h4>
    """
    
    for i, rec in enumerate(savings_recommendations):
        implementation_steps = rec.get('implementation_steps', [])
        aws_cli_command = rec.get('aws_cli_command', '')
        
        if implementation_steps or aws_cli_command:
            resource_id = rec.get('resource_id', 'Unknown')
            recommendation_type = rec.get('recommendation_type', 'Unknown')
            
            html += f"""
            <div class="implementation-card">
                <h5>{i+1}. {recommendation_type} - {resource_id}</h5>
            """
            
            if implementation_steps:
                html += """
                <div class="steps">
                    <h6>Implementation Steps:</h6>
                    <ol>
                """
                for step in implementation_steps:
                    html += f"<li>{step}</li>"
                html += """
                    </ol>
                </div>
                """
            
            if aws_cli_command:
                html += f"""
                <div class="cli-command">
                    <h6>AWS CLI Command:</h6>
                    <code>{aws_cli_command}</code>
                </div>
                """
            
            html += """
            </div>
            """
    
    html += """
        </div>
    </div>
    """
    
    return html
