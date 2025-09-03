import os
import json
import datetime
from typing import Dict, Any, Optional
import jinja2
from src.ai.groq_analyzer import GroqAnalyzer
from src.ai.rule_based_analyzer import RuleBasedAnalyzer

def generate_ai_enhanced_report(
    scan_results: Dict[str, Any],
    output_path: str,
    format: str = "html",
    environment: str = "unknown",
    region: str = "unknown",
    api_key: Optional[str] = None
) -> str:
    """
    Generate an AI-enhanced report from scan results
    
    Args:
        scan_results: Scan results from scanners
        output_path: Path to save the report
        format: Report format (html or pdf)
        environment: Environment name
        region: AWS region
        api_key: OpenAI API key (optional)
        
    Returns:
        Path to the generated report
    """
    # Try to analyze results using Groq AI first
    try:
        analyzer = GroqAnalyzer(api_key)
        analysis = analyzer.analyze_results(scan_results)
        
        # Check if there was an error with the Groq API
        if "error" in analysis:
            print(f"Warning: Groq API error - {analysis.get('error')}. Falling back to rule-based analyzer.")
            # Fall back to rule-based analyzer
            rule_analyzer = RuleBasedAnalyzer()
            analysis = rule_analyzer.analyze_results(scan_results)
    except Exception as e:
        print(f"Error using Groq API: {str(e)}. Falling back to rule-based analyzer.")
        # Fall back to rule-based analyzer
        rule_analyzer = RuleBasedAnalyzer()
        analysis = rule_analyzer.analyze_results(scan_results)
    
    # Add AI analysis to scan results
    scan_results['ai_analysis'] = analysis
    
    # Generate the report
    if format.lower() == "html":
        return generate_html_report(scan_results, output_path, environment, region)
    elif format.lower() == "pdf":
        return generate_pdf_report(scan_results, output_path, environment, region)
    else:
        raise ValueError(f"Unsupported report format: {format}")

def generate_html_report(
    results: Dict[str, Any],
    output_path: str,
    environment: str,
    region: str
) -> str:
    """Generate an HTML report with AI recommendations"""
    # Create Jinja2 environment
    template_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "templates")
    os.makedirs(template_dir, exist_ok=True)
    
    # Create template file if it doesn't exist
    template_path = os.path.join(template_dir, "ai_report_template.html")
    if not os.path.exists(template_path):
        with open(template_path, "w") as f:
            f.write("""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>AWS Infrastructure Scan Report with AI Recommendations</title>
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
        .ai-section {
            margin-bottom: 40px;
            background-color: #f0f7ff;
            border-radius: 5px;
            padding: 25px;
            box-shadow: 0 2px 4px rgba(0, 0, 0, 0.05);
            border-left: 4px solid #0073bb;
        }
        .recommendation {
            background-color: white;
            border-radius: 5px;
            padding: 20px;
            margin-bottom: 20px;
            box-shadow: 0 2px 4px rgba(0, 0, 0, 0.05);
            border-left: 4px solid #5bc0de;
        }
        .recommendation.high {
            border-left: 4px solid #d9534f;
        }
        .recommendation.medium {
            border-left: 4px solid #f0ad4e;
        }
        .recommendation.low {
            border-left: 4px solid #5bc0de;
        }
        .recommendation h3 {
            margin-top: 0;
            color: #333;
        }
        .recommendation-meta {
            display: flex;
            justify-content: space-between;
            margin-bottom: 15px;
        }
        .recommendation-category {
            background-color: #e9ecef;
            padding: 3px 10px;
            border-radius: 15px;
            font-size: 12px;
            font-weight: 600;
        }
        .steps {
            background-color: #f8f9fa;
            padding: 15px;
            border-radius: 5px;
            margin-top: 15px;
        }
        .steps h4 {
            margin-top: 0;
        }
        .steps ol {
            padding-left: 20px;
        }
        .commands {
            background-color: #f0f7ff;
            padding: 15px;
            border-radius: 5px;
            margin-top: 15px;
        }
        .best-practices {
            background-color: #f0fff0;
            padding: 15px;
            border-radius: 5px;
            margin-top: 15px;
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
        .ai-badge {
            background-color: #0073bb;
            color: white;
            padding: 5px 10px;
            border-radius: 15px;
            font-size: 12px;
            font-weight: 600;
            display: inline-block;
            margin-left: 10px;
        }
        .ai-heading {
            display: flex;
            align-items: center;
        }
        .ai-heading h2 {
            margin: 0;
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
        
        <!-- AI-powered Recommendations Section -->
        <div class="ai-section">
            <div class="ai-heading">
                <h2>AI-Powered Recommendations</h2>
                <span class="ai-badge">AI INSIGHTS</span>
            </div>
            <p>Based on the scan results, our AI has generated the following recommendations to improve your infrastructure security and compliance.</p>
            
            {% if 'ai_analysis' in results and 'recommendations' in results.ai_analysis %}
                {% if results.ai_analysis.recommendations %}
                    <div class="tabs">
                        <button class="tab active-tab" data-tab="all-recommendations">All Recommendations</button>
                        <button class="tab" data-tab="high-priority">High Priority</button>
                        <button class="tab" data-tab="medium-priority">Medium Priority</button>
                        <button class="tab" data-tab="low-priority">Low Priority</button>
                    </div>
                    
                    <div id="all-recommendations" class="tab-content">
                        {% for rec in results.ai_analysis.recommendations %}
                            <div class="recommendation {{ rec.severity|lower }}">
                                <div class="recommendation-meta">
                                    <span class="recommendation-category">{{ rec.category }}</span>
                                    <span class="severity-{{ rec.severity|lower }}">{{ rec.severity }}</span>
                                </div>
                                <h3>{{ rec.title }}</h3>
                                <p>{{ rec.description }}</p>
                                
                                {% if rec.steps %}
                                <div class="steps">
                                    <h4>Implementation Steps:</h4>
                                    <ol>
                                        {% for step in rec.steps %}
                                            <li>{{ step }}</li>
                                        {% endfor %}
                                    </ol>
                                </div>
                                {% endif %}
                                
                                {% if rec.commands %}
                                <div class="commands">
                                    <h4>AWS CLI Commands:</h4>
                                    {% for command in rec.commands %}
                                        <code>{{ command }}</code>
                                    {% endfor %}
                                </div>
                                {% endif %}
                                
                                {% if rec.best_practices %}
                                <div class="best-practices">
                                    <h4>Best Practices:</h4>
                                    <ul>
                                        {% for practice in rec.best_practices %}
                                            <li>{{ practice }}</li>
                                        {% endfor %}
                                    </ul>
                                </div>
                                {% endif %}
                            </div>
                        {% endfor %}
                    </div>
                    
                    <div id="high-priority" class="tab-content" style="display:none;">
                        {% set high_count = 0 %}
                        {% for rec in results.ai_analysis.recommendations %}
                            {% if rec.severity == 'HIGH' %}
                                {% set high_count = high_count + 1 %}
                                <div class="recommendation high">
                                    <div class="recommendation-meta">
                                        <span class="recommendation-category">{{ rec.category }}</span>
                                        <span class="severity-high">{{ rec.severity }}</span>
                                    </div>
                                    <h3>{{ rec.title }}</h3>
                                    <p>{{ rec.description }}</p>
                                    
                                    {% if rec.steps %}
                                    <div class="steps">
                                        <h4>Implementation Steps:</h4>
                                        <ol>
                                            {% for step in rec.steps %}
                                                <li>{{ step }}</li>
                                            {% endfor %}
                                        </ol>
                                    </div>
                                    {% endif %}
                                    
                                    {% if rec.commands %}
                                    <div class="commands">
                                        <h4>AWS CLI Commands:</h4>
                                        {% for command in rec.commands %}
                                            <code>{{ command }}</code>
                                        {% endfor %}
                                    </div>
                                    {% endif %}
                                    
                                    {% if rec.best_practices %}
                                    <div class="best-practices">
                                        <h4>Best Practices:</h4>
                                        <ul>
                                            {% for practice in rec.best_practices %}
                                                <li>{{ practice }}</li>
                                            {% endfor %}
                                        </ul>
                                    </div>
                                    {% endif %}
                                </div>
                            {% endif %}
                        {% endfor %}
                        {% if high_count == 0 %}
                            <p>No high priority recommendations found.</p>
                        {% endif %}
                    </div>
                    
                    <div id="medium-priority" class="tab-content" style="display:none;">
                        {% set medium_count = 0 %}
                        {% for rec in results.ai_analysis.recommendations %}
                            {% if rec.severity == 'MEDIUM' %}
                                {% set medium_count = medium_count + 1 %}
                                <div class="recommendation medium">
                                    <div class="recommendation-meta">
                                        <span class="recommendation-category">{{ rec.category }}</span>
                                        <span class="severity-medium">{{ rec.severity }}</span>
                                    </div>
                                    <h3>{{ rec.title }}</h3>
                                    <p>{{ rec.description }}</p>
                                    
                                    {% if rec.steps %}
                                    <div class="steps">
                                        <h4>Implementation Steps:</h4>
                                        <ol>
                                            {% for step in rec.steps %}
                                                <li>{{ step }}</li>
                                            {% endfor %}
                                        </ol>
                                    </div>
                                    {% endif %}
                                    
                                    {% if rec.commands %}
                                    <div class="commands">
                                        <h4>AWS CLI Commands:</h4>
                                        {% for command in rec.commands %}
                                            <code>{{ command }}</code>
                                        {% endfor %}
                                    </div>
                                    {% endif %}
                                    
                                    {% if rec.best_practices %}
                                    <div class="best-practices">
                                        <h4>Best Practices:</h4>
                                        <ul>
                                            {% for practice in rec.best_practices %}
                                                <li>{{ practice }}</li>
                                            {% endfor %}
                                        </ul>
                                    </div>
                                    {% endif %}
                                </div>
                            {% endif %}
                        {% endfor %}
                        {% if medium_count == 0 %}
                            <p>No medium priority recommendations found.</p>
                        {% endif %}
                    </div>
                    
                    <div id="low-priority" class="tab-content" style="display:none;">
                        {% set low_count = 0 %}
                        {% for rec in results.ai_analysis.recommendations %}
                            {% if rec.severity == 'LOW' %}
                                {% set low_count = low_count + 1 %}
                                <div class="recommendation low">
                                    <div class="recommendation-meta">
                                        <span class="recommendation-category">{{ rec.category }}</span>
                                        <span class="severity-low">{{ rec.severity }}</span>
                                    </div>
                                    <h3>{{ rec.title }}</h3>
                                    <p>{{ rec.description }}</p>
                                    
                                    {% if rec.steps %}
                                    <div class="steps">
                                        <h4>Implementation Steps:</h4>
                                        <ol>
                                            {% for step in rec.steps %}
                                                <li>{{ step }}</li>
                                            {% endfor %}
                                        </ol>
                                    </div>
                                    {% endif %}
                                    
                                    {% if rec.commands %}
                                    <div class="commands">
                                        <h4>AWS CLI Commands:</h4>
                                        {% for command in rec.commands %}
                                            <code>{{ command }}</code>
                                        {% endfor %}
                                    </div>
                                    {% endif %}
                                    
                                    {% if rec.best_practices %}
                                    <div class="best-practices">
                                        <h4>Best Practices:</h4>
                                        <ul>
                                            {% for practice in rec.best_practices %}
                                                <li>{{ practice }}</li>
                                            {% endfor %}
                                        </ul>
                                    </div>
                                    {% endif %}
                                </div>
                            {% endif %}
                        {% endfor %}
                        {% if low_count == 0 %}
                            <p>No low priority recommendations found.</p>
                        {% endif %}
                    </div>
                {% else %}
                    <div class="alert alert-warning">
                        <h4>No AI recommendations available</h4>
                        <p>{{ results.ai_analysis.error }}</p>
                    </div>
                {% endif %}
            {% else %}
                <div class="alert alert-warning">
                    <h4>No AI recommendations available</h4>
                    <p>AI analysis was not performed or no recommendations were generated.</p>
                </div>
            {% endif %}
        </div>
        
        <!-- Include the rest of your regular report sections here -->
        
        <div class="footer">
            <p>Report generated on {{ timestamp }}</p>
            <p>EKS Infrastructure Scanner with AI Recommendations</p>
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
    template = env.get_template("ai_report_template.html")
    
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
    region: str
) -> str:
    """Generate a PDF report with AI recommendations"""
    # First generate HTML report
    html_path = output_path.replace('.pdf', '.html')
    generate_html_report(results, html_path, environment, region)
    
    # Convert HTML to PDF using WeasyPrint
    import weasyprint
    html = weasyprint.HTML(filename=html_path)
    html.write_pdf(output_path)
    
    # Remove temporary HTML file
    os.remove(html_path)
    
    return output_path
