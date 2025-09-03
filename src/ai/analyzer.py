import os
import json
import logging
import requests
from typing import Dict, Any, List, Optional

class AIAnalyzer:
    """
    AI-powered analyzer for infrastructure scan results.
    Uses OpenAI API to generate insights and recommendations.
    """
    
    def __init__(self, api_key: Optional[str] = None):
        """
        Initialize the AI analyzer.
        
        Args:
            api_key: OpenAI API key. If not provided, will try to get from environment variable.
        """
        self.api_key = api_key or os.environ.get("OPENAI_API_KEY")
        if not self.api_key:
            logging.warning("No OpenAI API key provided. AI analysis will be disabled.")
        
        self.logger = logging.getLogger(self.__class__.__name__)
    
    def analyze_results(self, scan_results: Dict[str, Any]) -> Dict[str, Any]:
        """
        Analyze scan results and generate recommendations.
        
        Args:
            scan_results: The scan results from various scanners
            
        Returns:
            Dictionary with analysis results and recommendations
        """
        if not self.api_key:
            return {
                "error": "No OpenAI API key provided. Set OPENAI_API_KEY environment variable.",
                "recommendations": []
            }
        
        try:
            # Extract key findings from scan results
            findings = self._extract_findings(scan_results)
            
            # Generate recommendations using OpenAI API
            recommendations = self._generate_recommendations(findings)
            
            return {
                "findings": findings,
                "recommendations": recommendations
            }
        except Exception as e:
            self.logger.error(f"Error analyzing results: {str(e)}")
            return {
                "error": str(e),
                "recommendations": []
            }
    
    def _extract_findings(self, scan_results: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Extract key findings from scan results.
        
        Args:
            scan_results: The scan results from various scanners
            
        Returns:
            List of findings
        """
        findings = []
        
        # Extract EKS findings
        if 'eks' in scan_results:
            eks_results = scan_results['eks'].get('results', {})
            
            # Check for deprecated clusters
            deprecated_count = eks_results.get('deprecated_count', 0)
            if deprecated_count > 0:
                findings.append({
                    "category": "EKS",
                    "severity": "HIGH",
                    "finding": f"{deprecated_count} EKS clusters are running deprecated versions",
                    "details": "Deprecated Kubernetes versions may have security vulnerabilities and lack support"
                })
            
            # Check for problematic pods
            for cluster in eks_results.get('clusters', []):
                k8s_resources = cluster.get('kubernetes_resources', {})
                problematic_pods = k8s_resources.get('problematic_pods', [])
                
                if problematic_pods:
                    findings.append({
                        "category": "EKS",
                        "severity": "MEDIUM",
                        "finding": f"{len(problematic_pods)} problematic pods found in cluster {cluster.get('name')}",
                        "details": "Pods in CrashLoopBackOff or Pending state may indicate resource issues or configuration problems"
                    })
                
                # Check for unused PVCs
                unused_pvcs = k8s_resources.get('unused_pvcs', [])
                if unused_pvcs:
                    findings.append({
                        "category": "EKS",
                        "severity": "LOW",
                        "finding": f"{len(unused_pvcs)} unused Persistent Volume Claims found",
                        "details": "Unused PVCs may incur unnecessary costs"
                    })
        
        # Extract EC2 findings
        if 'ec2' in scan_results:
            ec2_results = scan_results['ec2'].get('results', {})
            
            # Check for instances with public IPs
            public_ip_count = ec2_results.get('public_ip_count', 0)
            if public_ip_count > 0:
                findings.append({
                    "category": "EC2",
                    "severity": "HIGH",
                    "finding": f"{public_ip_count} EC2 instances have public IP addresses",
                    "details": "Instances with public IPs are directly accessible from the internet and may be vulnerable to attacks"
                })
            
            # Check for open security groups
            open_sg_count = ec2_results.get('open_security_group_count', 0)
            if open_sg_count > 0:
                findings.append({
                    "category": "Security Groups",
                    "severity": "HIGH",
                    "finding": f"{open_sg_count} security groups have potentially risky open ports",
                    "details": "Security groups with open ports (0.0.0.0/0) can expose your infrastructure to unauthorized access"
                })
                
                # Analyze specific open ports
                high_risk_ports = set()
                medium_risk_ports = set()
                
                for sg in ec2_results.get('open_security_groups', []):
                    for port in sg.get('OpenPorts', []):
                        if port in [22, 3389, 3306, 5432]:
                            high_risk_ports.add(port)
                        else:
                            medium_risk_ports.add(port)
                
                if high_risk_ports:
                    findings.append({
                        "category": "Security Groups",
                        "severity": "HIGH",
                        "finding": f"High-risk ports open to the world: {', '.join(map(str, high_risk_ports))}",
                        "details": "These ports (SSH, RDP, database) should never be exposed to the internet"
                    })
            
            # Check for orphaned instances
            orphaned_count = ec2_results.get('orphaned_instance_count', 0)
            if orphaned_count > 0:
                findings.append({
                    "category": "EC2",
                    "severity": "MEDIUM",
                    "finding": f"{orphaned_count} orphaned EC2 instances found",
                    "details": "Instances not managed by Auto Scaling Groups or EKS may indicate forgotten resources"
                })
        
        # Extract VPC findings
        if 'vpc' in scan_results:
            vpc_results = scan_results['vpc'].get('results', {})
            
            # Additional VPC findings could be added here
        
        # Extract DynamoDB findings
        if 'dynamodb' in scan_results:
            dynamodb_results = scan_results['dynamodb'].get('results', {})
            
            # Check for low usage tables
            low_usage_count = dynamodb_results.get('low_usage_table_count', 0)
            if low_usage_count > 0:
                findings.append({
                    "category": "DynamoDB",
                    "severity": "LOW",
                    "finding": f"{low_usage_count} DynamoDB tables with low usage detected",
                    "details": "Low usage tables may indicate unnecessary costs"
                })
        
        # Extract IAM findings
        if 'iam' in scan_results:
            iam_results = scan_results['iam'].get('results', {})
            
            # Check for users with old access keys
            users_with_old_keys_count = iam_results.get('users_with_old_keys_count', 0)
            if users_with_old_keys_count > 0:
                findings.append({
                    "category": "IAM",
                    "severity": "HIGH",
                    "finding": f"{users_with_old_keys_count} IAM users have access keys older than 90 days",
                    "details": "Old access keys pose a security risk and should be rotated regularly"
                })
            
            # Check for permissive roles
            permissive_role_count = iam_results.get('permissive_role_count', 0)
            if permissive_role_count > 0:
                findings.append({
                    "category": "IAM",
                    "severity": "HIGH",
                    "finding": f"{permissive_role_count} IAM roles have overly permissive policies",
                    "details": "Overly permissive policies violate the principle of least privilege"
                })
        
        return findings
    
    def _generate_recommendations(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Generate recommendations based on findings using OpenAI API.
        
        Args:
            findings: List of findings from scan results
            
        Returns:
            List of recommendations
        """
        if not findings:
            return []
        
        # Format findings for the API request
        findings_text = json.dumps(findings, indent=2)
        
        # Prepare the prompt for OpenAI
        prompt = f"""
        You are a cloud security expert tasked with analyzing AWS infrastructure scan results.
        Based on the following findings, provide specific, actionable recommendations to address each issue.
        For each recommendation, include:
        1. A clear title
        2. Detailed steps to implement the fix
        3. AWS CLI commands or code snippets where applicable
        4. Best practices and additional considerations
        
        Findings:
        {findings_text}
        
        Format your response as a JSON array of recommendation objects, each with:
        - "title": A concise title for the recommendation
        - "category": The category (same as the finding category)
        - "severity": The severity level (HIGH, MEDIUM, LOW)
        - "description": A detailed explanation of the issue
        - "steps": An array of specific steps to take
        - "commands": An array of AWS CLI commands or code snippets
        - "best_practices": Additional best practices to consider
        """
        
        try:
            # Call OpenAI API
            response = self._call_openai_api(prompt)
            
            # Parse the response
            try:
                recommendations = json.loads(response)
                return recommendations
            except json.JSONDecodeError:
                # If the response is not valid JSON, try to extract JSON from the text
                import re
                json_match = re.search(r'(\[\s*{.*}\s*\])', response, re.DOTALL)
                if json_match:
                    try:
                        recommendations = json.loads(json_match.group(1))
                        return recommendations
                    except json.JSONDecodeError:
                        pass
                
                # If we still can't parse the JSON, return a formatted error
                self.logger.error(f"Failed to parse OpenAI response as JSON: {response}")
                return [{
                    "title": "Error generating recommendations",
                    "category": "System",
                    "severity": "HIGH",
                    "description": "The AI system was unable to generate properly formatted recommendations.",
                    "steps": ["Contact support for assistance."],
                    "commands": [],
                    "best_practices": ["Ensure the OpenAI API key is valid."]
                }]
        except Exception as e:
            self.logger.error(f"Error calling OpenAI API: {str(e)}")
            return [{
                "title": "Error generating recommendations",
                "category": "System",
                "severity": "HIGH",
                "description": f"Error: {str(e)}",
                "steps": ["Check your internet connection.", "Verify your OpenAI API key."],
                "commands": [],
                "best_practices": ["Ensure the OpenAI API key is valid."]
            }]
    
    def _call_openai_api(self, prompt: str) -> str:
        """
        Call OpenAI API to generate text.
        
        Args:
            prompt: The prompt to send to the API
            
        Returns:
            Generated text from the API
        """
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json"
        }
        
        data = {
            "model": "gpt-3.5-turbo",
            "messages": [
                {"role": "system", "content": "You are a cloud security expert specializing in AWS infrastructure."},
                {"role": "user", "content": prompt}
            ],
            "temperature": 0.7,
            "max_tokens": 2000
        }
        
        response = requests.post(
            "https://api.openai.com/v1/chat/completions",
            headers=headers,
            json=data
        )
        
        if response.status_code != 200:
            raise Exception(f"OpenAI API error: {response.status_code} - {response.text}")
        
        return response.json()["choices"][0]["message"]["content"]

# For local testing
if __name__ == "__main__":
    import sys
    
    if len(sys.argv) != 2:
        print("Usage: python analyzer.py <scan_results_json_file>")
        sys.exit(1)
    
    with open(sys.argv[1], 'r') as f:
        scan_results = json.load(f)
    
    analyzer = AIAnalyzer()
    analysis = analyzer.analyze_results(scan_results)
    
    print(json.dumps(analysis, indent=2))
