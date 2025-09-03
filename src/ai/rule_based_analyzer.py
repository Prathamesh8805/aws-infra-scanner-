import logging
from typing import Dict, Any, List

class RuleBasedAnalyzer:
    """
    Rule-based analyzer for infrastructure scan results.
    Provides recommendations based on predefined rules without requiring an external API.
    """
    
    def __init__(self):
        """
        Initialize the rule-based analyzer.
        """
        self.logger = logging.getLogger(self.__class__.__name__)
        
    def _fix_vertical_text(self, text: str) -> str:
        """
        Fix vertical text by joining characters properly.
        
        Args:
            text: The text to fix
            
        Returns:
            Fixed text
        """
        if not text:
            return ""
            
        # Check if the text has characters separated by newlines
        if '\n' in text and len(text.replace('\n', '')) > len(text) * 0.8:
            # Join all characters without newlines
            return ''.join(text.split())
        
        # If the text has spaces between each character
        if ' ' in text and all(c == ' ' or len(c) == 1 for c in text.split(' ')):
            return ''.join(text.split())
            
        return text
    
    def analyze_results(self, scan_results: Dict[str, Any]) -> Dict[str, Any]:
        """
        Analyze scan results and generate recommendations based on predefined rules.
        
        Args:
            scan_results: The scan results from various scanners
            
        Returns:
            Dictionary with analysis results and recommendations
        """
        try:
            # Extract key findings from scan results
            findings = self._extract_findings(scan_results)
            
            # Generate recommendations based on findings
            recommendations = self._generate_recommendations(findings)
            
            # Fix any formatting issues in the recommendations
            for rec in recommendations:
                if "best_practices" in rec and isinstance(rec["best_practices"], list):
                    rec["best_practices"] = [self._fix_vertical_text(practice) for practice in rec["best_practices"]]
                
                if "steps" in rec and isinstance(rec["steps"], list):
                    rec["steps"] = [self._fix_vertical_text(step) for step in rec["steps"]]
                
                if "commands" in rec and isinstance(rec["commands"], list):
                    rec["commands"] = [self._fix_vertical_text(command) for command in rec["commands"]]
                
                if "description" in rec:
                    rec["description"] = self._fix_vertical_text(rec["description"])
            
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
            
            # Check for orphaned instances
            orphaned_count = ec2_results.get('orphaned_instance_count', 0)
            if orphaned_count > 0:
                findings.append({
                    "category": "EC2",
                    "severity": "MEDIUM",
                    "finding": f"{orphaned_count} orphaned EC2 instances found",
                    "details": "Instances not managed by Auto Scaling Groups or EKS may indicate forgotten resources"
                })
        
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
        Generate recommendations based on findings using predefined rules.
        
        Args:
            findings: List of findings from scan results
            
        Returns:
            List of recommendations
        """
        recommendations = []
        
        # Process EKS findings
        eks_findings = [f for f in findings if f["category"] == "EKS"]
        if any(f for f in eks_findings if "deprecated versions" in f["finding"]):
            recommendations.append({
                "title": "Upgrade Deprecated EKS Clusters",
                "category": "EKS",
                "severity": "HIGH",
                "description": "Running deprecated Kubernetes versions exposes your clusters to security vulnerabilities and lack of support from AWS.",
                "steps": [
                    "Identify all clusters running deprecated versions",
                    "Plan a migration strategy to upgrade each cluster",
                    "Test applications on the new version in a staging environment",
                    "Schedule a maintenance window for the upgrade",
                    "Perform the upgrade using AWS Management Console or CLI",
                    "Verify all applications are functioning correctly after upgrade"
                ],
                "commands": [
                    "# Check current EKS version",
                    "aws eks describe-cluster --name your-cluster-name --query 'cluster.version'",
                    "",
                    "# Update EKS cluster version",
                    "aws eks update-cluster-version --name your-cluster-name --kubernetes-version 1.28"
                ],
                "best_practices": [
                    "Keep EKS clusters within one or two versions of the latest release",
                    "Subscribe to AWS release notifications for EKS",
                    "Test upgrades in a non-production environment first",
                    "Schedule regular version reviews every quarter"
                ]
            })
        
        if any(f for f in eks_findings if "problematic pods" in f["finding"]):
            recommendations.append({
                "title": "Resolve Problematic Kubernetes Pods",
                "category": "EKS",
                "severity": "MEDIUM",
                "description": "Pods in CrashLoopBackOff or Pending state indicate configuration issues, resource constraints, or application errors.",
                "steps": [
                    "Identify the problematic pods and their namespaces",
                    "Check pod events and logs for error messages",
                    "For CrashLoopBackOff: Review application logs and fix application errors",
                    "For Pending pods: Check if there are sufficient resources in the cluster",
                    "Verify node health and cluster capacity"
                ],
                "commands": [
                    "# Get pod details and events",
                    "kubectl describe pod <pod-name> -n <namespace>",
                    "",
                    "# Check pod logs",
                    "kubectl logs <pod-name> -n <namespace>",
                    "",
                    "# Check node capacity",
                    "kubectl get nodes -o wide"
                ],
                "best_practices": [
                    "Implement proper resource requests and limits for all pods",
                    "Set up monitoring and alerting for pod failures",
                    "Use horizontal pod autoscaling for applications with variable load",
                    "Implement liveness and readiness probes for all deployments"
                ]
            })
        
        if any(f for f in eks_findings if "unused Persistent Volume Claims" in f["finding"]):
            recommendations.append({
                "title": "Clean Up Unused PVCs",
                "category": "EKS",
                "severity": "LOW",
                "description": "Unused Persistent Volume Claims consume storage resources and incur unnecessary costs.",
                "steps": [
                    "Identify all unused PVCs across all namespaces",
                    "Verify that these PVCs are truly not needed",
                    "Back up any data if necessary",
                    "Delete the unused PVCs"
                ],
                "commands": [
                    "# List all PVCs",
                    "kubectl get pvc --all-namespaces",
                    "",
                    "# Delete an unused PVC",
                    "kubectl delete pvc <pvc-name> -n <namespace>"
                ],
                "best_practices": [
                    "Implement a regular cleanup process for unused resources",
                    "Use StorageClass reclaim policies appropriately",
                    "Consider using dynamic provisioning with appropriate retention policies",
                    "Tag PVCs with owner information and expiration dates"
                ]
            })
        
        # Process EC2 findings
        ec2_findings = [f for f in findings if f["category"] == "EC2"]
        if any(f for f in ec2_findings if "public IP addresses" in f["finding"]):
            recommendations.append({
                "title": "Secure EC2 Instances with Public IPs",
                "category": "EC2",
                "severity": "HIGH",
                "description": "EC2 instances with public IP addresses are directly accessible from the internet, increasing the attack surface of your infrastructure.",
                "steps": [
                    "Identify all instances with public IPs",
                    "Evaluate if these instances truly need direct internet access",
                    "For instances that don't need public access: Move to private subnets and use NAT gateway for outbound traffic",
                    "For instances that need public access: Implement strict security groups and network ACLs",
                    "Consider using a load balancer or bastion host pattern instead of direct public access"
                ],
                "commands": [
                    "# Find instances with public IPs",
                    "aws ec2 describe-instances --filters \"Name=ip-address,Values=*\" --query 'Reservations[*].Instances[*].[InstanceId,PublicIpAddress,Tags[?Key==`Name`].Value]' --output table",
                    "",
                    "# Disassociate Elastic IP",
                    "aws ec2 disassociate-address --association-id <association-id>"
                ],
                "best_practices": [
                    "Use private subnets for most workloads",
                    "Implement a bastion host or VPN for administrative access",
                    "Use load balancers for public-facing applications",
                    "Regularly audit and justify all public IP assignments"
                ]
            })
        
        # Process Security Group findings
        sg_findings = [f for f in findings if f["category"] == "Security Groups"]
        if any(f for f in sg_findings if "risky open ports" in f["finding"]):
            recommendations.append({
                "title": "Restrict Open Security Groups",
                "category": "Security Groups",
                "severity": "HIGH",
                "description": "Security groups with open ports (0.0.0.0/0) allow access from any IP address, potentially exposing your resources to unauthorized access and attacks.",
                "steps": [
                    "Identify all security groups with open ports (0.0.0.0/0)",
                    "Prioritize high-risk ports (SSH, RDP, database ports)",
                    "Replace 0.0.0.0/0 with specific IP ranges that need access",
                    "For SSH/RDP access, consider implementing a bastion host",
                    "For web applications, consider using a WAF in front of your resources"
                ],
                "commands": [
                    "# Identify security groups with open ports",
                    "aws ec2 describe-security-groups --filters \"Name=ip-permission.cidr,Values=0.0.0.0/0\" --query 'SecurityGroups[*].[GroupId,GroupName,IpPermissions[?IpRanges[?CidrIp==`0.0.0.0/0`]]]'",
                    "",
                    "# Revoke open SSH access",
                    "aws ec2 revoke-security-group-ingress --group-id <sg-id> --protocol tcp --port 22 --cidr 0.0.0.0/0",
                    "",
                    "# Add restricted SSH access",
                    "aws ec2 authorize-security-group-ingress --group-id <sg-id> --protocol tcp --port 22 --cidr <your-ip>/32"
                ],
                "best_practices": [
                    "Never allow 0.0.0.0/0 for administrative ports (SSH, RDP)",
                    "Use security group references instead of CIDR ranges for internal traffic",
                    "Implement the principle of least privilege for all security groups",
                    "Regularly audit security groups for overly permissive rules",
                    "Consider using AWS Config rules to detect and alert on open security groups"
                ]
            })
        
        # Process IAM findings
        iam_findings = [f for f in findings if f["category"] == "IAM"]
        if any(f for f in iam_findings if "access keys older than 90 days" in f["finding"]):
            recommendations.append({
                "title": "Rotate Old IAM Access Keys",
                "category": "IAM",
                "severity": "HIGH",
                "description": "IAM access keys older than 90 days pose a security risk due to potential compromise over time.",
                "steps": [
                    "Identify all users with old access keys",
                    "Create new access keys for each user",
                    "Update applications and scripts to use the new keys",
                    "Verify everything works with the new keys",
                    "Disable (don't delete) the old keys for a grace period",
                    "Delete the old keys after confirming no issues"
                ],
                "commands": [
                    "# List access keys and creation date",
                    "aws iam list-access-keys --user-name <username> --query 'AccessKeyMetadata[*].[AccessKeyId,CreateDate,Status]'",
                    "",
                    "# Create new access key",
                    "aws iam create-access-key --user-name <username>",
                    "",
                    "# Deactivate old access key",
                    "aws iam update-access-key --access-key-id <old-key-id> --status Inactive --user-name <username>",
                    "",
                    "# Delete old access key",
                    "aws iam delete-access-key --access-key-id <old-key-id> --user-name <username>"
                ],
                "best_practices": [
                    "Implement a key rotation policy (90 days is recommended)",
                    "Use AWS IAM Roles instead of long-term access keys when possible",
                    "Consider using AWS Secrets Manager for application credentials",
                    "Set up CloudWatch Events to alert on old access keys",
                    "Use AWS Config to monitor compliance with key rotation policies"
                ]
            })
        
        if any(f for f in iam_findings if "overly permissive policies" in f["finding"]):
            recommendations.append({
                "title": "Restrict Overly Permissive IAM Policies",
                "category": "IAM",
                "severity": "HIGH",
                "description": "Overly permissive IAM policies violate the principle of least privilege and increase the potential impact of credential compromise.",
                "steps": [
                    "Identify roles and policies with overly permissive statements (e.g., \"*\" actions)",
                    "Generate IAM Access Advisor reports to see which permissions are actually used",
                    "Rewrite policies to include only the specific actions needed",
                    "Test the restricted policies in a non-production environment",
                    "Implement the updated policies"
                ],
                "commands": [
                    "# List roles with attached policies",
                    "aws iam list-roles --query 'Roles[*].[RoleName,AssumeRolePolicyDocument]'",
                    "",
                    "# Get policy details",
                    "aws iam get-policy --policy-arn <policy-arn>",
                    "",
                    "# Get policy version details",
                    "aws iam get-policy-version --policy-arn <policy-arn> --version-id <version-id>"
                ],
                "best_practices": [
                    "Follow the principle of least privilege",
                    "Avoid using \"*\" in Action or Resource elements",
                    "Use IAM Access Analyzer to identify unused permissions",
                    "Regularly review and prune permissions",
                    "Consider using AWS managed policies as a starting point, then restrict further"
                ]
            })
        
        # Process DynamoDB findings
        dynamodb_findings = [f for f in findings if f["category"] == "DynamoDB"]
        if any(f for f in dynamodb_findings if "low usage" in f["finding"]):
            recommendations.append({
                "title": "Optimize Low-Usage DynamoDB Tables",
                "category": "DynamoDB",
                "severity": "LOW",
                "description": "DynamoDB tables with low usage may be incurring unnecessary costs, especially if they are using provisioned capacity mode.",
                "steps": [
                    "Identify tables with consistently low usage",
                    "For infrequently accessed tables, switch to on-demand capacity mode",
                    "For tables that are no longer needed, consider archiving data and deleting the table",
                    "For tables with predictable but low traffic, consider reducing provisioned capacity"
                ],
                "commands": [
                    "# Describe table to check capacity mode",
                    "aws dynamodb describe-table --table-name <table-name> --query 'Table.BillingModeSummary'",
                    "",
                    "# Switch to on-demand capacity",
                    "aws dynamodb update-table --table-name <table-name> --billing-mode PAY_PER_REQUEST",
                    "",
                    "# Update provisioned capacity",
                    "aws dynamodb update-table --table-name <table-name> --provisioned-throughput ReadCapacityUnits=1,WriteCapacityUnits=1"
                ],
                "best_practices": [
                    "Use on-demand capacity for unpredictable or very low workloads",
                    "Use auto-scaling for provisioned capacity tables",
                    "Implement a regular review process for table usage",
                    "Consider Time-to-Live (TTL) for data that has a limited useful life",
                    "Use DynamoDB Accelerator (DAX) for frequently accessed tables with read-heavy workloads"
                ]
            })
        
        return recommendations

# For local testing
if __name__ == "__main__":
    import sys
    import json
    
    if len(sys.argv) != 2:
        print("Usage: python rule_based_analyzer.py <scan_results_json_file>")
        sys.exit(1)
    
    with open(sys.argv[1], 'r') as f:
        scan_results = json.load(f)
    
    analyzer = RuleBasedAnalyzer()
    analysis = analyzer.analyze_results(scan_results)
    
    print(json.dumps(analysis, indent=2))
