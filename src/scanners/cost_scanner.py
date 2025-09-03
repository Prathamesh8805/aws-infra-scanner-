from typing import Dict, Any, List
from datetime import datetime, timedelta
from .base_scanner import BaseScanner

class CostScanner(BaseScanner):
    """Scanner for AWS cost optimization opportunities"""
    
    def scan(self) -> Dict[str, Any]:
        """Scan for cost optimization opportunities using AWS Cost Explorer"""
        ce_client = self.get_boto3_client('ce')
        
        try:
            # Get cost data for the last 30 days
            end_date = datetime.now().strftime('%Y-%m-%d')
            start_date = (datetime.now() - timedelta(days=30)).strftime('%Y-%m-%d')
            
            # Get cost by service
            cost_by_service = self._get_cost_by_service(ce_client, start_date, end_date)
            
            # Get cost by region
            cost_by_region = self._get_cost_by_region(ce_client, start_date, end_date)
            
            # Get cost by tag
            cost_by_tag = self._get_cost_by_tag(ce_client, start_date, end_date)
            
            # Get cost anomalies
            cost_anomalies = self._get_cost_anomalies(ce_client, start_date, end_date)
            
            # Get savings recommendations
            savings_recommendations = self._get_savings_recommendations(ce_client)
            
            # Calculate total potential savings and current costs
            total_potential_savings = sum(rec.get('potential_savings', 0) for rec in savings_recommendations)
            total_current_cost = sum(rec.get('current_cost', 0) for rec in savings_recommendations)
            
            # Calculate average savings percentage
            avg_savings_percentage = 0
            if total_current_cost > 0:
                avg_savings_percentage = round((total_potential_savings / total_current_cost) * 100)
            
            return self.format_results({
                "period": {
                    "start_date": start_date,
                    "end_date": end_date
                },
                "cost_by_service": cost_by_service,
                "cost_by_region": cost_by_region,
                "cost_by_tag": cost_by_tag,
                "cost_anomalies": cost_anomalies,
                "savings_recommendations": savings_recommendations,
                "total_potential_savings": total_potential_savings,
                "total_current_cost": total_current_cost,
                "avg_savings_percentage": avg_savings_percentage
            })
            
        except Exception as e:
            self.logger.error(f"Error scanning cost data: {str(e)}")
            return self.format_results({
                "error": str(e),
                "cost_by_service": [],
                "cost_by_region": [],
                "cost_by_tag": [],
                "cost_anomalies": [],
                "savings_recommendations": [],
                "total_potential_savings": 0,
                "total_current_cost": 0,
                "avg_savings_percentage": 0
            })
    
    def _get_cost_by_service(self, ce_client, start_date: str, end_date: str) -> List[Dict[str, Any]]:
        """Get cost data grouped by service"""
        try:
            # In a real implementation, we would query AWS Cost Explorer API
            # For this example, we'll return simulated values
            
            # Simulate cost data for various services
            return [
                {"service": "Amazon Elastic Compute Cloud", "amount": 1250.45, "unit": "USD"},
                {"service": "Amazon Elastic Kubernetes Service", "amount": 450.20, "unit": "USD"},
                {"service": "Amazon DynamoDB", "amount": 320.75, "unit": "USD"},
                {"service": "Amazon Simple Storage Service", "amount": 280.30, "unit": "USD"},
                {"service": "Amazon CloudWatch", "amount": 175.60, "unit": "USD"},
                {"service": "AWS Lambda", "amount": 120.15, "unit": "USD"},
                {"service": "Amazon RDS", "amount": 380.90, "unit": "USD"},
                {"service": "Data Transfer", "amount": 95.40, "unit": "USD"},
                {"service": "Other", "amount": 210.25, "unit": "USD"}
            ]
        except Exception as e:
            self.logger.error(f"Error getting cost by service: {str(e)}")
            return []
    
    def _get_cost_by_region(self, ce_client, start_date: str, end_date: str) -> List[Dict[str, Any]]:
        """Get cost data grouped by region"""
        try:
            # Simulate cost data for various regions
            return [
                {"region": "us-east-1", "amount": 1850.30, "unit": "USD"},
                {"region": "us-west-2", "amount": 950.75, "unit": "USD"},
                {"region": "eu-west-1", "amount": 420.60, "unit": "USD"},
                {"region": "ap-southeast-1", "amount": 280.45, "unit": "USD"},
                {"region": "Other", "amount": 180.90, "unit": "USD"}
            ]
        except Exception as e:
            self.logger.error(f"Error getting cost by region: {str(e)}")
            return []
    
    def _get_cost_by_tag(self, ce_client, start_date: str, end_date: str) -> List[Dict[str, Any]]:
        """Get cost data grouped by tags"""
        try:
            # Simulate cost data for various tags
            return [
                {"tag": "Environment:Production", "amount": 2450.80, "unit": "USD"},
                {"tag": "Environment:Development", "amount": 850.35, "unit": "USD"},
                {"tag": "Environment:Staging", "amount": 380.85, "unit": "USD"},
                {"tag": "Project:MainApp", "amount": 1250.60, "unit": "USD"},
                {"tag": "Project:Analytics", "amount": 750.40, "unit": "USD"},
                {"tag": "Untagged", "amount": 620.30, "unit": "USD"}
            ]
        except Exception as e:
            self.logger.error(f"Error getting cost by tag: {str(e)}")
            return []
    
    def _get_cost_anomalies(self, ce_client, start_date: str, end_date: str) -> List[Dict[str, Any]]:
        """Get cost anomalies"""
        try:
            # Simulate cost anomalies
            return [
                {
                    "service": "Amazon Elastic Compute Cloud",
                    "anomaly_start_date": "2023-06-15",
                    "anomaly_end_date": "2023-06-18",
                    "impact": 120.45,
                    "reason": "Unexpected increase in instance usage"
                },
                {
                    "service": "Amazon DynamoDB",
                    "anomaly_start_date": "2023-06-20",
                    "anomaly_end_date": "2023-06-22",
                    "impact": 85.30,
                    "reason": "Increased read/write capacity"
                }
            ]
        except Exception as e:
            self.logger.error(f"Error getting cost anomalies: {str(e)}")
            return []
    
    def _get_savings_recommendations(self, ce_client) -> List[Dict[str, Any]]:
        """Get savings recommendations with detailed savings estimates"""
        try:
            # Simulate savings recommendations with more detailed information
            return [
                {
                    "recommendation_type": "Right Sizing",
                    "service": "Amazon EC2",
                    "resource_type": "EC2 Instance",
                    "resource_id": "i-0a1b2c3d4e5f6g7h8",
                    "current_cost": 450.25,
                    "potential_savings": 320.50,
                    "savings_percentage": 71,
                    "recommendation": "Downsize from r5.2xlarge to r5.xlarge based on low CPU/memory utilization (avg 15% CPU, 4GB memory used)",
                    "implementation_effort": "Low",
                    "implementation_steps": [
                        "Stop the instance",
                        "Change instance type from r5.2xlarge to r5.xlarge",
                        "Start the instance"
                    ],
                    "aws_cli_command": "aws ec2 modify-instance-attribute --instance-id i-0a1b2c3d4e5f6g7h8 --instance-type r5.xlarge"
                },
                {
                    "recommendation_type": "Reserved Instances",
                    "service": "Amazon EC2",
                    "resource_type": "EC2 Instance Group",
                    "resource_id": "Web Servers",
                    "current_cost": 1250.00,
                    "potential_savings": 450.75,
                    "savings_percentage": 36,
                    "recommendation": "Purchase 15 t3.large Reserved Instances for consistently running web servers (1-year term, partial upfront)",
                    "implementation_effort": "Medium",
                    "implementation_steps": [
                        "Review instance usage patterns to confirm consistent usage",
                        "Purchase Reserved Instances through AWS Console or CLI"
                    ],
                    "aws_cli_command": "aws ec2 purchase-reserved-instances-offering --instance-count 15 --reserved-instances-offering-id ri-0a1b2c3d4e5f6g7h8"
                },
                {
                    "recommendation_type": "Idle Resources",
                    "service": "Amazon EBS",
                    "resource_type": "EBS Volume",
                    "resource_id": "vol-0a1b2c3d4e5f6g7h8",
                    "current_cost": 45.20,
                    "potential_savings": 45.20,
                    "savings_percentage": 100,
                    "recommendation": "Delete 5 unattached EBS volumes (total 500GB) that have been unused for over 30 days",
                    "implementation_effort": "Low",
                    "implementation_steps": [
                        "Verify volumes are not needed",
                        "Create snapshots if data needs to be preserved",
                        "Delete the volumes"
                    ],
                    "aws_cli_command": "aws ec2 delete-volume --volume-id vol-0a1b2c3d4e5f6g7h8"
                },
                {
                    "recommendation_type": "Savings Plans",
                    "service": "AWS Lambda",
                    "resource_type": "Lambda Functions",
                    "resource_id": "Multiple Functions",
                    "current_cost": 180.50,
                    "potential_savings": 65.30,
                    "savings_percentage": 36,
                    "recommendation": "Purchase Compute Savings Plan for consistent Lambda usage (approx. 5M invocations/month)",
                    "implementation_effort": "Medium",
                    "implementation_steps": [
                        "Review Lambda usage patterns over the last 3 months",
                        "Purchase Compute Savings Plan through AWS Console"
                    ],
                    "aws_cli_command": "Use AWS Console to purchase Savings Plans"
                },
                {
                    "recommendation_type": "On-Demand Capacity Reservations",
                    "service": "Amazon EC2",
                    "resource_type": "Capacity Reservation",
                    "resource_id": "cr-0a1b2c3d4e5f6g7h8",
                    "current_cost": 120.80,
                    "potential_savings": 120.80,
                    "savings_percentage": 100,
                    "recommendation": "Cancel 3 unused capacity reservations for c5.2xlarge instances that have been empty for over 7 days",
                    "implementation_effort": "Low",
                    "implementation_steps": [
                        "Verify reservations are not needed for upcoming workloads",
                        "Cancel the reservations through AWS Console or CLI"
                    ],
                    "aws_cli_command": "aws ec2 cancel-capacity-reservation --capacity-reservation-id cr-0a1b2c3d4e5f6g7h8"
                },
                {
                    "recommendation_type": "DynamoDB Provisioned Capacity",
                    "service": "Amazon DynamoDB",
                    "resource_type": "DynamoDB Table",
                    "resource_id": "UserSessions",
                    "current_cost": 95.40,
                    "potential_savings": 68.75,
                    "savings_percentage": 72,
                    "recommendation": "Switch from provisioned capacity (1000 RCU/1000 WCU) to on-demand pricing based on usage patterns (avg 150 RCU/100 WCU)",
                    "implementation_effort": "Low",
                    "implementation_steps": [
                        "Switch table to on-demand capacity mode through AWS Console or CLI"
                    ],
                    "aws_cli_command": "aws dynamodb update-table --table-name UserSessions --billing-mode PAY_PER_REQUEST"
                },
                {
                    "recommendation_type": "RDS Instance Sizing",
                    "service": "Amazon RDS",
                    "resource_type": "RDS Instance",
                    "resource_id": "db-reporting-instance",
                    "current_cost": 280.30,
                    "potential_savings": 140.15,
                    "savings_percentage": 50,
                    "recommendation": "Downsize from db.r5.xlarge to db.r5.large based on low CPU utilization (avg 25%) and memory usage",
                    "implementation_effort": "Medium",
                    "implementation_steps": [
                        "Schedule downtime window",
                        "Modify instance class through AWS Console or CLI",
                        "Monitor performance after change"
                    ],
                    "aws_cli_command": "aws rds modify-db-instance --db-instance-identifier db-reporting-instance --db-instance-class db.r5.large --apply-immediately"
                },
                {
                    "recommendation_type": "S3 Storage Class",
                    "service": "Amazon S3",
                    "resource_type": "S3 Bucket",
                    "resource_id": "logs-archive-bucket",
                    "current_cost": 75.20,
                    "potential_savings": 52.64,
                    "savings_percentage": 70,
                    "recommendation": "Move 500GB of log data older than 90 days from Standard to Glacier storage class",
                    "implementation_effort": "Low",
                    "implementation_steps": [
                        "Create lifecycle policy to transition objects older than 90 days to Glacier"
                    ],
                    "aws_cli_command": "aws s3api put-bucket-lifecycle-configuration --bucket logs-archive-bucket --lifecycle-configuration file://lifecycle-config.json"
                }
            ]
        except Exception as e:
            self.logger.error(f"Error getting savings recommendations: {str(e)}")
            return []
