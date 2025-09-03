from typing import Dict, Any, List
from .base_scanner import BaseScanner

class VPCScanner(BaseScanner):
    """Scanner for VPC resources"""
    
    def scan(self) -> Dict[str, Any]:
        """Scan VPC and related resources"""
        client = self.get_boto3_client('ec2')
        
        try:
            # Get all VPCs
            vpcs_response = client.describe_vpcs()
            vpcs = vpcs_response.get('Vpcs', [])
            
            vpc_details = []
            for vpc in vpcs:
                vpc_id = vpc['VpcId']
                
                # Get subnets for this VPC
                subnets_response = client.describe_subnets(Filters=[
                    {'Name': 'vpc-id', 'Values': [vpc_id]}
                ])
                subnets = subnets_response.get('Subnets', [])
                
                # Get route tables for this VPC
                route_tables_response = client.describe_route_tables(Filters=[
                    {'Name': 'vpc-id', 'Values': [vpc_id]}
                ])
                route_tables = route_tables_response.get('RouteTables', [])
                
                # Get internet gateways for this VPC
                igw_response = client.describe_internet_gateways(Filters=[
                    {'Name': 'attachment.vpc-id', 'Values': [vpc_id]}
                ])
                internet_gateways = igw_response.get('InternetGateways', [])
                
                # Get NAT gateways for this VPC
                nat_gateways_response = client.describe_nat_gateways(Filters=[
                    {'Name': 'vpc-id', 'Values': [vpc_id]}
                ])
                nat_gateways = nat_gateways_response.get('NatGateways', [])
                
                # Get network ACLs for this VPC
                nacls_response = client.describe_network_acls(Filters=[
                    {'Name': 'vpc-id', 'Values': [vpc_id]}
                ])
                network_acls = nacls_response.get('NetworkAcls', [])
                
                # Compile VPC details
                vpc_detail = {
                    'vpc': vpc,
                    'subnets': subnets,
                    'route_tables': route_tables,
                    'internet_gateways': internet_gateways,
                    'nat_gateways': nat_gateways,
                    'network_acls': network_acls
                }
                
                vpc_details.append(vpc_detail)
            
            return self.format_results({
                "vpcs": vpc_details,
                "vpc_count": len(vpcs)
            })
        
        except Exception as e:
            self.logger.error(f"Error scanning VPC resources: {str(e)}")
            return self.format_results({
                "error": str(e),
                "vpcs": [],
                "vpc_count": 0
            })
