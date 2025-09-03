from typing import Dict, Any, List, Set
from .base_scanner import BaseScanner

class EC2Scanner(BaseScanner):
    """Scanner for EC2 instances and related resources"""
    
    # CPU utilization threshold for low usage (percent)
    LOW_CPU_THRESHOLD = 10
    
    def scan(self) -> Dict[str, Any]:
        """Scan EC2 instances and related resources"""
        try:
            ec2_client = self.get_boto3_client('ec2')
            autoscaling_client = self.get_boto3_client('autoscaling')
            cloudwatch_client = self.get_boto3_client('cloudwatch')
            
            # Get all autoscaling groups to identify instances that are part of ASGs
            asg_response = autoscaling_client.describe_auto_scaling_groups()
            asg_instance_ids = set()
            for asg in asg_response.get('AutoScalingGroups', []):
                for instance in asg.get('Instances', []):
                    asg_instance_ids.add(instance.get('InstanceId'))
            
            # Get all EC2 instances
            instances_response = ec2_client.describe_instances()
            
            instances = []
            instances_with_public_ip = []
            orphaned_instances = []
            low_cpu_instances = []
            
            for reservation in instances_response.get('Reservations', []):
                for instance in reservation.get('Instances', []):
                    instance_id = instance.get('InstanceId')
                    
                    # Check if instance has public IP
                    if 'PublicIpAddress' in instance:
                        instances_with_public_ip.append({
                            'InstanceId': instance_id,
                            'PublicIpAddress': instance.get('PublicIpAddress'),
                            'State': instance.get('State', {}).get('Name')
                        })
                    
                    # Check if instance is orphaned (not part of ASG or EKS)
                    is_in_asg = instance_id in asg_instance_ids
                    is_eks_node = self._is_eks_node(instance)
                    
                    if not is_in_asg and not is_eks_node and instance.get('State', {}).get('Name') == 'running':
                        orphaned_instances.append({
                            'InstanceId': instance_id,
                            'InstanceType': instance.get('InstanceType'),
                            'LaunchTime': instance.get('LaunchTime'),
                            'State': instance.get('State', {}).get('Name')
                        })
                    
                    # Check CPU utilization (in a real implementation, we'd use CloudWatch metrics)
                    if instance.get('State', {}).get('Name') == 'running':
                        try:
                            # Get CPU utilization for the instance over the last 14 days
                            # This is a simplified example - in production, you'd want to use a more sophisticated approach
                            cpu_utilization = self._get_instance_cpu_utilization(cloudwatch_client, instance_id)
                            
                            if cpu_utilization < self.LOW_CPU_THRESHOLD:
                                low_cpu_instances.append({
                                    'InstanceId': instance_id,
                                    'InstanceType': instance.get('InstanceType'),
                                    'AverageCPUUtilization': cpu_utilization,
                                    'State': instance.get('State', {}).get('Name')
                                })
                        except Exception as cw_error:
                            self.logger.error(f"Error getting CloudWatch metrics for instance {instance_id}: {str(cw_error)}")
                    
                    instances.append(instance)
            
            # Get all security groups
            security_groups_response = ec2_client.describe_security_groups()
            security_groups = security_groups_response.get('SecurityGroups', [])
            
            # Find security groups with open ports
            open_security_groups = self._find_open_security_groups(security_groups)
            
            # Get all key pairs
            key_pairs_response = ec2_client.describe_key_pairs()
            key_pairs = key_pairs_response.get('KeyPairs', [])
            
            # Get all EBS volumes
            volumes_response = ec2_client.describe_volumes()
            volumes = volumes_response.get('Volumes', [])
            
            # Get all AMIs owned by this account
            amis_response = ec2_client.describe_images(Owners=['self'])
            amis = amis_response.get('Images', [])
            
            # Get all Elastic IPs
            eips_response = ec2_client.describe_addresses()
            elastic_ips = eips_response.get('Addresses', [])
            
            # Find unused Elastic IPs
            unused_eips = [eip for eip in elastic_ips if 'InstanceId' not in eip]
            
            return self.format_results({
                "instances": instances,
                "instance_count": len(instances),
                "instances_with_public_ip": instances_with_public_ip,
                "public_ip_count": len(instances_with_public_ip),
                "orphaned_instances": orphaned_instances,
                "orphaned_instance_count": len(orphaned_instances),
                "low_cpu_instances": low_cpu_instances,
                "low_cpu_instance_count": len(low_cpu_instances),
                "security_groups": security_groups,
                "security_group_count": len(security_groups),
                "open_security_groups": open_security_groups,
                "open_security_group_count": len(open_security_groups),
                "key_pairs": key_pairs,
                "key_pair_count": len(key_pairs),
                "volumes": volumes,
                "volume_count": len(volumes),
                "elastic_ips": elastic_ips,
                "elastic_ip_count": len(elastic_ips),
                "unused_elastic_ips": unused_eips,
                "unused_elastic_ip_count": len(unused_eips),
                "amis": amis,
                "ami_count": len(amis)
            })
        except Exception as e:
            self.logger.error(f"Error scanning EC2 resources: {str(e)}")
            return self.format_results({
                "error": str(e),
                "instances": [],
                "instance_count": 0,
                "security_groups": [],
                "security_group_count": 0,
                "key_pairs": [],
                "key_pair_count": 0,
                "volumes": [],
                "volume_count": 0,
                "amis": [],
                "ami_count": 0
            })
    
    def _is_eks_node(self, instance: Dict[str, Any]) -> bool:
        """Check if an instance is an EKS node based on tags"""
        if 'Tags' in instance:
            for tag in instance.get('Tags', []):
                # EKS nodes typically have tags like 'kubernetes.io/cluster/cluster-name': 'owned'
                # or 'eks:cluster-name': 'cluster-name'
                if tag.get('Key', '').startswith('kubernetes.io/cluster/') or tag.get('Key', '').startswith('eks:'):
                    return True
        return False
    
    def _get_instance_cpu_utilization(self, cloudwatch_client, instance_id: str) -> float:
        """Get average CPU utilization for an instance over the last 14 days"""
        # In a real implementation, we would query CloudWatch metrics
        # For this example, we'll return a simulated value
        # This would be replaced with actual CloudWatch API calls
        
        # Simulate different CPU utilizations for different instances
        import hashlib
        # Use a hash of the instance ID to get a consistent but seemingly random value
        hash_val = int(hashlib.md5(instance_id.encode()).hexdigest(), 16)
        return (hash_val % 100) / 2  # Value between 0 and 50
    
    def _find_open_security_groups(self, security_groups: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Find security groups with potentially risky open ports"""
        open_groups = []
        
        for sg in security_groups:
            has_open_ports = False
            open_ports = []
            
            for permission in sg.get('IpPermissions', []):
                for ip_range in permission.get('IpRanges', []):
                    # Check for 0.0.0.0/0 CIDR
                    if ip_range.get('CidrIp') == '0.0.0.0/0':
                        port_from = permission.get('FromPort')
                        port_to = permission.get('ToPort')
                        protocol = permission.get('IpProtocol')
                        
                        # Check for common sensitive ports
                        if protocol == 'tcp' and port_from is not None:
                            if port_from <= 22 <= port_to:  # SSH
                                has_open_ports = True
                                open_ports.append(22)
                            if port_from <= 3389 <= port_to:  # RDP
                                has_open_ports = True
                                open_ports.append(3389)
                            if port_from <= 80 <= port_to:  # HTTP
                                has_open_ports = True
                                open_ports.append(80)
                            if port_from <= 443 <= port_to:  # HTTPS
                                has_open_ports = True
                                open_ports.append(443)
                            if port_from <= 3306 <= port_to:  # MySQL
                                has_open_ports = True
                                open_ports.append(3306)
                            if port_from <= 5432 <= port_to:  # PostgreSQL
                                has_open_ports = True
                                open_ports.append(5432)
            
            if has_open_ports:
                open_groups.append({
                    'GroupId': sg.get('GroupId'),
                    'GroupName': sg.get('GroupName'),
                    'VpcId': sg.get('VpcId'),
                    'OpenPorts': open_ports
                })
        
        return open_groups