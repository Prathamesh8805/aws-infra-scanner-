from typing import Dict, Any, List
from .base_scanner import BaseScanner

class RDSScanner(BaseScanner):
    """Scanner for RDS databases and related resources"""
    
    def scan(self) -> Dict[str, Any]:
        """Scan RDS databases and related resources"""
        try:
            rds_client = self.get_boto3_client('rds')
            
            # Get all DB instances
            db_instances_response = rds_client.describe_db_instances()
            db_instances = db_instances_response.get('DBInstances', [])
            
            # Find public databases
            public_db_instances = []
            for db in db_instances:
                if db.get('PubliclyAccessible', False):
                    public_db_instances.append(db)
            
            # Get all DB snapshots
            db_snapshots_response = rds_client.describe_db_snapshots()
            db_snapshots = db_snapshots_response.get('DBSnapshots', [])
            
            # Find public snapshots
            public_db_snapshots = []
            for snapshot in db_snapshots:
                try:
                    # Check if snapshot is public
                    snapshot_attributes = rds_client.describe_db_snapshot_attributes(
                        DBSnapshotIdentifier=snapshot.get('DBSnapshotIdentifier')
                    )
                    
                    for attr in snapshot_attributes.get('DBSnapshotAttributesResult', {}).get('DBSnapshotAttributes', []):
                        if attr.get('AttributeName') == 'restore' and 'all' in attr.get('AttributeValues', []):
                            public_db_snapshots.append(snapshot)
                            break
                except Exception as e:
                    self.logger.error(f"Error checking snapshot attributes: {str(e)}")
            
            # Find databases without encryption
            unencrypted_db_instances = []
            for db in db_instances:
                if not db.get('StorageEncrypted', False):
                    unencrypted_db_instances.append(db)
            
            # Find databases without Multi-AZ
            non_multi_az_db_instances = []
            for db in db_instances:
                if not db.get('MultiAZ', False):
                    non_multi_az_db_instances.append(db)
            
            # Find databases without automatic backups
            no_backup_db_instances = []
            for db in db_instances:
                if db.get('BackupRetentionPeriod', 0) == 0:
                    no_backup_db_instances.append(db)
            
            # Extract engine versions to identify outdated ones
            engine_versions = {}
            outdated_db_instances = []
            
            for db in db_instances:
                engine = db.get('Engine')
                version = db.get('EngineVersion')
                
                if engine and version:
                    if engine not in engine_versions:
                        engine_versions[engine] = []
                    
                    if version not in engine_versions[engine]:
                        engine_versions[engine].append(version)
            
            # Define outdated versions for common engines
            # These would need to be updated regularly in a production environment
            outdated_versions = {
                'mysql': ['5.6', '5.7'],
                'postgres': ['9.6', '10', '11'],
                'oracle': ['11.2', '12.1'],
                'sqlserver': ['12.0', '13.0']
            }
            
            for db in db_instances:
                engine = db.get('Engine', '')
                version = db.get('EngineVersion', '')
                
                for outdated_engine, versions in outdated_versions.items():
                    if engine.startswith(outdated_engine):
                        for outdated_version in versions:
                            if version.startswith(outdated_version):
                                outdated_db_instances.append(db)
                                break
            
            # Get all DB parameter groups
            parameter_groups_response = rds_client.describe_db_parameter_groups()
            parameter_groups = parameter_groups_response.get('DBParameterGroups', [])
            
            # Get all DB security groups
            security_groups_response = rds_client.describe_db_security_groups()
            security_groups = security_groups_response.get('DBSecurityGroups', [])
            
            # Find security groups with public access
            public_security_groups = []
            for sg in security_groups:
                for ingress in sg.get('IPRanges', []):
                    if ingress.get('CIDRIP') == '0.0.0.0/0':
                        public_security_groups.append(sg)
                        break
            
            # Process DB instances for the report
            processed_db_instances = []
            for db in db_instances:
                processed_db = {
                    'DBInstanceIdentifier': db.get('DBInstanceIdentifier'),
                    'Engine': db.get('Engine'),
                    'EngineVersion': db.get('EngineVersion'),
                    'DBInstanceClass': db.get('DBInstanceClass'),
                    'MultiAZ': db.get('MultiAZ', False),
                    'PubliclyAccessible': db.get('PubliclyAccessible', False),
                    'StorageEncrypted': db.get('StorageEncrypted', False),
                    'BackupRetentionPeriod': db.get('BackupRetentionPeriod', 0),
                    'DBInstanceStatus': db.get('DBInstanceStatus'),
                    'Endpoint': db.get('Endpoint', {}).get('Address') if db.get('Endpoint') else None,
                    'AllocatedStorage': db.get('AllocatedStorage'),
                    'VpcId': db.get('DBSubnetGroup', {}).get('VpcId') if db.get('DBSubnetGroup') else None
                }
                processed_db_instances.append(processed_db)
            
            return self.format_results({
                "db_instances": processed_db_instances,
                "db_instance_count": len(db_instances),
                "public_db_instances": [db.get('DBInstanceIdentifier') for db in public_db_instances],
                "public_db_instance_count": len(public_db_instances),
                "unencrypted_db_instances": [db.get('DBInstanceIdentifier') for db in unencrypted_db_instances],
                "unencrypted_db_instance_count": len(unencrypted_db_instances),
                "non_multi_az_db_instances": [db.get('DBInstanceIdentifier') for db in non_multi_az_db_instances],
                "non_multi_az_db_instance_count": len(non_multi_az_db_instances),
                "no_backup_db_instances": [db.get('DBInstanceIdentifier') for db in no_backup_db_instances],
                "no_backup_db_instance_count": len(no_backup_db_instances),
                "outdated_db_instances": [db.get('DBInstanceIdentifier') for db in outdated_db_instances],
                "outdated_db_instance_count": len(outdated_db_instances),
                "db_snapshots": [snapshot.get('DBSnapshotIdentifier') for snapshot in db_snapshots],
                "db_snapshot_count": len(db_snapshots),
                "public_db_snapshots": [snapshot.get('DBSnapshotIdentifier') for snapshot in public_db_snapshots],
                "public_db_snapshot_count": len(public_db_snapshots),
                "db_parameter_groups": [pg.get('DBParameterGroupName') for pg in parameter_groups],
                "db_parameter_group_count": len(parameter_groups),
                "db_security_groups": [sg.get('DBSecurityGroupName') for sg in security_groups],
                "db_security_group_count": len(security_groups),
                "public_db_security_groups": [sg.get('DBSecurityGroupName') for sg in public_security_groups],
                "public_db_security_group_count": len(public_security_groups),
                "engine_versions": engine_versions
            })
        except Exception as e:
            self.logger.error(f"Error scanning RDS resources: {str(e)}")
            return self.format_results({
                "error": str(e),
                "db_instances": [],
                "db_instance_count": 0,
                "db_snapshots": [],
                "db_snapshot_count": 0,
                "db_parameter_groups": [],
                "db_parameter_group_count": 0,
                "db_security_groups": [],
                "db_security_group_count": 0
            })
