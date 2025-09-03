from typing import Dict, Any, List
from datetime import datetime, timedelta
from .base_scanner import BaseScanner

class DynamoDBScanner(BaseScanner):
    """Scanner for DynamoDB resources"""
    
    # Threshold for low usage tables (items count)
    LOW_USAGE_ITEM_THRESHOLD = 10
    
    # Threshold for table size (bytes)
    LOW_USAGE_SIZE_THRESHOLD = 1024 * 1024  # 1 MB
    
    # Threshold for high provisioned capacity (percentage of usage)
    HIGH_PROVISIONED_THRESHOLD = 30  # If using less than 30% of provisioned capacity
    
    # Threshold for old tables (days)
    OLD_TABLE_THRESHOLD = 365  # 1 year
    
    def scan(self) -> Dict[str, Any]:
        """Scan DynamoDB tables and related resources"""
        try:
            client = self.get_boto3_client('dynamodb')
            cloudwatch_client = self.get_boto3_client('cloudwatch')
            
            # List all tables
            tables_response = client.list_tables()
            table_names = tables_response.get('TableNames', [])
            
            tables_info = []
            low_usage_tables = []
            on_demand_tables = []
            provisioned_tables = []
            over_provisioned_tables = []
            no_backup_tables = []
            no_pitr_tables = []
            old_tables = []
            
            current_time = datetime.utcnow()
            
            for table_name in table_names:
                # Get detailed table information
                table_info = client.describe_table(TableName=table_name)['Table']
                
                # Get tags for this table
                tags_response = client.list_tags_of_resource(
                    ResourceArn=table_info['TableArn']
                )
                tags = tags_response.get('Tags', [])
                
                # Add tags to table info
                table_info['Tags'] = tags
                
                # Check billing mode
                if 'BillingModeSummary' in table_info and table_info['BillingModeSummary']['BillingMode'] == 'PAY_PER_REQUEST':
                    on_demand_tables.append({
                        'TableName': table_name,
                        'ItemCount': table_info.get('ItemCount', 0),
                        'TableSizeBytes': table_info.get('TableSizeBytes', 0),
                        'CreationDateTime': table_info.get('CreationDateTime')
                    })
                elif 'ProvisionedThroughput' in table_info:
                    throughput = table_info['ProvisionedThroughput']
                    provisioned_table = {
                        'TableName': table_name,
                        'ReadCapacityUnits': throughput.get('ReadCapacityUnits', 0),
                        'WriteCapacityUnits': throughput.get('WriteCapacityUnits', 0),
                        'ItemCount': table_info.get('ItemCount', 0),
                        'TableSizeBytes': table_info.get('TableSizeBytes', 0),
                        'CreationDateTime': table_info.get('CreationDateTime')
                    }
                    provisioned_tables.append(provisioned_table)
                    
                    # Get consumed capacity metrics from CloudWatch
                    try:
                        consumed_capacity = self._get_table_consumed_capacity(cloudwatch_client, table_name)
                        table_info['ConsumedCapacity'] = consumed_capacity
                        
                        # Check for over-provisioning
                        read_capacity = throughput.get('ReadCapacityUnits', 0)
                        write_capacity = throughput.get('WriteCapacityUnits', 0)
                        consumed_read = consumed_capacity.get('ReadCapacityUnits', {}).get('Average', 0)
                        consumed_write = consumed_capacity.get('WriteCapacityUnits', {}).get('Average', 0)
                        
                        # Calculate utilization percentage
                        read_utilization = (consumed_read / read_capacity * 100) if read_capacity > 0 else 0
                        write_utilization = (consumed_write / write_capacity * 100) if write_capacity > 0 else 0
                        
                        # If utilization is below threshold, consider it over-provisioned
                        if read_utilization < self.HIGH_PROVISIONED_THRESHOLD or write_utilization < self.HIGH_PROVISIONED_THRESHOLD:
                            over_provisioned_tables.append({
                                'TableName': table_name,
                                'ReadCapacityUnits': read_capacity,
                                'WriteCapacityUnits': write_capacity,
                                'ReadUtilization': read_utilization,
                                'WriteUtilization': write_utilization,
                                'RecommendedReadCapacity': max(1, int(consumed_read * 1.5)),
                                'RecommendedWriteCapacity': max(1, int(consumed_write * 1.5))
                            })
                    except Exception as cw_error:
                        table_info['ConsumedCapacity'] = {
                            'ReadCapacityUnits': 'Error: ' + str(cw_error),
                            'WriteCapacityUnits': 'Error: ' + str(cw_error)
                        }
                
                # Check for low usage tables
                item_count = table_info.get('ItemCount', 0)
                table_size_bytes = table_info.get('TableSizeBytes', 0)
                
                if item_count <= self.LOW_USAGE_ITEM_THRESHOLD or table_size_bytes <= self.LOW_USAGE_SIZE_THRESHOLD:
                    low_usage_tables.append({
                        'TableName': table_name,
                        'ItemCount': item_count,
                        'TableSizeBytes': table_size_bytes,
                        'CreationDateTime': table_info.get('CreationDateTime')
                    })
                
                # Check for tables without Point-in-Time Recovery (PITR)
                pitr_description = table_info.get('ContinuousBackupsDescription', {})
                pitr_status = pitr_description.get('PointInTimeRecoveryDescription', {}).get('PointInTimeRecoveryStatus', 'DISABLED')
                
                if pitr_status == 'DISABLED':
                    no_pitr_tables.append({
                        'TableName': table_name,
                        'CreationDateTime': table_info.get('CreationDateTime')
                    })
                
                # Get backup information
                try:
                    backups_response = client.list_backups(TableName=table_name)
                    backups = backups_response.get('BackupSummaries', [])
                    table_info['Backups'] = backups
                    
                    # Check for tables without backups
                    if not backups:
                        no_backup_tables.append({
                            'TableName': table_name,
                            'CreationDateTime': table_info.get('CreationDateTime')
                        })
                except Exception as backup_error:
                    table_info['Backups'] = []
                    table_info['BackupError'] = str(backup_error)
                    
                    # If we can't check backups, assume there are none
                    no_backup_tables.append({
                        'TableName': table_name,
                        'CreationDateTime': table_info.get('CreationDateTime')
                    })
                
                # Check for old tables
                creation_date = table_info.get('CreationDateTime')
                if creation_date:
                    if isinstance(creation_date, str):
                        try:
                            creation_date = datetime.fromisoformat(creation_date.replace('Z', '+00:00'))
                        except:
                            creation_date = None
                    
                    if creation_date:
                        # Make sure both datetimes are timezone-aware or both are naive
                        if creation_date.tzinfo is not None and current_time.tzinfo is None:
                            current_time = current_time.replace(tzinfo=creation_date.tzinfo)
                        elif creation_date.tzinfo is None and current_time.tzinfo is not None:
                            creation_date = creation_date.replace(tzinfo=current_time.tzinfo)
                            
                        if (current_time - creation_date).days > self.OLD_TABLE_THRESHOLD:
                            old_tables.append({
                                'TableName': table_name,
                                'CreationDateTime': creation_date,
                                'AgeInDays': (current_time - creation_date).days
                            })
                
                # Get global secondary indexes
                gsi_list = table_info.get('GlobalSecondaryIndexes', [])
                table_info['GSICount'] = len(gsi_list)
                
                # Get local secondary indexes
                lsi_list = table_info.get('LocalSecondaryIndexes', [])
                table_info['LSICount'] = len(lsi_list)
                
                tables_info.append(table_info)
            
            return self.format_results({
                "tables": tables_info,
                "table_count": len(tables_info),
                "on_demand_tables": on_demand_tables,
                "on_demand_table_count": len(on_demand_tables),
                "provisioned_tables": provisioned_tables,
                "provisioned_table_count": len(provisioned_tables),
                "low_usage_tables": low_usage_tables,
                "low_usage_table_count": len(low_usage_tables),
                "over_provisioned_tables": over_provisioned_tables,
                "over_provisioned_table_count": len(over_provisioned_tables),
                "no_backup_tables": no_backup_tables,
                "no_backup_table_count": len(no_backup_tables),
                "no_pitr_tables": no_pitr_tables,
                "no_pitr_table_count": len(no_pitr_tables),
                "old_tables": old_tables,
                "old_table_count": len(old_tables)
            })
        except Exception as e:
            self.logger.error(f"Error scanning DynamoDB resources: {str(e)}")
            return self.format_results({
                "error": str(e),
                "tables": [],
                "table_count": 0,
                "on_demand_tables": [],
                "on_demand_table_count": 0,
                "provisioned_tables": [],
                "provisioned_table_count": 0,
                "low_usage_tables": [],
                "low_usage_table_count": 0,
                "over_provisioned_tables": [],
                "over_provisioned_table_count": 0,
                "no_backup_tables": [],
                "no_backup_table_count": 0,
                "no_pitr_tables": [],
                "no_pitr_table_count": 0,
                "old_tables": [],
                "old_table_count": 0
            })
    
    def _get_table_consumed_capacity(self, cloudwatch_client, table_name: str) -> Dict[str, Any]:
        """Get consumed capacity metrics for a DynamoDB table"""
        # In a real implementation, we would query CloudWatch metrics
        # For this example, we'll return simulated values
        
        end_time = datetime.utcnow()
        start_time = end_time - timedelta(days=14)
        
        # Simulate different consumed capacities for different tables
        import hashlib
        # Use a hash of the table name to get a consistent but seemingly random value
        hash_val = int(hashlib.md5(table_name.encode()).hexdigest(), 16)
        read_capacity = (hash_val % 100) / 10  # Value between 0 and 10
        write_capacity = (hash_val % 50) / 10  # Value between 0 and 5
        
        return {
            'ReadCapacityUnits': {
                'Average': read_capacity,
                'Maximum': read_capacity * 2,
                'Period': '14 days'
            },
            'WriteCapacityUnits': {
                'Average': write_capacity,
                'Maximum': write_capacity * 3,
                'Period': '14 days'
            }
        }