"""
Helper functions for creating RDS, Lambda, and enhanced DynamoDB sections in the dashboard.
"""
from typing import Dict, Any

def create_rds_findings_html(scan_results: Dict[str, Any]) -> str:
    """
    Create HTML for RDS findings.
    """
    html = ""
    
    if 'rds' not in scan_results:
        return html
    
    html += '<h3>RDS Findings</h3>'
    rds_results = scan_results['rds'].get('results', {})
    
    # Public DB instances
    public_db_instances = rds_results.get('public_db_instances', [])
    if public_db_instances:
        html += '<div class="danger-box">'
        html += f'<h4>⚠️ {len(public_db_instances)} RDS Instances are Publicly Accessible</h4>'
        html += '<p>Public databases are directly accessible from the internet and may be vulnerable to attacks.</p>'
        html += '</div>'
        
        html += '<h4>Publicly Accessible Databases</h4>'
        html += '<table>'
        html += '<tr><th>DB Identifier</th><th>Engine</th><th>Version</th><th>Status</th></tr>'
        
        for db_id in public_db_instances:
            # Find the full DB instance info
            db_info = None
            for db in rds_results.get('db_instances', []):
                if db.get('DBInstanceIdentifier') == db_id:
                    db_info = db
                    break
            
            if db_info:
                db_id = db_info.get('DBInstanceIdentifier', 'Unknown')
                engine = db_info.get('Engine', 'Unknown')
                version = db_info.get('EngineVersion', 'Unknown')
                status = db_info.get('DBInstanceStatus', 'Unknown')
                
                html += f'<tr><td>{db_id}</td><td>{engine}</td><td>{version}</td><td>{status}</td></tr>'
            else:
                html += f'<tr><td>{db_id}</td><td>Unknown</td><td>Unknown</td><td>Unknown</td></tr>'
        
        html += '</table>'
    
    # Unencrypted DB instances
    unencrypted_db_instances = rds_results.get('unencrypted_db_instances', [])
    if unencrypted_db_instances:
        html += '<div class="danger-box">'
        html += f'<h4>⚠️ {len(unencrypted_db_instances)} RDS Instances are Not Encrypted</h4>'
        html += '<p>Unencrypted databases may expose sensitive data if the underlying storage is compromised.</p>'
        html += '</div>'
        
        html += '<h4>Unencrypted Databases</h4>'
        html += '<table>'
        html += '<tr><th>DB Identifier</th><th>Engine</th><th>Version</th><th>Status</th></tr>'
        
        for db_id in unencrypted_db_instances:
            # Find the full DB instance info
            db_info = None
            for db in rds_results.get('db_instances', []):
                if db.get('DBInstanceIdentifier') == db_id:
                    db_info = db
                    break
            
            if db_info:
                db_id = db_info.get('DBInstanceIdentifier', 'Unknown')
                engine = db_info.get('Engine', 'Unknown')
                version = db_info.get('EngineVersion', 'Unknown')
                status = db_info.get('DBInstanceStatus', 'Unknown')
                
                html += f'<tr><td>{db_id}</td><td>{engine}</td><td>{version}</td><td>{status}</td></tr>'
            else:
                html += f'<tr><td>{db_id}</td><td>Unknown</td><td>Unknown</td><td>Unknown</td></tr>'
        
        html += '</table>'
    
    # Outdated DB instances
    outdated_db_instances = rds_results.get('outdated_db_instances', [])
    if outdated_db_instances:
        html += '<div class="warning-box">'
        html += f'<h4>⚠️ {len(outdated_db_instances)} RDS Instances are Running Outdated Versions</h4>'
        html += '<p>Outdated database engines may have security vulnerabilities and lack support.</p>'
        html += '</div>'
        
        html += '<h4>Outdated Database Engines</h4>'
        html += '<table>'
        html += '<tr><th>DB Identifier</th><th>Engine</th><th>Version</th><th>Status</th></tr>'
        
        for db_id in outdated_db_instances:
            # Find the full DB instance info
            db_info = None
            for db in rds_results.get('db_instances', []):
                if db.get('DBInstanceIdentifier') == db_id:
                    db_info = db
                    break
            
            if db_info:
                db_id = db_info.get('DBInstanceIdentifier', 'Unknown')
                engine = db_info.get('Engine', 'Unknown')
                version = db_info.get('EngineVersion', 'Unknown')
                status = db_info.get('DBInstanceStatus', 'Unknown')
                
                html += f'<tr><td>{db_id}</td><td>{engine}</td><td>{version}</td><td>{status}</td></tr>'
            else:
                html += f'<tr><td>{db_id}</td><td>Unknown</td><td>Unknown</td><td>Unknown</td></tr>'
        
        html += '</table>'
    
    # Non-Multi-AZ DB instances
    non_multi_az_db_instances = rds_results.get('non_multi_az_db_instances', [])
    if non_multi_az_db_instances:
        html += '<div class="warning-box">'
        html += f'<h4>⚠️ {len(non_multi_az_db_instances)} RDS Instances are Not Using Multi-AZ</h4>'
        html += '<p>Single-AZ deployments lack high availability and may experience downtime during maintenance.</p>'
        html += '</div>'
        
        html += '<h4>Single-AZ Databases</h4>'
        html += '<table>'
        html += '<tr><th>DB Identifier</th><th>Engine</th><th>Version</th><th>Status</th></tr>'
        
        for db_id in non_multi_az_db_instances:
            # Find the full DB instance info
            db_info = None
            for db in rds_results.get('db_instances', []):
                if db.get('DBInstanceIdentifier') == db_id:
                    db_info = db
                    break
            
            if db_info:
                db_id = db_info.get('DBInstanceIdentifier', 'Unknown')
                engine = db_info.get('Engine', 'Unknown')
                version = db_info.get('EngineVersion', 'Unknown')
                status = db_info.get('DBInstanceStatus', 'Unknown')
                
                html += f'<tr><td>{db_id}</td><td>{engine}</td><td>{version}</td><td>{status}</td></tr>'
            else:
                html += f'<tr><td>{db_id}</td><td>Unknown</td><td>Unknown</td><td>Unknown</td></tr>'
        
        html += '</table>'
    
    # No backup DB instances
    no_backup_db_instances = rds_results.get('no_backup_db_instances', [])
    if no_backup_db_instances:
        html += '<div class="warning-box">'
        html += f'<h4>⚠️ {len(no_backup_db_instances)} RDS Instances Have No Automated Backups</h4>'
        html += '<p>Databases without automated backups risk data loss in case of failures.</p>'
        html += '</div>'
        
        html += '<h4>Databases Without Automated Backups</h4>'
        html += '<table>'
        html += '<tr><th>DB Identifier</th><th>Engine</th><th>Version</th><th>Status</th></tr>'
        
        for db_id in no_backup_db_instances:
            # Find the full DB instance info
            db_info = None
            for db in rds_results.get('db_instances', []):
                if db.get('DBInstanceIdentifier') == db_id:
                    db_info = db
                    break
            
            if db_info:
                db_id = db_info.get('DBInstanceIdentifier', 'Unknown')
                engine = db_info.get('Engine', 'Unknown')
                version = db_info.get('EngineVersion', 'Unknown')
                status = db_info.get('DBInstanceStatus', 'Unknown')
                
                html += f'<tr><td>{db_id}</td><td>{engine}</td><td>{version}</td><td>{status}</td></tr>'
            else:
                html += f'<tr><td>{db_id}</td><td>Unknown</td><td>Unknown</td><td>Unknown</td></tr>'
        
        html += '</table>'
    
    # Public DB snapshots
    public_db_snapshots = rds_results.get('public_db_snapshots', [])
    if public_db_snapshots:
        html += '<div class="danger-box">'
        html += f'<h4>⚠️ {len(public_db_snapshots)} RDS Snapshots are Publicly Accessible</h4>'
        html += '<p>Public snapshots may expose sensitive data to unauthorized users.</p>'
        html += '</div>'
        
        html += '<h4>Public DB Snapshots</h4>'
        html += '<table>'
        html += '<tr><th>Snapshot Identifier</th></tr>'
        
        for snapshot_id in public_db_snapshots:
            html += f'<tr><td>{snapshot_id}</td></tr>'
        
        html += '</table>'
    
    return html

def create_lambda_findings_html(scan_results: Dict[str, Any]) -> str:
    """
    Create HTML for Lambda findings.
    """
    html = ""
    
    if 'lambda' not in scan_results:
        return html
    
    html += '<h3>Lambda Findings</h3>'
    lambda_results = scan_results['lambda'].get('results', {})
    
    # Outdated runtime functions
    outdated_runtime_functions = lambda_results.get('outdated_runtime_functions', [])
    if outdated_runtime_functions:
        html += '<div class="danger-box">'
        html += f'<h4>⚠️ {len(outdated_runtime_functions)} Lambda Functions are Using Outdated Runtimes</h4>'
        html += '<p>Outdated runtimes may have security vulnerabilities and lack support.</p>'
        html += '</div>'
        
        html += '<h4>Functions with Outdated Runtimes</h4>'
        html += '<table>'
        html += '<tr><th>Function Name</th><th>Runtime</th><th>Last Modified</th></tr>'
        
        for function_name in outdated_runtime_functions:
            # Find the full function info
            function_info = None
            for function in lambda_results.get('functions', []):
                if function.get('FunctionName') == function_name:
                    function_info = function
                    break
            
            if function_info:
                name = function_info.get('FunctionName', 'Unknown')
                runtime = function_info.get('Runtime', 'Unknown')
                last_modified = function_info.get('LastModified', 'Unknown')
                
                html += f'<tr><td>{name}</td><td>{runtime}</td><td>{last_modified}</td></tr>'
            else:
                html += f'<tr><td>{function_name}</td><td>Unknown</td><td>Unknown</td></tr>'
        
        html += '</table>'
    
    # Functions without VPC
    no_vpc_functions = lambda_results.get('no_vpc_functions', [])
    if no_vpc_functions:
        html += '<div class="warning-box">'
        html += f'<h4>⚠️ {len(no_vpc_functions)} Lambda Functions are Not in a VPC</h4>'
        html += '<p>Functions without VPC configuration may have broader network access than necessary.</p>'
        html += '</div>'
        
        html += '<h4>Functions Without VPC Configuration</h4>'
        html += '<table>'
        html += '<tr><th>Function Name</th><th>Runtime</th><th>Last Modified</th></tr>'
        
        for function_name in no_vpc_functions:
            # Find the full function info
            function_info = None
            for function in lambda_results.get('functions', []):
                if function.get('FunctionName') == function_name:
                    function_info = function
                    break
            
            if function_info:
                name = function_info.get('FunctionName', 'Unknown')
                runtime = function_info.get('Runtime', 'Unknown')
                last_modified = function_info.get('LastModified', 'Unknown')
                
                html += f'<tr><td>{name}</td><td>{runtime}</td><td>{last_modified}</td></tr>'
            else:
                html += f'<tr><td>{function_name}</td><td>Unknown</td><td>Unknown</td></tr>'
        
        html += '</table>'
    
    # Functions without DLQ
    no_dlq_functions = lambda_results.get('no_dlq_functions', [])
    if no_dlq_functions:
        html += '<div class="warning-box">'
        html += f'<h4>⚠️ {len(no_dlq_functions)} Lambda Functions Have No Dead Letter Queue</h4>'
        html += '<p>Functions without DLQ configuration may lose failed invocation data.</p>'
        html += '</div>'
        
        html += '<h4>Functions Without Dead Letter Queue</h4>'
        html += '<table>'
        html += '<tr><th>Function Name</th><th>Runtime</th><th>Last Modified</th></tr>'
        
        for function_name in no_dlq_functions:
            # Find the full function info
            function_info = None
            for function in lambda_results.get('functions', []):
                if function.get('FunctionName') == function_name:
                    function_info = function
                    break
            
            if function_info:
                name = function_info.get('FunctionName', 'Unknown')
                runtime = function_info.get('Runtime', 'Unknown')
                last_modified = function_info.get('LastModified', 'Unknown')
                
                html += f'<tr><td>{name}</td><td>{runtime}</td><td>{last_modified}</td></tr>'
            else:
                html += f'<tr><td>{function_name}</td><td>Unknown</td><td>Unknown</td></tr>'
        
        html += '</table>'
    
    # High memory functions
    high_memory_functions = lambda_results.get('high_memory_functions', [])
    if high_memory_functions:
        html += '<div class="warning-box">'
        html += f'<h4>⚠️ {len(high_memory_functions)} Lambda Functions Have High Memory Allocation</h4>'
        html += '<p>Functions with high memory allocation may be over-provisioned and incur unnecessary costs.</p>'
        html += '</div>'
        
        html += '<h4>Functions with High Memory Allocation</h4>'
        html += '<table>'
        html += '<tr><th>Function Name</th><th>Memory Size (MB)</th><th>Runtime</th></tr>'
        
        for function_name in high_memory_functions:
            # Find the full function info
            function_info = None
            for function in lambda_results.get('functions', []):
                if function.get('FunctionName') == function_name:
                    function_info = function
                    break
            
            if function_info:
                name = function_info.get('FunctionName', 'Unknown')
                memory_size = function_info.get('MemorySize', 'Unknown')
                runtime = function_info.get('Runtime', 'Unknown')
                
                html += f'<tr><td>{name}</td><td>{memory_size}</td><td>{runtime}</td></tr>'
            else:
                html += f'<tr><td>{function_name}</td><td>Unknown</td><td>Unknown</td></tr>'
        
        html += '</table>'
    
    # High timeout functions
    high_timeout_functions = lambda_results.get('high_timeout_functions', [])
    if high_timeout_functions:
        html += '<div class="warning-box">'
        html += f'<h4>⚠️ {len(high_timeout_functions)} Lambda Functions Have High Timeout Settings</h4>'
        html += '<p>Functions with high timeout settings may indicate inefficient code or potential issues.</p>'
        html += '</div>'
        
        html += '<h4>Functions with High Timeout Settings</h4>'
        html += '<table>'
        html += '<tr><th>Function Name</th><th>Timeout (seconds)</th><th>Runtime</th></tr>'
        
        for function_name in high_timeout_functions:
            # Find the full function info
            function_info = None
            for function in lambda_results.get('functions', []):
                if function.get('FunctionName') == function_name:
                    function_info = function
                    break
            
            if function_info:
                name = function_info.get('FunctionName', 'Unknown')
                timeout = function_info.get('Timeout', 'Unknown')
                runtime = function_info.get('Runtime', 'Unknown')
                
                html += f'<tr><td>{name}</td><td>{timeout}</td><td>{runtime}</td></tr>'
            else:
                html += f'<tr><td>{function_name}</td><td>Unknown</td><td>Unknown</td></tr>'
        
        html += '</table>'
    
    return html

def create_enhanced_dynamodb_findings_html(scan_results: Dict[str, Any]) -> str:
    """
    Create HTML for enhanced DynamoDB findings.
    """
    html = ""
    
    if 'dynamodb' not in scan_results:
        return html
    
    dynamodb_results = scan_results['dynamodb'].get('results', {})
    
    # Over-provisioned tables
    over_provisioned_tables = dynamodb_results.get('over_provisioned_tables', [])
    if over_provisioned_tables:
        html += '<div class="warning-box">'
        html += f'<h4>⚠️ {len(over_provisioned_tables)} DynamoDB Tables are Over-Provisioned</h4>'
        html += '<p>Over-provisioned tables may be incurring unnecessary costs.</p>'
        html += '</div>'
        
        html += '<h4>Over-Provisioned Tables</h4>'
        html += '<table>'
        html += '<tr><th>Table Name</th><th>Read Capacity</th><th>Write Capacity</th><th>Read Utilization (%)</th><th>Write Utilization (%)</th><th>Recommendation</th></tr>'
        
        for table in over_provisioned_tables:
            table_name = table.get('TableName', 'Unknown')
            read_capacity = table.get('ReadCapacityUnits', 'Unknown')
            write_capacity = table.get('WriteCapacityUnits', 'Unknown')
            read_utilization = f"{table.get('ReadUtilization', 0):.1f}%"
            write_utilization = f"{table.get('WriteUtilization', 0):.1f}%"
            
            recommended_read = table.get('RecommendedReadCapacity', 'Unknown')
            recommended_write = table.get('RecommendedWriteCapacity', 'Unknown')
            recommendation = f"Reduce to RCU: {recommended_read}, WCU: {recommended_write}"
            
            html += f'<tr><td>{table_name}</td><td>{read_capacity}</td><td>{write_capacity}</td><td>{read_utilization}</td><td>{write_utilization}</td><td>{recommendation}</td></tr>'
        
        html += '</table>'
    
    # Tables without Point-in-Time Recovery
    no_pitr_tables = dynamodb_results.get('no_pitr_tables', [])
    if no_pitr_tables:
        html += '<div class="warning-box">'
        html += f'<h4>⚠️ {len(no_pitr_tables)} DynamoDB Tables Have No Point-in-Time Recovery</h4>'
        html += '<p>Tables without PITR enabled may be at risk of data loss.</p>'
        html += '</div>'
        
        html += '<h4>Tables Without Point-in-Time Recovery</h4>'
        html += '<table>'
        html += '<tr><th>Table Name</th><th>Creation Date</th></tr>'
        
        for table in no_pitr_tables:
            table_name = table.get('TableName', 'Unknown')
            creation_date = table.get('CreationDateTime', 'Unknown')
            if creation_date != 'Unknown' and not isinstance(creation_date, str):
                try:
                    creation_date = creation_date.strftime('%Y-%m-%d %H:%M:%S')
                except:
                    pass
            
            html += f'<tr><td>{table_name}</td><td>{creation_date}</td></tr>'
        
        html += '</table>'
    
    # Tables without backups
    no_backup_tables = dynamodb_results.get('no_backup_tables', [])
    if no_backup_tables:
        html += '<div class="warning-box">'
        html += f'<h4>⚠️ {len(no_backup_tables)} DynamoDB Tables Have No Backups</h4>'
        html += '<p>Tables without backups may be at risk of data loss.</p>'
        html += '</div>'
        
        html += '<h4>Tables Without Backups</h4>'
        html += '<table>'
        html += '<tr><th>Table Name</th><th>Creation Date</th></tr>'
        
        for table in no_backup_tables:
            table_name = table.get('TableName', 'Unknown')
            creation_date = table.get('CreationDateTime', 'Unknown')
            if creation_date != 'Unknown' and not isinstance(creation_date, str):
                try:
                    creation_date = creation_date.strftime('%Y-%m-%d %H:%M:%S')
                except:
                    pass
            
            html += f'<tr><td>{table_name}</td><td>{creation_date}</td></tr>'
        
        html += '</table>'
    
    # Old tables
    old_tables = dynamodb_results.get('old_tables', [])
    if old_tables:
        html += '<div class="warning-box">'
        html += f'<h4>⚠️ {len(old_tables)} DynamoDB Tables are Over 1 Year Old</h4>'
        html += '<p>Old tables may contain outdated data or may no longer be needed.</p>'
        html += '</div>'
        
        html += '<h4>Old Tables</h4>'
        html += '<table>'
        html += '<tr><th>Table Name</th><th>Creation Date</th><th>Age (days)</th></tr>'
        
        for table in old_tables:
            table_name = table.get('TableName', 'Unknown')
            creation_date = table.get('CreationDateTime', 'Unknown')
            if creation_date != 'Unknown' and not isinstance(creation_date, str):
                try:
                    creation_date = creation_date.strftime('%Y-%m-%d %H:%M:%S')
                except:
                    pass
            age_days = table.get('AgeInDays', 'Unknown')
            
            html += f'<tr><td>{table_name}</td><td>{creation_date}</td><td>{age_days}</td></tr>'
        
        html += '</table>'
    
    return html
