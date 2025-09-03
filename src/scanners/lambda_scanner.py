from typing import Dict, Any, List
from .base_scanner import BaseScanner

class LambdaScanner(BaseScanner):
    """Scanner for Lambda functions and related resources"""
    
    # Memory threshold for potential over-provisioning (MB)
    MEMORY_THRESHOLD = 1024
    
    # Timeout threshold for potential issues (seconds)
    TIMEOUT_THRESHOLD = 60
    
    def scan(self) -> Dict[str, Any]:
        """Scan Lambda functions and related resources"""
        try:
            lambda_client = self.get_boto3_client('lambda')
            iam_client = self.get_boto3_client('iam')
            cloudwatch_client = self.get_boto3_client('cloudwatch')
            
            # Get all Lambda functions
            functions = []
            marker = None
            
            while True:
                if marker:
                    response = lambda_client.list_functions(Marker=marker)
                else:
                    response = lambda_client.list_functions()
                
                functions.extend(response.get('Functions', []))
                
                if 'NextMarker' in response:
                    marker = response['NextMarker']
                else:
                    break
            
            # Process functions for analysis
            processed_functions = []
            high_memory_functions = []
            high_timeout_functions = []
            no_vpc_functions = []
            no_dlq_functions = []
            outdated_runtime_functions = []
            
            # Define outdated runtimes
            outdated_runtimes = [
                'nodejs10.x', 'nodejs8.10', 'nodejs6.10', 'nodejs4.3',
                'python2.7', 'python3.6', 'python3.7',
                'ruby2.5',
                'java8',
                'dotnetcore2.1', 'dotnetcore2.0', 'dotnetcore1.0'
            ]
            
            for function in functions:
                function_name = function.get('FunctionName')
                runtime = function.get('Runtime')
                memory_size = function.get('MemorySize', 0)
                timeout = function.get('Timeout', 0)
                
                # Check if function has VPC configuration
                vpc_config = function.get('VpcConfig', {})
                has_vpc = bool(vpc_config.get('VpcId')) if vpc_config else False
                
                # Check if function has Dead Letter Queue
                dead_letter_config = function.get('DeadLetterConfig', {})
                has_dlq = bool(dead_letter_config.get('TargetArn')) if dead_letter_config else False
                
                # Get function policy
                try:
                    policy_response = lambda_client.get_policy(FunctionName=function_name)
                    policy = policy_response.get('Policy')
                except Exception:
                    policy = None
                
                # Check for high memory allocation
                if memory_size >= self.MEMORY_THRESHOLD:
                    high_memory_functions.append(function)
                
                # Check for high timeout
                if timeout >= self.TIMEOUT_THRESHOLD:
                    high_timeout_functions.append(function)
                
                # Check for functions without VPC
                if not has_vpc:
                    no_vpc_functions.append(function)
                
                # Check for functions without DLQ
                if not has_dlq:
                    no_dlq_functions.append(function)
                
                # Check for outdated runtimes
                if runtime in outdated_runtimes:
                    outdated_runtime_functions.append(function)
                
                # Get metrics for the function
                # In a real implementation, we'd get actual CloudWatch metrics
                # For this example, we'll use simulated values
                metrics = self._get_function_metrics(cloudwatch_client, function_name)
                
                # Process function for the report
                processed_function = {
                    'FunctionName': function_name,
                    'Runtime': runtime,
                    'MemorySize': memory_size,
                    'Timeout': timeout,
                    'HasVPC': has_vpc,
                    'HasDLQ': has_dlq,
                    'LastModified': function.get('LastModified'),
                    'CodeSize': function.get('CodeSize'),
                    'Description': function.get('Description'),
                    'Environment': function.get('Environment', {}).get('Variables', {}),
                    'Metrics': metrics,
                    'PublicAccess': self._check_public_access(policy)
                }
                
                processed_functions.append(processed_function)
            
            # Get all Lambda layers
            layers = []
            marker = None
            
            while True:
                if marker:
                    response = lambda_client.list_layers(Marker=marker)
                else:
                    response = lambda_client.list_layers()
                
                layers.extend(response.get('Layers', []))
                
                if 'NextMarker' in response:
                    marker = response['NextMarker']
                else:
                    break
            
            # Get all Lambda event source mappings
            event_source_mappings = []
            marker = None
            
            while True:
                if marker:
                    response = lambda_client.list_event_source_mappings(Marker=marker)
                else:
                    response = lambda_client.list_event_source_mappings()
                
                event_source_mappings.extend(response.get('EventSourceMappings', []))
                
                if 'NextMarker' in response:
                    marker = response['NextMarker']
                else:
                    break
            
            return self.format_results({
                "functions": processed_functions,
                "function_count": len(functions),
                "high_memory_functions": [f.get('FunctionName') for f in high_memory_functions],
                "high_memory_function_count": len(high_memory_functions),
                "high_timeout_functions": [f.get('FunctionName') for f in high_timeout_functions],
                "high_timeout_function_count": len(high_timeout_functions),
                "no_vpc_functions": [f.get('FunctionName') for f in no_vpc_functions],
                "no_vpc_function_count": len(no_vpc_functions),
                "no_dlq_functions": [f.get('FunctionName') for f in no_dlq_functions],
                "no_dlq_function_count": len(no_dlq_functions),
                "outdated_runtime_functions": [f.get('FunctionName') for f in outdated_runtime_functions],
                "outdated_runtime_function_count": len(outdated_runtime_functions),
                "layers": layers,
                "layer_count": len(layers),
                "event_source_mappings": event_source_mappings,
                "event_source_mapping_count": len(event_source_mappings)
            })
        except Exception as e:
            self.logger.error(f"Error scanning Lambda resources: {str(e)}")
            return self.format_results({
                "error": str(e),
                "functions": [],
                "function_count": 0,
                "layers": [],
                "layer_count": 0,
                "event_source_mappings": [],
                "event_source_mapping_count": 0
            })
    
    def _get_function_metrics(self, cloudwatch_client, function_name: str) -> Dict[str, Any]:
        """Get metrics for a Lambda function"""
        # In a real implementation, we would query CloudWatch metrics
        # For this example, we'll return simulated values
        import random
        
        return {
            "Invocations": random.randint(0, 10000),
            "Errors": random.randint(0, 100),
            "Throttles": random.randint(0, 50),
            "Duration": random.randint(10, 5000),  # milliseconds
            "ConcurrentExecutions": random.randint(1, 100)
        }
    
    def _check_public_access(self, policy: str) -> bool:
        """Check if a Lambda function has public access"""
        if not policy:
            return False
        
        import json
        try:
            policy_json = json.loads(policy)
            statements = policy_json.get('Statement', [])
            
            for statement in statements:
                principal = statement.get('Principal', {})
                
                # Check for public access ("*" principal)
                if principal == "*" or principal.get('AWS') == "*":
                    return True
                
                # Check for public access via service principals
                if isinstance(principal, dict) and 'Service' in principal:
                    service = principal['Service']
                    if isinstance(service, list) and 'apigateway.amazonaws.com' in service:
                        return True
                    elif service == 'apigateway.amazonaws.com':
                        return True
            
            return False
        except Exception:
            return False
