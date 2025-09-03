from typing import Dict, Any, List
from datetime import datetime, timezone, timedelta
from .base_scanner import BaseScanner

class IAMScanner(BaseScanner):
    """Scanner for IAM resources"""
    
    # Access key age threshold in days
    OLD_ACCESS_KEY_THRESHOLD_DAYS = 90
    
    def scan(self) -> Dict[str, Any]:
        """Scan IAM users, roles, and policies"""
        iam_client = self.get_boto3_client('iam')
        
        try:
            # Get all IAM users
            users_response = iam_client.list_users()
            users = users_response.get('Users', [])
            
            # Check for users with old access keys
            users_with_old_keys = []
            for user in users:
                user_name = user.get('UserName')
                
                # Get access keys for this user
                access_keys_response = iam_client.list_access_keys(UserName=user_name)
                access_keys = access_keys_response.get('AccessKeyMetadata', [])
                
                old_keys = []
                for key in access_keys:
                    if key.get('Status') == 'Active':
                        # Check key age
                        create_date = key.get('CreateDate')
                        if create_date:
                            key_age_days = (datetime.now(timezone.utc) - create_date).days
                            if key_age_days > self.OLD_ACCESS_KEY_THRESHOLD_DAYS:
                                old_keys.append({
                                    'AccessKeyId': key.get('AccessKeyId'),
                                    'CreateDate': create_date,
                                    'AgeDays': key_age_days
                                })
                
                if old_keys:
                    users_with_old_keys.append({
                        'UserName': user_name,
                        'UserId': user.get('UserId'),
                        'OldAccessKeys': old_keys
                    })
            
            # Get all IAM roles
            roles_response = iam_client.list_roles()
            roles = roles_response.get('Roles', [])
            
            # Find roles with overly permissive policies
            permissive_roles = self._find_permissive_roles(iam_client, roles)
            
            # Get all IAM policies
            policies_response = iam_client.list_policies(Scope='Local')
            policies = policies_response.get('Policies', [])
            
            # Find overly permissive policies
            permissive_policies = self._find_permissive_policies(iam_client, policies)
            
            # Get password policy
            try:
                password_policy = iam_client.get_account_password_policy()['PasswordPolicy']
            except iam_client.exceptions.NoSuchEntityException:
                password_policy = {'error': 'No password policy set'}
            
            return self.format_results({
                "users": users,
                "user_count": len(users),
                "users_with_old_keys": users_with_old_keys,
                "users_with_old_keys_count": len(users_with_old_keys),
                "roles": roles,
                "role_count": len(roles),
                "permissive_roles": permissive_roles,
                "permissive_role_count": len(permissive_roles),
                "policies": policies,
                "policy_count": len(policies),
                "permissive_policies": permissive_policies,
                "permissive_policy_count": len(permissive_policies),
                "password_policy": password_policy
            })
            
        except Exception as e:
            self.logger.error(f"Error scanning IAM resources: {str(e)}")
            return self.format_results({
                "error": str(e),
                "users": [],
                "user_count": 0,
                "roles": [],
                "role_count": 0,
                "policies": [],
                "policy_count": 0
            })
    
    def _find_permissive_roles(self, iam_client, roles: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Find IAM roles with overly permissive policies"""
        permissive_roles = []
        
        for role in roles:
            role_name = role.get('RoleName')
            
            # Check if role has admin access or overly permissive policies
            is_permissive = False
            permissive_statements = []
            
            # Check inline policies
            inline_policies_response = iam_client.list_role_policies(RoleName=role_name)
            inline_policy_names = inline_policies_response.get('PolicyNames', [])
            
            for policy_name in inline_policy_names:
                policy_response = iam_client.get_role_policy(
                    RoleName=role_name,
                    PolicyName=policy_name
                )
                
                # Check for "*" in Action and Resource
                policy_document = policy_response.get('PolicyDocument', {})
                for statement in policy_document.get('Statement', []):
                    action = statement.get('Action', [])
                    resource = statement.get('Resource', [])
                    effect = statement.get('Effect')
                    
                    if effect == 'Allow':
                        # Check for "*" in Action
                        if action == "*" or (isinstance(action, list) and "*" in action):
                            # Check for "*" in Resource
                            if resource == "*" or (isinstance(resource, list) and "*" in resource):
                                is_permissive = True
                                permissive_statements.append({
                                    'PolicyName': policy_name,
                                    'PolicyType': 'Inline',
                                    'Statement': statement
                                })
            
            # Check attached policies
            attached_policies_response = iam_client.list_attached_role_policies(RoleName=role_name)
            attached_policies = attached_policies_response.get('AttachedPolicies', [])
            
            for attached_policy in attached_policies:
                policy_arn = attached_policy.get('PolicyArn')
                
                # Check for known admin policies
                if 'AdministratorAccess' in policy_arn:
                    is_permissive = True
                    permissive_statements.append({
                        'PolicyName': attached_policy.get('PolicyName'),
                        'PolicyArn': policy_arn,
                        'PolicyType': 'Managed',
                        'Reason': 'Administrator Access'
                    })
            
            if is_permissive:
                permissive_roles.append({
                    'RoleName': role_name,
                    'RoleId': role.get('RoleId'),
                    'PermissiveStatements': permissive_statements
                })
        
        return permissive_roles
    
    def _find_permissive_policies(self, iam_client, policies: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Find overly permissive IAM policies"""
        permissive_policies = []
        
        for policy in policies:
            policy_arn = policy.get('Arn')
            policy_name = policy.get('PolicyName')
            
            # Get the default version of the policy
            policy_version_response = iam_client.get_policy(PolicyArn=policy_arn)
            default_version_id = policy_version_response['Policy']['DefaultVersionId']
            
            # Get the policy document
            policy_version = iam_client.get_policy_version(
                PolicyArn=policy_arn,
                VersionId=default_version_id
            )
            
            policy_document = policy_version['PolicyVersion']['Document']
            
            # Check for overly permissive statements
            is_permissive = False
            permissive_statements = []
            
            for statement in policy_document.get('Statement', []):
                action = statement.get('Action', [])
                resource = statement.get('Resource', [])
                effect = statement.get('Effect')
                
                if effect == 'Allow':
                    # Check for "*" in Action
                    if action == "*" or (isinstance(action, list) and "*" in action):
                        # Check for "*" in Resource
                        if resource == "*" or (isinstance(resource, list) and "*" in resource):
                            is_permissive = True
                            permissive_statements.append(statement)
            
            if is_permissive:
                permissive_policies.append({
                    'PolicyName': policy_name,
                    'PolicyArn': policy_arn,
                    'PermissiveStatements': permissive_statements
                })
        
        return permissive_policies
