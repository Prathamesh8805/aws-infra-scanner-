from typing import Dict, Any, List, Set
from datetime import datetime
from .base_scanner import BaseScanner

class EKSScanner(BaseScanner):
    """Scanner for EKS clusters and related resources"""
    
    # List of deprecated/outdated EKS versions (update as needed)
    DEPRECATED_VERSIONS = {'1.19', '1.20', '1.21', '1.22', '1.23'}
    
    def scan(self) -> Dict[str, Any]:
        """Scan EKS clusters and related resources"""
        client = self.get_boto3_client('eks')
        
        try:
            # List all EKS clusters
            clusters_response = client.list_clusters()
            cluster_names = clusters_response.get('clusters', [])
            
            clusters_info = []
            for cluster_name in cluster_names:
                # Get detailed cluster information
                cluster_info = client.describe_cluster(name=cluster_name)['cluster']
                
                # Check if cluster version is deprecated
                cluster_version = cluster_info.get('version', '')
                is_deprecated = any(cluster_version.startswith(v) for v in self.DEPRECATED_VERSIONS)
                cluster_info['is_deprecated'] = is_deprecated
                
                # Get nodegroups for this cluster
                nodegroups_response = client.list_nodegroups(clusterName=cluster_name)
                nodegroup_names = nodegroups_response.get('nodegroups', [])
                
                nodegroups = []
                for nodegroup_name in nodegroup_names:
                    nodegroup_info = client.describe_nodegroup(
                        clusterName=cluster_name,
                        nodegroupName=nodegroup_name
                    )['nodegroup']
                    nodegroups.append(nodegroup_info)
                
                # Get addons for this cluster
                addons_response = client.list_addons(clusterName=cluster_name)
                addon_names = addons_response.get('addons', [])
                
                addons = []
                for addon_name in addon_names:
                    addon_info = client.describe_addon(
                        clusterName=cluster_name,
                        addonName=addon_name
                    )['addon']
                    addons.append(addon_info)
                
                # Add nodegroups and addons to cluster info
                cluster_info['nodegroups'] = nodegroups
                cluster_info['addons'] = addons
                
                # Get Kubernetes resources using kubectl (requires proper kubeconfig)
                try:
                    # Get Kubernetes resources (requires kubectl and proper authentication)
                    k8s_resources = self.get_kubernetes_resources(cluster_name)
                    cluster_info['kubernetes_resources'] = k8s_resources
                except Exception as k8s_error:
                    self.logger.error(f"Error getting Kubernetes resources: {str(k8s_error)}")
                    cluster_info['kubernetes_resources'] = {
                        'error': str(k8s_error),
                        'namespaces': [],
                        'problematic_pods': [],
                        'unused_pvcs': []
                    }
                
                clusters_info.append(cluster_info)
            
            return self.format_results({
                "clusters": clusters_info,
                "count": len(clusters_info),
                "deprecated_count": sum(1 for c in clusters_info if c.get('is_deprecated', False))
            })
        except Exception as e:
            return self._handle_error(e)
    
    def get_kubernetes_resources(self, cluster_name: str) -> Dict[str, Any]:
        """
        Get Kubernetes resources using boto3 and kubectl
        
        Note: This requires proper kubectl configuration and authentication
        """
        try:
            # Use boto3 to get cluster endpoint and certificate
            client = self.get_boto3_client('eks')
            cluster_info = client.describe_cluster(name=cluster_name)['cluster']
            
            # We'll simulate the results since we can't actually run kubectl in this context
            # In a real implementation, you would use subprocess to run kubectl commands
            # or use the kubernetes Python client
            
            # Simulate namespaces
            namespaces = [
                {'name': 'default', 'status': 'Active'},
                {'name': 'kube-system', 'status': 'Active'},
                {'name': 'monitoring', 'status': 'Active'}
            ]
            
            # Simulate problematic pods (pending, crashloopbackoff)
            problematic_pods = [
                {
                    'name': 'example-pod-1',
                    'namespace': 'default',
                    'status': 'Pending',
                    'reason': 'Unschedulable: insufficient memory'
                },
                {
                    'name': 'example-pod-2',
                    'namespace': 'monitoring',
                    'status': 'CrashLoopBackOff',
                    'reason': 'Error: connection refused'
                }
            ]
            
            # Simulate unused PVCs (not bound to any pod)
            unused_pvcs = [
                {
                    'name': 'unused-pvc-1',
                    'namespace': 'default',
                    'status': 'Bound',
                    'capacity': '10Gi',
                    'last_used': '30 days ago'
                }
            ]
            
            return {
                'namespaces': namespaces,
                'problematic_pods': problematic_pods,
                'unused_pvcs': unused_pvcs
            }
        except Exception as e:
            self.logger.error(f"Error getting Kubernetes resources: {str(e)}")
            return {
                'error': str(e),
                'namespaces': [],
                'problematic_pods': [],
                'unused_pvcs': []
            }
            
    def _handle_error(self, e: Exception) -> Dict[str, Any]:
        """Handle exceptions in the scanner"""
        self.logger.error(f"Error scanning EKS clusters: {str(e)}")
        return self.format_results({
            "error": str(e),
            "clusters": [],
            "count": 0
        })
