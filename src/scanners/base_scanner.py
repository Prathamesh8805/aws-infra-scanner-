import boto3
from typing import Dict, Any, List, Optional
import logging

class BaseScanner:
    """Base class for all AWS resource scanners"""
    
    def __init__(self, region: str = "us-east-1", session: Optional[boto3.Session] = None):
        self.region = region
        self.session = session or boto3.Session(region_name=region)
        self.logger = logging.getLogger(self.__class__.__name__)
    
    def get_boto3_client(self, service_name: str):
        """Get a boto3 client for the specified service"""
        return self.session.client(service_name, region_name=self.region)
    
    def get_boto3_resource(self, service_name: str):
        """Get a boto3 resource for the specified service"""
        return self.session.resource(service_name, region_name=self.region)
    
    def scan(self) -> Dict[str, Any]:
        """
        Perform the scan operation. Must be implemented by subclasses.
        
        Returns:
            Dict containing scan results
        """
        raise NotImplementedError("Subclasses must implement scan method")
    
    def format_results(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """Format scan results for reporting"""
        return {
            "service": self.__class__.__name__.replace("Scanner", ""),
            "region": self.region,
            "results": results,
        }
