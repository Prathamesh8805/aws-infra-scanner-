from fastapi import FastAPI, BackgroundTasks, HTTPException
from pydantic import BaseModel
import os
from typing import Optional, List, Dict, Any
import uuid
import datetime

from src.scanners.eks_scanner import EKSScanner
from src.scanners.ec2_scanner import EC2Scanner
from src.scanners.vpc_scanner import VPCScanner
from src.scanners.dynamodb_scanner import DynamoDBScanner
from src.scanners.iam_scanner import IAMScanner
from src.scanners.cost_scanner import CostScanner
from src.reports.report_generator import generate_report

app = FastAPI(title="EKS Infrastructure Scanner")

class ScanRequest(BaseModel):
    environment: str
    region: str
    output_format: str = "html"
    output_path: str = "./reports"
    services: Optional[List[str]] = None

class ScanResponse(BaseModel):
    scan_id: str
    status: str
    report_path: Optional[str] = None

# Store scan results in memory
scan_results = {}

@app.post("/scan", response_model=ScanResponse)
async def start_scan(request: ScanRequest, background_tasks: BackgroundTasks):
    scan_id = str(uuid.uuid4())
    
    # Create output directory if it doesn't exist
    os.makedirs(request.output_path, exist_ok=True)
    
    # Define services to scan if not specified
    services = request.services or ["eks", "ec2", "vpc", "dynamodb", "iam", "cost"]
    
    # Start scan in background
    background_tasks.add_task(
        run_scan,
        scan_id=scan_id,
        environment=request.environment,
        region=request.region,
        output_format=request.output_format,
        output_path=request.output_path,
        services=services,
    )
    
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    report_filename = f"{request.environment}_{timestamp}.{request.output_format}"
    report_path = os.path.join(request.output_path, report_filename)
    
    return ScanResponse(
        scan_id=scan_id,
        status="running",
        report_path=report_path
    )

@app.get("/scan/{scan_id}", response_model=ScanResponse)
async def get_scan_status(scan_id: str):
    if scan_id not in scan_results:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    return ScanResponse(
        scan_id=scan_id,
        status=scan_results[scan_id]["status"],
        report_path=scan_results[scan_id].get("report_path")
    )

async def run_scan(
    scan_id: str,
    environment: str,
    region: str,
    output_format: str,
    output_path: str,
    services: List[str],
):
    results = {}
    
    try:
        # Run EKS scanner
        if "eks" in services:
            eks_scanner = EKSScanner(region=region)
            results["eks"] = eks_scanner.scan()
        
        # Run EC2 scanner
        if "ec2" in services:
            ec2_scanner = EC2Scanner(region=region)
            results["ec2"] = ec2_scanner.scan()
        
        # Run VPC scanner
        if "vpc" in services:
            vpc_scanner = VPCScanner(region=region)
            results["vpc"] = vpc_scanner.scan()
        
        # Run DynamoDB scanner
        if "dynamodb" in services:
            dynamodb_scanner = DynamoDBScanner(region=region)
            results["dynamodb"] = dynamodb_scanner.scan()
        
        # Run IAM scanner
        if "iam" in services:
            iam_scanner = IAMScanner(region=region)
            results["iam"] = iam_scanner.scan()
        
        # Run Cost scanner
        if "cost" in services:
            cost_scanner = CostScanner(region=region)
            results["cost"] = cost_scanner.scan()
        
        # Generate report
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        report_filename = f"{environment}_{timestamp}.{output_format}"
        report_path = os.path.join(output_path, report_filename)
        
        generate_report(
            results=results,
            output_path=report_path,
            format=output_format,
            environment=environment,
            region=region,
        )
        
        scan_results[scan_id] = {
            "status": "completed",
            "report_path": report_path,
            "results": results
        }
    except Exception as e:
        scan_results[scan_id] = {
            "status": "failed",
            "error": str(e)
        }
