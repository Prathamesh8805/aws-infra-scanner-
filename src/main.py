#!/usr/bin/env python3
import os
import sys
import datetime
import boto3
import typer
from typing import Optional
from rich.console import Console
from rich.panel import Panel
from rich.prompt import Prompt, Confirm
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()
from src.scanners.eks_scanner import EKSScanner
from src.scanners.ec2_scanner import EC2Scanner
from src.scanners.vpc_scanner import VPCScanner
from src.scanners.dynamodb_scanner import DynamoDBScanner
from src.scanners.iam_scanner import IAMScanner
from src.scanners.cost_scanner import CostScanner
from src.scanners.rds_scanner import RDSScanner
from src.scanners.lambda_scanner import LambdaScanner
from src.reports.report_generator import generate_report
from src.reports.ai_report import generate_ai_enhanced_report
from src.dashboard.dashboard_generator import DashboardGenerator
from src.compliance.reporter import ComplianceReporter

app = typer.Typer(help="AWS Infrastructure Scanner")
console = Console()

def configure_aws_credentials(
    access_key: Optional[str] = None,
    secret_key: Optional[str] = None,
    region: str = "us-east-1",
    profile: Optional[str] = None
) -> boto3.Session:
    """
    Configure AWS credentials and return a boto3 session
    """
    # Check if credentials are provided as environment variables
    if not access_key:
        access_key = os.environ.get("AWS_ACCESS_KEY_ID")
    if not secret_key:
        secret_key = os.environ.get("AWS_SECRET_ACCESS_KEY")
    
    # If still not available, prompt the user
    if not access_key:
        access_key = Prompt.ask("Enter your AWS Access Key ID", password=True)
    if not secret_key:
        secret_key = Prompt.ask("Enter your AWS Secret Access Key", password=True)
    
    # Create and return a boto3 session
    if profile:
        return boto3.Session(profile_name=profile, region_name=region)
    else:
        return boto3.Session(
            aws_access_key_id=access_key,
            aws_secret_access_key=secret_key,
            region_name=region
        )

@app.command()
def scan(
    region: str = typer.Option("us-east-1", help="AWS region to scan"),
    profile: Optional[str] = typer.Option(None, help="AWS profile name to use"),
    access_key: Optional[str] = typer.Option(None, help="AWS access key ID"),
    secret_key: Optional[str] = typer.Option(None, help="AWS secret access key"),
    environment: str = typer.Option("dev", help="Environment name for the report"),
    output_format: str = typer.Option("html", help="Output format for report (html, pdf)"),
    output_path: str = typer.Option("./reports", help="Path to save the report"),
    services: str = typer.Option("all", help="Comma-separated list of services to scan (eks,ec2,vpc,dynamodb,iam,cost,rds,lambda) or 'all'"),
    ai_recommendations: bool = typer.Option(False, help="Enable AI-powered recommendations (with rule-based fallback)"),
    groq_api_key: str = typer.Option(None, help="Groq API key for AI recommendations"),
    interactive_dashboard: bool = typer.Option(False, help="Generate interactive dashboard with charts and graphs"),
    compliance_frameworks: bool = typer.Option(False, help="Include compliance framework mappings (CIS, NIST, AWS Well-Architected)"),
):
    """
    Scan AWS infrastructure and related services
    """
    console.print(Panel(f"Starting AWS Infrastructure Scan for [bold]{environment}[/bold] environment in [bold]{region}[/bold] region"))
    
    # Configure AWS credentials
    try:
        session = configure_aws_credentials(access_key, secret_key, region, profile)
        
        # Verify credentials
        sts_client = session.client('sts')
        caller_identity = sts_client.get_caller_identity()
        console.print(f"[green]Successfully authenticated as:[/green] {caller_identity['Arn']}")
        
    except Exception as e:
        console.print(f"[bold red]Error:[/bold red] Failed to configure AWS credentials: {str(e)}")
        sys.exit(1)
    
    # Process services parameter
    services_list = None
    if services.lower() != "all":
        services_list = [s.strip() for s in services.split(",")]
        console.print(f"Scanning selected services: {', '.join(services_list)}")
    else:
        services_list = ["eks", "ec2", "vpc", "dynamodb", "iam", "cost", "rds", "lambda"]
        console.print("Scanning all services")
    
    # Create output directory if it doesn't exist
    os.makedirs(output_path, exist_ok=True)
    
    # Run scanners directly
    console.print("Starting scan process...")
    
    scan_results = {
        "timestamp": datetime.datetime.now().isoformat(),
        "environment": environment,
        "region": region
    }
    
    try:
        # Run EKS scanner
        if "eks" in services_list:
            console.print("Scanning EKS resources...")
            eks_scanner = EKSScanner(region=region, session=session)
            scan_results["eks"] = eks_scanner.scan()
        
        # Run EC2 scanner
        if "ec2" in services_list:
            console.print("Scanning EC2 resources...")
            ec2_scanner = EC2Scanner(region=region, session=session)
            scan_results["ec2"] = ec2_scanner.scan()
        
        # Run VPC scanner
        if "vpc" in services_list:
            console.print("Scanning VPC resources...")
            vpc_scanner = VPCScanner(region=region, session=session)
            scan_results["vpc"] = vpc_scanner.scan()
        
        # Run DynamoDB scanner
        if "dynamodb" in services_list:
            console.print("Scanning DynamoDB resources...")
            dynamodb_scanner = DynamoDBScanner(region=region, session=session)
            scan_results["dynamodb"] = dynamodb_scanner.scan()
        
        # Run IAM scanner
        if "iam" in services_list:
            console.print("Scanning IAM resources...")
            iam_scanner = IAMScanner(region=region, session=session)
            scan_results["iam"] = iam_scanner.scan()
        
        # Run Cost scanner
        if "cost" in services_list:
            console.print("Scanning Cost resources...")
            cost_scanner = CostScanner(region=region, session=session)
            scan_results["cost"] = cost_scanner.scan()
        
        # Run RDS scanner
        if "rds" in services_list:
            console.print("Scanning RDS resources...")
            rds_scanner = RDSScanner(region=region, session=session)
            scan_results["rds"] = rds_scanner.scan()
        
        # Run Lambda scanner
        if "lambda" in services_list:
            console.print("Scanning Lambda resources...")
            lambda_scanner = LambdaScanner(region=region, session=session)
            scan_results["lambda"] = lambda_scanner.scan()
        
        # Generate compliance report if requested
        if compliance_frameworks:
            console.print("Generating compliance framework mappings...")
            try:
                compliance_report = ComplianceReporter.generate_compliance_report(scan_results)
                scan_results["compliance"] = compliance_report
            except Exception as e:
                console.print(f"[bold red]Error generating compliance report:[/bold red] {str(e)}")
                # Print scan_results keys for debugging
                console.print(f"Scan results keys: {list(scan_results.keys())}")
                for key in scan_results:
                    console.print(f"Type of {key}: {type(scan_results[key])}")
                    if isinstance(scan_results[key], dict) and "error" in scan_results[key]:
                        console.print(f"Error in {key}: {scan_results[key]['error']}")
                    elif key in ['lambda', 'dynamodb', 'rds']:
                        console.print(f"Value of {key}: {scan_results[key]}")
                # Continue without compliance report
                scan_results["compliance"] = {
                    "summary": {"frameworks": {"cis": {"name": "CIS Controls v8", "controls_affected": [], "count": 0}, 
                                             "nist": {"name": "NIST 800-53 Rev 5", "controls_affected": [], "count": 0},
                                             "aws_waf": {"name": "AWS Well-Architected Framework", "pillars_affected": [], "pillar_counts": {}, "count": 0}}},
                    "detailed_findings": []
                }
        
        # Generate report
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        report_filename = f"{environment}_{timestamp}.{output_format}"
        report_path = os.path.join(output_path, report_filename)
        
        console.print("Generating report...")
        
        # If interactive dashboard is requested, use that instead of regular report
        if interactive_dashboard:
            # Process AI recommendations if requested
            if ai_recommendations:
                if not groq_api_key:
                    groq_api_key = os.environ.get("GROQ_API_KEY")
                    if not groq_api_key:
                        console.print("[yellow]Warning: No Groq API key provided. Falling back to rule-based recommendations.[/yellow]")
            
            # Generate the enhanced interactive report with all details
            console.print("Generating enhanced interactive report with findings and recommendations...")
            dashboard_generator = DashboardGenerator()
            dashboard_generator.generate_dashboard(
                scan_results=scan_results,
                output_path=report_path,
                environment=environment,
                region=region,
                ai_key=groq_api_key if ai_recommendations else None
            )
        else:
            # Generate regular report
            if ai_recommendations:
                if not groq_api_key:
                    groq_api_key = os.environ.get("GROQ_API_KEY")
                    if not groq_api_key:
                        console.print("[yellow]Warning: No Groq API key provided. Falling back to rule-based recommendations.[/yellow]")
                
                console.print("Generating AI-enhanced report with Groq recommendations (with rule-based fallback)...")
                generate_ai_enhanced_report(
                    scan_results=scan_results,
                    output_path=report_path,
                    format=output_format,
                    environment=environment,
                    region=region,
                    api_key=groq_api_key
                )
            else:
                generate_report(
                    results=scan_results,
                    output_path=report_path,
                    format=output_format,
                    environment=environment,
                    region=region,
                )
        

        console.print(f"[bold green]Scan completed successfully![/bold green]")
        console.print(f"Report saved to: {report_path}")
    except Exception as e:
        console.print(f"[bold red]Error:[/bold red] {str(e)}")

if __name__ == "__main__":
    app()
