from setuptools import setup, find_packages

setup(
    name="infra-scanner",
    version="0.2.0",
    description="AWS Infrastructure Scanner for EKS, EC2, VPC, DynamoDB, IAM, RDS, Lambda and more",
    author="Cloud Security Team",
    author_email="cloudsecurity@example.com",
    url="https://github.com/yourusername/infra-scanner",
    packages=find_packages(),
    include_package_data=True,
    install_requires=[
        "boto3>=1.28.53",
        "pydantic>=2.3.0",
        "typer>=0.9.0",
        "rich>=13.5.2",
        "reportlab>=4.0.4",
        "jinja2>=3.1.2",
        "weasyprint>=59.0",
        "requests>=2.31.0",
        "python-dotenv>=1.0.0",
        "pandas>=2.0.0",
        "plotly>=5.13.0",
    ],
    entry_points={
        "console_scripts": [
            "infra-scanner=src.main:app",
        ],
    },
    python_requires=">=3.8",
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: System Administrators",
        "Intended Audience :: Information Technology",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Topic :: System :: Systems Administration",
        "Topic :: Security",
    ],
)
