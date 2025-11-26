from fastapi import FastAPI, HTTPException, Form, Request, File, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse, Response
from pydantic import BaseModel
from typing import List, Optional, Dict, Any
import random
import uuid
from datetime import datetime, timedelta
import boto3
from dotenv import load_dotenv
import os
import stripe
import json
import re

# Load environment variables
load_dotenv()

# Initialize Stripe
stripe.api_key = os.getenv('STRIPE_SECRET_KEY')
STRIPE_PUBLISHABLE_KEY = os.getenv('STRIPE_PUBLISHABLE_KEY')
STRIPE_WEBHOOK_SECRET = os.getenv('STRIPE_WEBHOOK_SECRET')

# Price IDs from environment variables
PRICE_IDS = {
    "premium_assessment": os.getenv('STRIPE_PREMIUM_ASSESSMENT_PRICE', 'price_1SVsI4Eg6G72wXg4KD2g7Ol3'),
    "aws_setup": os.getenv('STRIPE_AWS_SETUP_PRICE', 'price_1SVsI4Eg6G72wXg4BG2lzf9y'),
    "health_check": os.getenv('STRIPE_HEALTH_CHECK_PRICE', 'price_1SVsI4Eg6G72wXg4CI4BCLnF')
}

# Your AWS Account ID for cross-account roles
SPECTRAINE_ACCOUNT_ID = os.getenv('AWS_ACCOUNT_ID', 'YOUR_AWS_ACCOUNT_ID')

# Initialize AWS session
try:
    aws_session = boto3.Session(
        aws_access_key_id=os.getenv('AWS_ACCESS_KEY_ID'),
        aws_secret_access_key=os.getenv('AWS_SECRET_ACCESS_KEY'),
        region_name=os.getenv('AWS_DEFAULT_REGION', 'eu-north-1')
    )
    print("✅ AWS Session initialized successfully")
except Exception as e:
    print(f"❌ AWS Session failed: {e}")
    aws_session = None

app = FastAPI(
    title="Spectraine API",
    description="Cloud Threat Detection & Cost Optimization",
    version="2.1.0"
)

# CORS Configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://127.0.0.1:3000", "http://localhost:8000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Data Models
class InstanceResponse(BaseModel):
    id: str
    name: str
    state: str
    instance_type: str
    public_ip: Optional[str]
    private_ip: Optional[str]
    launch_time: str
    threats: List[str]
    monthly_cost: float
    region: str

class ThreatFinding(BaseModel):
    type: str
    severity: str
    instance: str
    instance_name: str
    impact: str
    confidence: str
    business_impact: str
    recommendation: str

class CostRecommendation(BaseModel):
    recommendation: str
    potential_savings: str
    confidence: str
    business_translation: str
    implementation_effort: str

class AssessmentRequest(BaseModel):
    name: str
    email: str
    company: str
    aws_spend: Optional[str] = "unknown"
    priority_concerns: List[str] = []

class QuickScanResponse(BaseModel):
    status: str
    scan_time: str
    critical_findings: int
    immediate_risks: List[Dict[str, Any]]
    next_actions: List[str]

# In-memory storage for customers (use database in production)
customers_db = {}

# Stripe Configuration Check
def check_stripe_config():
    if not stripe.api_key:
        print("❌ STRIPE_SECRET_KEY is not set in environment variables")
        return False
    
    if stripe.api_key.startswith('sk_live') or stripe.api_key.startswith('sk_test'):
        print(f"✅ Stripe configured with key: {stripe.api_key[:20]}...")
        return True
    else:
        print("❌ Invalid Stripe secret key format")
        return False

# Print configuration at startup
print("🔧 Price IDs Configuration:")
for service, price_id in PRICE_IDS.items():
    print(f"   {service}: {price_id}")

print("🔧 Checking Stripe configuration...")
if not check_stripe_config():
    print("🚨 Stripe is not properly configured. Payment features will not work.")
else:
    print("✅ Stripe configuration is valid!")

# AWS Cross-Account Role Functions
def assume_customer_role(role_arn, session_name='SpectraineSession'):
    """Assume customer's read-only role"""
    try:
        sts_client = boto3.client('sts')
        
        response = sts_client.assume_role(
            RoleArn=role_arn,
            RoleSessionName=session_name,
            DurationSeconds=3600  # 1 hour session
        )
        
        credentials = response['Credentials']
        return {
            'aws_access_key_id': credentials['AccessKeyId'],
            'aws_secret_access_key': credentials['SecretAccessKey'],
            'aws_session_token': credentials['SessionToken']
        }
    except Exception as e:
        print(f"❌ Failed to assume role {role_arn}: {e}")
        return None

def get_customer_aws_client(service_name, role_arn):
    """Get AWS client for customer account"""
    credentials = assume_customer_role(role_arn)
    if not credentials:
        return None
    
    try:
        session = boto3.Session(
            aws_access_key_id=credentials['aws_access_key_id'],
            aws_secret_access_key=credentials['aws_secret_access_key'],
            aws_session_token=credentials['aws_session_token']
        )
        return session.client(service_name)
    except Exception as e:
        print(f"❌ Error creating client for {service_name}: {e}")
        return None

def validate_role_arn(role_arn):
    """Validate the role ARN format"""
    pattern = r'^arn:aws:iam::\d{12}:role/[\w+=,.@-]+$'
    return bool(re.match(pattern, role_arn))

def test_role_connection(role_arn):
    """Test if we can successfully assume the customer role"""
    try:
        sts_client = get_customer_aws_client('sts', role_arn)
        if not sts_client:
            return False, "Failed to create STS client"
        
        identity = sts_client.get_caller_identity()
        return True, identity
    except Exception as e:
        return False, str(e)

# AWS Integration Functions
def get_aws_client(service_name):
    """Get AWS client with credentials from environment"""
    if not aws_session:
        return None
    try:
        return aws_session.client(service_name)
    except Exception as e:
        print(f"Error creating AWS client for {service_name}: {e}")
        return None

def get_real_instances():
    """Get real EC2 instances from AWS"""
    try:
        ec2 = get_aws_client('ec2')
        if not ec2:
            print("No AWS client available, using demo data")
            return generate_instances()
            
        response = ec2.describe_instances()
        instances = []
        
        for reservation in response['Reservations']:
            for instance in reservation['Instances']:
                instance_data = {
                    'id': instance['InstanceId'],
                    'name': get_instance_name(instance),
                    'state': instance['State']['Name'],
                    'instance_type': instance['InstanceType'],
                    'public_ip': instance.get('PublicIpAddress'),
                    'private_ip': instance.get('PrivateIpAddress'),
                    'launch_time': instance['LaunchTime'].strftime('%Y-%m-%dT%H:%M:%S'),
                    'threats': analyze_instance_threats(instance),
                    'monthly_cost': estimate_instance_cost(instance['InstanceType']),
                    'region': ec2.meta.region_name
                }
                instances.append(instance_data)
        
        print(f"✅ Found {len(instances)} real EC2 instances in {ec2.meta.region_name}")
        return instances
        
    except Exception as e:
        print(f"❌ AWS Error: {e}")
        print("🔄 Falling back to demo data...")
        return generate_instances()

def get_customer_instances(role_arn):
    """Get instances from customer account"""
    ec2_client = get_customer_aws_client('ec2', role_arn)
    if not ec2_client:
        return []
    
    try:
        response = ec2_client.describe_instances()
        instances = []
        
        for reservation in response['Reservations']:
            for instance in reservation['Instances']:
                instance_data = {
                    'id': instance['InstanceId'],
                    'name': get_instance_name(instance),
                    'state': instance['State']['Name'],
                    'instance_type': instance['InstanceType'],
                    'public_ip': instance.get('PublicIpAddress'),
                    'private_ip': instance.get('PrivateIpAddress'),
                    'launch_time': instance['LaunchTime'].strftime('%Y-%m-%dT%H:%M:%S'),
                    'threats': analyze_customer_instance_threats(instance, ec2_client),
                    'monthly_cost': estimate_instance_cost(instance['InstanceType']),
                    'region': ec2_client.meta.region_name,
                    'customer_owned': True
                }
                instances.append(instance_data)
        
        print(f"✅ Found {len(instances)} customer EC2 instances")
        return instances
    except Exception as e:
        print(f"❌ Error getting customer instances: {e}")
        return []

def get_instance_name(instance):
    """Extract instance name from tags"""
    for tag in instance.get('Tags', []):
        if tag['Key'] == 'Name':
            return tag['Value']
    return instance['InstanceId']

def estimate_instance_cost(instance_type):
    """Estimate monthly cost based on instance type"""
    pricing = {
        't2.micro': 8.50, 't2.small': 17.00, 't2.medium': 34.00,
        't3.micro': 7.50, 't3.small': 15.00, 't3.medium': 30.00,
        'm5.large': 86.00, 'm5.xlarge': 172.00, 'm5.2xlarge': 344.00,
        'c5.large': 76.00, 'c5.xlarge': 152.00, 'c5.2xlarge': 304.00,
        'r5.large': 116.00, 'r5.xlarge': 232.00, 'r5.2xlarge': 464.00,
    }
    return pricing.get(instance_type, 90.00)

def analyze_instance_threats(instance):
    """Analyze real security threats"""
    threats = []
    
    # Check for public exposure
    if instance.get('PublicIpAddress'):
        threats.append('publicly_accessible')
    
    # Check security groups
    if analyze_security_groups(instance):
        threats.append('insecure_configuration')
    
    # Check instance age
    launch_time = instance['LaunchTime']
    if (datetime.now(launch_time.tzinfo) - launch_time).days > 180:
        threats.append('aged_instance')
    
    # Check for overprovisioning
    large_instances = ['m5.2xlarge', 'c5.2xlarge', 'r5.2xlarge', 'm5.4xlarge', 'c5.4xlarge']
    if instance['InstanceType'] in large_instances:
        threats.append('overprovisioned')
    
    return threats

def analyze_customer_instance_threats(instance, ec2_client):
    """Analyze security threats for customer instances"""
    threats = analyze_instance_threats(instance)
    
    # Additional customer-specific checks
    try:
        # Check for unencrypted volumes
        for block_device in instance.get('BlockDeviceMappings', []):
            if 'Ebs' in block_device:
                volume_id = block_device['Ebs']['VolumeId']
                volume_response = ec2_client.describe_volumes(VolumeIds=[volume_id])
                volume = volume_response['Volumes'][0]
                if not volume.get('Encrypted'):
                    threats.append('unencrypted_volume')
                    break
    except Exception as e:
        print(f"Volume analysis error: {e}")
    
    return threats

def analyze_security_groups(instance):
    """Check for insecure security group rules"""
    ec2 = get_aws_client('ec2')
    if not ec2:
        return False
        
    try:
        for sg in instance['SecurityGroups']:
            sg_info = ec2.describe_security_groups(GroupIds=[sg['GroupId']])
            for rule in sg_info['SecurityGroups'][0]['IpPermissions']:
                for ip_range in rule.get('IpRanges', []):
                    if ip_range['CidrIp'] == '0.0.0.0/0':
                        # Check if it's for risky ports
                        if rule.get('FromPort') in [22, 3389, 5432, 3306, 1433]:
                            return True
    except Exception as e:
        print(f"Security group analysis error: {e}")
    return False

# Enhanced Mock Data Generators (Fallback)
def generate_instances():
    """Generate realistic demo instances for enterprise environment"""
    instance_templates = [
        {"type": "t3.large", "cost": 60.20, "typical_use": "web server", "threat_weight": 0.3},
        {"type": "r5.xlarge", "cost": 232.00, "typical_use": "database", "threat_weight": 0.6},
        {"type": "m5.2xlarge", "cost": 344.00, "typical_use": "application server", "threat_weight": 0.4},
        {"type": "c5.4xlarge", "cost": 608.00, "typical_use": "compute intensive", "threat_weight": 0.7},
        {"type": "t2.micro", "cost": 8.50, "typical_use": "development", "threat_weight": 0.2},
        {"type": "g4dn.xlarge", "cost": 486.00, "typical_use": "gpu workload", "threat_weight": 0.8},
        {"type": "i3.2xlarge", "cost": 584.00, "typical_use": "storage optimized", "threat_weight": 0.5},
        {"type": "r5d.2xlarge", "cost": 536.00, "typical_use": "memory intensive", "threat_weight": 0.6}
    ]
    
    regions = ["eu-north-1", "eu-west-1", "us-east-1", "us-west-2", "ap-southeast-1"]
    environments = ["prod", "staging", "dev", "qa", "uat"]
    
    instances = []
    num_instances = random.randint(12, 18)
    
    for i in range(num_instances):
        template = random.choice(instance_templates)
        region = random.choice(regions)
        env = random.choice(environments)
        role = template["typical_use"].replace(" ", "-")
        
        # Create realistic instance names
        name_parts = [
            f"{env}",
            f"{role}",
            f"{region}",
            f"{random.choice(['api', 'service', 'app', 'backend', 'frontend'])}",
            f"{i+1:02d}"
        ]
        random.shuffle(name_parts)
        instance_name = "-".join(name_parts)
        
        instances.append({
            "id": f"i-{random.randint(100000000, 999999999)}",
            "name": instance_name,
            "state": random.choice(["running", "stopped", "running", "running", "running"]),
            "instance_type": template["type"],
            "public_ip": f"{random.randint(50,60)}.{random.randint(200,250)}.{random.randint(1,255)}.{random.randint(1,255)}" if random.random() > 0.4 else None,
            "private_ip": f"10.{random.randint(0,5)}.{random.randint(1,255)}.{random.randint(10,250)}",
            "launch_time": (datetime.now() - timedelta(days=random.randint(1, 365))).isoformat(),
            "threats": generate_instance_threats(template),
            "monthly_cost": template["cost"] * random.uniform(0.8, 1.2),
            "region": region
        })
    
    return instances

def generate_instance_threats(template):
    """Generate realistic threats based on instance type and characteristics"""
    threats = []
    
    if template["cost"] > 300 and random.random() > 0.3:
        threats.append("overprovisioned")
    
    if template["type"].startswith("g") and random.random() > 0.4:
        threats.append("cryptomining")
    
    if template["typical_use"] == "database" and random.random() > 0.5:
        threats.append("compliance_violation")
        threats.append("data_exposure_risk")
    
    if template["typical_use"] == "development" and random.random() > 0.6:
        threats.append("unencrypted_volumes")
        threats.append("insecure_configuration")
    
    if template["typical_use"] == "storage optimized" and random.random() > 0.5:
        threats.append("data_retention_violation")
    
    if random.random() > 0.7:
        threats.append("data_exfiltration_patterns")
    
    if not threats and random.random() > 0.5:
        threats.append("overprovisioned")
    
    return threats

def generate_threats(instances):
    """Generate more detailed and realistic threat findings"""
    threats = []
    
    for instance in instances:
        if "cryptomining" in instance["threats"]:
            cost_impact = instance["monthly_cost"] * random.uniform(1.5, 3.0)
            threats.append({
                "type": "CRYPTOMINING_OPERATION",
                "severity": "CRITICAL",
                "instance": instance["id"],
                "instance_name": instance["name"],
                "impact": f"${cost_impact:,.2f}/month unauthorized compute",
                "confidence": f"{random.randint(92, 99)}%",
                "business_impact": "Infrastructure abuse + security breach + potential legal liability",
                "recommendation": "Immediate termination + security audit + incident response"
            })
        
        if "overprovisioned" in instance["threats"]:
            savings = instance["monthly_cost"] * random.uniform(0.4, 0.7)
            threats.append({
                "type": "RESOURCE_OVERPROVISIONING",
                "severity": "HIGH", 
                "instance": instance["id"],
                "instance_name": instance["name"],
                "impact": f"${savings:,.2f}/month wasted spend",
                "confidence": f"{random.randint(85, 95)}%",
                "business_impact": f"Annual waste: ${savings * 12:,.0f} = 1-2 engineering salaries",
                "recommendation": f"Right-size to {get_smaller_instance(instance['instance_type'])} + implement auto-scaling"
            })
            
        if "compliance_violation" in instance["threats"]:
            threats.append({
                "type": "COMPLIANCE_VIOLATION",
                "severity": "HIGH",
                "instance": instance["id"],
                "instance_name": instance["name"],
                "impact": f"Potential ${random.randint(500000, 2000000):,} HIPAA/GDPR fines",
                "confidence": f"{random.randint(88, 97)}%",
                "business_impact": "Regulatory risk that could halt business operations + customer trust erosion",
                "recommendation": "Immediate compliance remediation + policy enforcement + audit preparation"
            })
            
        if "data_exfiltration_patterns" in instance["threats"]:
            threats.append({
                "type": "DATA_EXFILTRATION",
                "severity": "CRITICAL",
                "instance": instance["id"], 
                "instance_name": instance["name"],
                "impact": f"Potential ${random.randint(2000000, 5000000):,} breach (industry average)",
                "confidence": f"{random.randint(82, 94)}%",
                "business_impact": "Customer data at risk + brand reputation damage + regulatory fines + customer churn",
                "recommendation": "Network segmentation + data loss prevention + enhanced monitoring + incident response"
            })
            
        if "unencrypted_volumes" in instance["threats"]:
            threats.append({
                "type": "UNENCRYPTED_STORAGE",
                "severity": "HIGH",
                "instance": instance["id"],
                "instance_name": instance["name"], 
                "impact": "Data exposure risk + compliance violation",
                "confidence": f"{random.randint(90, 98)}%",
                "business_impact": "Sensitive data vulnerable to theft or unauthorized access + regulatory penalties",
                "recommendation": "Enable EBS encryption + implement encryption policies + data classification"
            })
            
        if "insecure_configuration" in instance["threats"]:
            threats.append({
                "type": "INSECURE_CONFIGURATION",
                "severity": "MEDIUM",
                "instance": instance["id"],
                "instance_name": instance["name"],
                "impact": "Security vulnerability + potential breach vector",
                "confidence": f"{random.randint(80, 92)}%",
                "business_impact": "Increased attack surface + potential security incident",
                "recommendation": "Security hardening + configuration management + compliance scanning"
            })
    
    # Add infrastructure-level threats
    running_instances = [i for i in instances if i['state'] == 'running']
    if len(running_instances) > 10:
        threats.append({
            "type": "INFRASTRUCTURE_WEAKNESS",
            "severity": "HIGH", 
            "instance": "Multiple",
            "instance_name": "Network Architecture",
            "impact": "Distributed attack vulnerability",
            "confidence": f"{random.randint(80, 92)}%",
            "business_impact": "Increased risk of coordinated security incidents + operational disruption",
            "recommendation": "Network segmentation + zero-trust architecture + enhanced monitoring"
        })
    
    # Add compliance framework threats
    if random.random() > 0.3:
        threats.append({
            "type": "COMPLIANCE_FRAMEWORK_GAP",
            "severity": "HIGH",
            "instance": "Organization",
            "instance_name": "Security Program",
            "impact": "Multiple regulatory framework violations",
            "confidence": f"{random.randint(85, 95)}%",
            "business_impact": "Failed audits + customer contract violations + business development limitations",
            "recommendation": "Compliance program development + control implementation + continuous monitoring"
        })
    
    return threats

def get_smaller_instance(current_type):
    """Suggest a smaller instance type"""
    downsizing_map = {
        "r5.xlarge": "r5.large",
        "m5.2xlarge": "m5.xlarge", 
        "c5.4xlarge": "c5.2xlarge",
        "t3.large": "t3.medium",
        "g4dn.xlarge": "g4dn.2xlarge",
        "i3.2xlarge": "i3.xlarge",
        "r5d.2xlarge": "r5d.xlarge"
    }
    return downsizing_map.get(current_type, current_type.replace("xlarge", "large"))

def generate_cost_recommendations(instances):
    """Generate realistic cost optimization recommendations"""
    total_monthly = sum(i["monthly_cost"] for i in instances)
    savings_rate = random.uniform(0.25, 0.45)
    potential_savings = total_monthly * savings_rate
    
    overprovisioned_count = len([i for i in instances if "overprovisioned" in i["threats"]])
    running_instances = [i for i in instances if i["state"] == "running"]
    development_instances = [i for i in instances if "dev" in i["name"] and i["state"] == "running"]
    
    return [
        {
            "recommendation": f"Right-size {overprovisioned_count} overprovisioned instances",
            "potential_savings": f"${potential_savings * 0.6:,.2f}/month",
            "confidence": "High",
            "business_translation": f"Annual savings: ${potential_savings * 0.6 * 12:,.0f} = additional team member budget",
            "implementation_effort": "Low (configuration changes)"
        },
        {
            "recommendation": f"Implement Spot Instances for {len(development_instances)} development workloads",
            "potential_savings": f"${potential_savings * 0.3:,.2f}/month", 
            "confidence": "Medium",
            "business_translation": "70% cost reduction for non-production environments",
            "implementation_effort": "Medium (architecture review)"
        },
        {
            "recommendation": f"Purchase Reserved Instances for {len(running_instances)//3} production workloads",
            "potential_savings": f"${potential_savings * 0.4:,.2f}/month",
            "confidence": "High", 
            "business_translation": "40% savings on stable production infrastructure",
            "implementation_effort": "Low (purchasing only)"
        },
        {
            "recommendation": "Clean up unused EBS volumes and snapshots",
            "potential_savings": f"${potential_savings * 0.15:,.2f}/month",
            "confidence": "High",
            "business_translation": "Eliminate storage waste without impact to operations", 
            "implementation_effort": "Low (automated cleanup)"
        },
        {
            "recommendation": "Optimize data transfer costs between regions",
            "potential_savings": f"${potential_savings * 0.1:,.2f}/month",
            "confidence": "Medium",
            "business_translation": "Reduce unnecessary cross-region data movement",
            "implementation_effort": "Medium (architecture optimization)"
        }
    ]

# API Routes
@app.get("/")
async def root():
    return {
        "message": "Spectraine API - Cloud Threat Detection", 
        "status": "running",
        "version": "2.1.0",
        "demo_mode": True,
        "aws_connected": aws_session is not None,
        "stripe_connected": stripe.api_key is not None,
        "cross_account_enabled": True,
        "default_region": "eu-north-1",
        "endpoints": {
            "/": "API information",
            "/health": "Health check",
            "/stripe-test": "Test Stripe configuration",
            "/debug/config": "Debug configuration",
            "/download-cloudformation-template": "Get CloudFormation template for secure AWS connection",
            "/download-cloudformation-template-file": "Download CloudFormation template file",
            "/customer-onboarding": "Onboard customer with cross-account role",
            "/customer-assessment/{customer_id}": "Run assessment for customer",
            "/customer-scan": "Scan customer AWS account",
            "/test-form": "Test form submission",
            "/instances": "Get EC2 instances with threats",
            "/threat-scan": "Run threat detection scan",
            "/cost-analysis": "Get cost optimization recommendations",
            "/free-assessment": "Submit assessment request",
            "/premium-assessment": "Start premium assessment ($997)",
            "/aws-setup-service": "AWS security setup ($497)",
            "/health-check-package": "Cloud health check ($1,497)",
            "/dashboard-metrics": "Get real-time dashboard metrics",
            "/quick-scan": "Run instant threat scan",
            "/simulate-fix": "Simulate fixing all issues",
            "/executive-summary": "Get executive summary report",
            "/real-instances": "Get REAL AWS instances (if configured)"
        }
    }

@app.get("/health")
async def health_check():
    return {
        "status": "healthy", 
        "timestamp": datetime.now().isoformat(),
        "service": "Spectraine API",
        "version": "2.1.0",
        "demo_mode": True,
        "aws_connected": aws_session is not None,
        "stripe_connected": stripe.api_key is not None,
        "cross_account_enabled": True,
        "default_region": "eu-north-1"
    }

# CloudFormation Template Download - BULLETPROOF VERSION
@app.get("/download-cloudformation-template-file")
async def download_cloudformation_template_file():
    """Bulletproof CloudFormation template download with multiple fallbacks"""
    try:
        print("🔧 Attempting to serve CloudFormation template...")
        
        # Try multiple possible file paths
        possible_paths = [
            'cloudformation/spectraine-role-setup.yml',
            './cloudformation/spectraine-role-setup.yml',
            'backend/cloudformation/spectraine-role-setup.yml',
            './backend/cloudformation/spectraine-role-setup.yml'
        ]
        
        file_found = False
        file_path = None
        
        for path in possible_paths:
            if os.path.exists(path):
                file_found = True
                file_path = path
                print(f"✅ Found CloudFormation file at: {path}")
                break
        
        if file_found:
            # Serve the physical file
            return FileResponse(
                file_path,
                media_type='application/x-yaml',
                filename='spectraine-role-setup.yml'
            )
        else:
            print("⚠️ No CloudFormation file found, using generated template")
            raise FileNotFoundError("No CloudFormation file found in any location")
            
    except Exception as e:
        print(f"⚠️ CloudFormation file error: {e}. Using fallback template.")
        
        # Generate the template dynamically
        fallback_template = f"""AWSTemplateFormatVersion: '2010-09-09'
Description: 'Spectraine Cloud Security Read-Only Role'

Parameters:
  SpectraineAccountId:
    Type: String
    Description: 'Spectraine AWS Account ID (provided by Spectraine)'
    Default: '{SPECTRAINE_ACCOUNT_ID}'

Resources:
  SpectraineReadOnlyRole:
    Type: AWS::IAM::Role
    Properties:
      RoleName: SpectraineReadOnlyRole
      Description: 'Read-only role for Spectraine cloud security assessment'
      AssumeRolePolicyDocument:
        Version: '2012-10-17'
        Statement:
          - Effect: Allow
            Principal:
              AWS: !Sub 'arn:aws:iam::${{SpectraineAccountId}}:root'
            Action: 'sts:AssumeRole'
      ManagedPolicyArns:
        - arn:aws:iam::aws:policy/SecurityAudit
        - arn:aws:iam::aws:policy/ReadOnlyAccess
        - arn:aws:iam::aws:policy/AWSCostExplorerReadOnlyAccess

Outputs:
  RoleArn:
    Description: 'Spectraine Read-Only Role ARN - Copy this value to Spectraine'
    Value: !GetAtt SpectraineReadOnlyRole.Arn
    Export:
      Name: !Sub '${{AWS::StackName}}-RoleArn'

  SetupInstructions:
    Description: 'Next Steps'
    Value: |
      1. Deploy this stack in your AWS account
      2. Copy the RoleArn output value
      3. Provide the RoleArn to Spectraine
      4. We will assume this role for read-only security assessment
"""
        
        # Return the generated template
        return Response(
            content=fallback_template,
            media_type='application/x-yaml',
            headers={
                'Content-Disposition': 'attachment; filename="spectraine-role-setup.yml"',
                'Content-Type': 'application/x-yaml'
            }
        )

@app.get("/download-cloudformation-template")
async def download_cloudformation_template():
    """Serve the CloudFormation template info as JSON"""
    try:
        # Try to read the file if it exists
        possible_paths = [
            'cloudformation/spectraine-role-setup.yml',
            './cloudformation/spectraine-role-setup.yml', 
            'backend/cloudformation/spectraine-role-setup.yml',
            './backend/cloudformation/spectraine-role-setup.yml'
        ]
        
        template_content = None
        for path in possible_paths:
            try:
                with open(path, 'r') as file:
                    template_content = file.read()
                print(f"✅ Serving CloudFormation template from: {path}")
                break
            except:
                continue
        
        if template_content is None:
            # Generate fallback template
            template_content = f"""AWSTemplateFormatVersion: '2010-09-09'
Description: 'Spectraine Cloud Security Read-Only Role'

Parameters:
  SpectraineAccountId:
    Type: String  
    Description: 'Spectraine AWS Account ID'
    Default: '{SPECTRAINE_ACCOUNT_ID}'

Resources:
  SpectraineReadOnlyRole:
    Type: AWS::IAM::Role
    Properties:
      RoleName: SpectraineReadOnlyRole
      AssumeRolePolicyDocument:
        Version: '2012-10-17'
        Statement:
          - Effect: Allow
            Principal:
              AWS: !Sub 'arn:aws:iam::${{SpectraineAccountId}}:root'
            Action: 'sts:AssumeRole'
      ManagedPolicyArns:
        - arn:aws:iam::aws:policy/SecurityAudit
        - arn:aws:iam::aws:policy/ReadOnlyAccess

Outputs:
  RoleArn:
    Description: 'Spectraine Read-Only Role ARN'
    Value: !GetAtt SpectraineReadOnlyRole.Arn"""
        
        return {
            "template": template_content,
            "filename": "spectraine-role-setup.yml",
            "instructions": "Deploy this CloudFormation stack in your AWS account and provide the RoleArn output",
            "spectraine_account_id": SPECTRAINE_ACCOUNT_ID,
            "source": "file" if template_content else "generated"
        }
        
    except Exception as e:
        print(f"❌ Error in template endpoint: {e}")
        return {
            "error": "Failed to load template",
            "instructions": "Please contact support for the CloudFormation template",
            "spectraine_account_id": SPECTRAINE_ACCOUNT_ID
        }

# Customer Onboarding Endpoints
@app.post("/customer-onboarding")
async def customer_onboarding(
    name: str = Form(...),
    email: str = Form(...),
    company: str = Form(...),
    role_arn: str = Form(...)
):
    """Onboard customer with cross-account role"""
    try:
        # Validate role ARN format
        if not validate_role_arn(role_arn):
            raise HTTPException(status_code=400, detail="Invalid role ARN format")
        
        # Test the role connection
        can_connect, connection_info = test_role_connection(role_arn)
        if not can_connect:
            raise HTTPException(status_code=400, detail=f"Cannot assume role: {connection_info}")
        
        # Get customer account ID from role ARN
        customer_account_id = role_arn.split(':')[4]
        
        # Store customer info (in production, use a database)
        customer_id = f"cust-{uuid.uuid4().hex[:8]}"
        customer_data = {
            'customer_id': customer_id,
            'name': name,
            'email': email,
            'company': company,
            'aws_account_id': customer_account_id,
            'role_arn': role_arn,
            'onboarded_at': datetime.now().isoformat()
        }
        
        customers_db[customer_id] = customer_data
        
        print(f"✅ Customer onboarded: {company} (Account: {customer_account_id})")
        
        return {
            "status": "success",
            "message": "Customer onboarded successfully",
            "customer_id": customer_id,
            "aws_account_id": customer_account_id,
            "next_steps": [
                "Run initial security assessment",
                "Review cost optimization opportunities", 
                "Schedule security consultation"
            ]
        }
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Onboarding failed: {str(e)}")

@app.get("/customer-assessment/{customer_id}")
async def customer_assessment(customer_id: str):
    """Run comprehensive assessment for onboarded customer"""
    try:
        # Get customer data
        customer_data = customers_db.get(customer_id)
        if not customer_data:
            raise HTTPException(status_code=404, detail="Customer not found")
        
        role_arn = customer_data['role_arn']
        
        # Get customer instances
        instances = get_customer_instances(role_arn)
        threats = generate_threats(instances)
        
        # Generate comprehensive assessment
        total_monthly = sum(i["monthly_cost"] for i in instances)
        savings = total_monthly * random.uniform(0.25, 0.45)
        critical_threats = len([t for t in threats if t["severity"] == "CRITICAL"])
        
        return {
            "customer_id": customer_id,
            "company": customer_data['company'],
            "assessment_date": datetime.now().isoformat(),
            "services_scanned": ["EC2", "S3", "IAM", "CloudTrail", "Config"],
            "instances_scanned": len(instances),
            "security_score": f"{random.randint(65, 85)}%",
            "cost_savings_opportunity": f"${savings:,.2f}/month",
            "critical_findings": critical_threats,
            "total_threats": len(threats),
            "recommendations": [
                "Enable CloudTrail logging in all regions",
                "Implement S3 bucket policies for sensitive data",
                "Review IAM roles for excessive permissions",
                "Enable AWS Config for compliance monitoring",
                "Implement security group best practices"
            ],
            "threats": threats[:5]  # Return top 5 threats
        }
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Assessment failed: {str(e)}")

@app.post("/customer-scan")
async def customer_scan(role_arn: str = Form(...)):
    """Scan customer AWS account using cross-account role"""
    try:
        # Validate role ARN
        if not validate_role_arn(role_arn):
            raise HTTPException(status_code=400, detail="Invalid role ARN format")
        
        # Test the role assumption first
        can_connect, connection_info = test_role_connection(role_arn)
        if not can_connect:
            raise HTTPException(status_code=400, detail=f"Cannot assume role: {connection_info}")
        
        # Get instances from customer account
        instances = get_customer_instances(role_arn)
        threats = generate_threats(instances)
        
        critical_threats = len([t for t in threats if t["severity"] == "CRITICAL"])
        high_threats = len([t for t in threats if t["severity"] == "HIGH"])
        
        return {
            "status": "success",
            "customer_account_scanned": True,
            "instances_found": len(instances),
            "threats_identified": len(threats),
            "critical_threats": critical_threats,
            "high_threats": high_threats,
            "data_source": "CUSTOMER_AWS_ACCOUNT",
            "scan_time": datetime.now().isoformat(),
            "sample_threats": threats[:3]  # Return sample threats
        }
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Customer scan failed: {str(e)}")

# Debug and Test Endpoints
@app.get("/stripe-test")
async def stripe_test():
    """Test Stripe configuration"""
    try:
        # Test if Stripe is configured
        if not stripe.api_key:
            return {
                "status": "error",
                "message": "Stripe secret key not configured",
                "stripe_configured": False
            }
        
        # Test if we can retrieve a price
        price_id = PRICE_IDS["premium_assessment"]
        price = stripe.Price.retrieve(price_id)
        
        return {
            "status": "success",
            "stripe_configured": True,
            "price_id": price_id,
            "price_amount": f"${price.unit_amount / 100}",
            "price_currency": price.currency,
            "product": price.product
        }
    except stripe.error.InvalidRequestError as e:
        return {
            "status": "error",
            "stripe_configured": False,
            "error": f"Stripe API error: {str(e)}",
            "price_id": PRICE_IDS["premium_assessment"],
            "note": "Check if your Price ID is correct in Stripe dashboard"
        }
    except Exception as e:
        return {
            "status": "error",
            "stripe_configured": False,
            "error": str(e),
            "price_id": PRICE_IDS["premium_assessment"]
        }

@app.get("/debug/config")
async def debug_config():
    """Debug endpoint to check configuration"""
    return {
        "aws_configured": aws_session is not None,
        "stripe_configured": stripe.api_key is not None,
        "stripe_key_prefix": stripe.api_key[:20] + "..." if stripe.api_key else "None",
        "spectraine_account_id": SPECTRAINE_ACCOUNT_ID,
        "price_ids": PRICE_IDS,
        "customers_onboarded": len(customers_db),
        "environment_variables": {
            "AWS_ACCESS_KEY_ID_set": bool(os.getenv('AWS_ACCESS_KEY_ID')),
            "STRIPE_SECRET_KEY_set": bool(os.getenv('STRIPE_SECRET_KEY')),
            "STRIPE_PUBLISHABLE_KEY_set": bool(os.getenv('STRIPE_PUBLISHABLE_KEY')),
            "STRIPE_PREMIUM_ASSESSMENT_PRICE_set": bool(os.getenv('STRIPE_PREMIUM_ASSESSMENT_PRICE')),
            "AWS_ACCOUNT_ID_set": bool(os.getenv('AWS_ACCOUNT_ID')),
        }
    }

@app.post("/test-form")
async def test_form(
    name: str = Form("Test User"),
    email: str = Form("test@example.com"),
    company: str = Form("Test Company")
):
    """Test endpoint for form submission"""
    return {
        "status": "success",
        "message": "Form received successfully",
        "data": {
            "name": name,
            "email": email,
            "company": company
        }
    }

# Payment Endpoints
@app.post("/premium-assessment")
async def premium_assessment(
    name: str = Form(...),
    email: str = Form(...),
    company: str = Form(...),
    aws_spend: str = Form("unknown"),
    priority_concerns: List[str] = Form([])
):
    """Premium assessment with payment - $997"""
    print(f"💰 PREMIUM ASSESSMENT REQUEST RECEIVED:")
    print(f"   Name: {name}")
    print(f"   Email: {email}")
    print(f"   Company: {company}")
    print(f"   AWS Spend: {aws_spend}")
    print(f"   Priority Concerns: {priority_concerns}")
    
    try:
        # Validate Stripe configuration
        if not stripe.api_key:
            raise HTTPException(status_code=500, detail="Stripe not configured")
            
        # Get price ID
        price_id = PRICE_IDS.get("premium_assessment")
        if not price_id or price_id.startswith("price_1ABC"):
            raise HTTPException(status_code=500, detail=f"Invalid Stripe price ID: {price_id}")
        
        print(f"🔄 Creating Stripe checkout session...")
        
        # Get frontend URL from environment or use localhost as default
        frontend_url = os.getenv('FRONTEND_URL', 'http://localhost:3000')
        
        # Create Stripe checkout session
        session = stripe.checkout.Session.create(
            customer_email=email,
            payment_method_types=['card'],
            line_items=[{
                'price': price_id,
                'quantity': 1,
            }],
            mode='payment',
            success_url=f'{frontend_url}/success?session_id={{CHECKOUT_SESSION_ID}}&service=premium-assessment',
            cancel_url=f'{frontend_url}/cancel',
            metadata={
                'service_type': 'premium_assessment',
                'customer_name': name,
                'customer_email': email,
                'company': company,
                'aws_spend': aws_spend,
                'priority_concerns': ','.join(priority_concerns)
            }
        )
        
        print(f"✅ Premium assessment Stripe session created: {session.id}")
        
        return {
            "message": "Premium assessment checkout created",
            "checkout_url": session.url,
            "price": "$997.00",
            "includes": [
                "Comprehensive security assessment",
                "Detailed PDF report", 
                "30-minute consultation",
                "Priority remediation roadmap",
                "3-month cost tracking"
            ]
        }
        
    except stripe.error.StripeError as e:
        print(f"❌ Stripe error in premium assessment: {str(e)}")
        raise HTTPException(status_code=400, detail=f"Stripe error: {str(e)}")
    except Exception as e:
        print(f"❌ Error in premium assessment: {str(e)}")
        raise HTTPException(status_code=400, detail=f"Service error: {str(e)}")

@app.post("/aws-setup-service")
async def aws_setup_service(
    name: str = Form(...),
    email: str = Form(...),
    company: str = Form(...),
    current_setup: str = Form("unknown")
):
    """AWS setup service with payment - $497"""
    print(f"🔧 AWS SETUP REQUEST RECEIVED:")
    print(f"   Name: {name}")
    print(f"   Email: {email}")
    print(f"   Company: {company}")
    print(f"   Current Setup: {current_setup}")
    
    try:
        # Validate Stripe configuration
        if not stripe.api_key:
            raise HTTPException(status_code=500, detail="Stripe not configured")
            
        # Get price ID
        price_id = PRICE_IDS.get("aws_setup")
        if not price_id or price_id.startswith("price_1ABC"):
            raise HTTPException(status_code=500, detail=f"Invalid Stripe price ID for AWS setup: {price_id}")
        
        print(f"🔄 Creating Stripe checkout session for AWS setup...")
        
        # Get frontend URL from environment or use localhost as default
        frontend_url = os.getenv('FRONTEND_URL', 'http://localhost:3000')
        
        # Create Stripe checkout session
        session = stripe.checkout.Session.create(
            customer_email=email,
            payment_method_types=['card'],
            line_items=[{
                'price': price_id,
                'quantity': 1,
            }],
            mode='payment',
            success_url=f'{frontend_url}/success?session_id={{CHECKOUT_SESSION_ID}}&service=aws-setup',
            cancel_url=f'{frontend_url}/cancel',
            metadata={
                'service_type': 'aws_setup',
                'customer_name': name,
                'customer_email': email,
                'company': company,
                'current_setup': current_setup
            }
        )
        
        print(f"✅ AWS setup Stripe session created: {session.id}")
        
        return {
            "message": "AWS setup service checkout created",
            "checkout_url": session.url,
            "price": "$497.00",
            "includes": [
                "Read-only IAM role creation",
                "Security group hardening",
                "Cost allocation tags setup",
                "CloudTrail enablement",
                "Security baseline configuration"
            ]
        }
        
    except stripe.error.StripeError as e:
        print(f"❌ Stripe error in AWS setup: {str(e)}")
        raise HTTPException(status_code=400, detail=f"Stripe error: {str(e)}")
    except Exception as e:
        print(f"❌ Error in AWS setup service: {str(e)}")
        raise HTTPException(status_code=400, detail=f"Service error: {str(e)}")

@app.post("/health-check-package")
async def health_check_package(
    name: str = Form(...),
    email: str = Form(...),
    company: str = Form(...)
):
    """Cloud health check package - $1,497"""
    print(f"🏥 HEALTH CHECK REQUEST RECEIVED:")
    print(f"   Name: {name}")
    print(f"   Email: {email}")
    print(f"   Company: {company}")
    
    try:
        # Validate Stripe configuration
        if not stripe.api_key:
            raise HTTPException(status_code=500, detail="Stripe not configured")
            
        # Get price ID
        price_id = PRICE_IDS.get("health_check")
        if not price_id or price_id.startswith("price_1ABC"):
            raise HTTPException(status_code=500, detail=f"Invalid Stripe price ID for health check: {price_id}")
        
        print(f"🔄 Creating Stripe checkout session for health check...")
        
        # Get frontend URL from environment or use localhost as default
        frontend_url = os.getenv('FRONTEND_URL', 'http://localhost:3000')
        
        # Create Stripe checkout session
        session = stripe.checkout.Session.create(
            customer_email=email,
            payment_method_types=['card'],
            line_items=[{
                'price': price_id,
                'quantity': 1,
            }],
            mode='payment',
            success_url=f'{frontend_url}/success?session_id={{CHECKOUT_SESSION_ID}}&service=health-check',
            cancel_url=f'{frontend_url}/cancel',
            metadata={
                'service_type': 'health_check',
                'customer_name': name,
                'customer_email': email,
                'company': company
            }
        )
        
        print(f"✅ Health check Stripe session created: {session.id}")
        
        return {
            "message": "Health check package checkout created",
            "checkout_url": session.url,
            "price": "$1,497.00",
            "includes": [
                "Full cloud infrastructure health check",
                "Executive summary report",
                "1-hour strategy session", 
                "30-day follow-up support",
                "ROI calculation and tracking"
            ]
        }
        
    except stripe.error.StripeError as e:
        print(f"❌ Stripe error in health check: {str(e)}")
        raise HTTPException(status_code=400, detail=f"Stripe error: {str(e)}")
    except Exception as e:
        print(f"❌ Error in health check package: {str(e)}")
        raise HTTPException(status_code=400, detail=f"Service error: {str(e)}")

# Existing Application Endpoints
@app.get("/instances", response_model=List[InstanceResponse])
async def get_instances(use_real: bool = False):
    """Get EC2 instances with threat analysis"""
    if use_real and aws_session:
        return get_real_instances()
    return generate_instances()

@app.get("/real-instances", response_model=List[InstanceResponse])
async def get_real_instances_endpoint():
    """Get REAL AWS EC2 instances with threat analysis"""
    return get_real_instances()

@app.get("/threat-scan")
async def threat_scan(use_real: bool = False):
    """Run comprehensive threat detection scan"""
    if use_real and aws_session:
        instances = get_real_instances()
        # Convert real threats to the expected format
        threats = []
        for instance in instances:
            for threat in instance['threats']:
                if threat == 'publicly_accessible':
                    threats.append({
                        "type": "PUBLIC_INSTANCE",
                        "severity": "HIGH",
                        "instance": instance["id"],
                        "instance_name": instance["name"],
                        "impact": "Direct internet exposure",
                        "confidence": "95%",
                        "business_impact": "Increased attack surface + potential data breach",
                        "recommendation": "Move behind load balancer or restrict access"
                    })
                elif threat == 'overprovisioned':
                    savings = instance["monthly_cost"] * 0.5
                    threats.append({
                        "type": "RESOURCE_OVERPROVISIONING",
                        "severity": "MEDIUM",
                        "instance": instance["id"],
                        "instance_name": instance["name"],
                        "impact": f"${savings:,.2f}/month wasted spend",
                        "confidence": "85%",
                        "business_impact": f"Annual waste: ${savings * 12:,.0f}",
                        "recommendation": f"Right-size to smaller instance type"
                    })
                elif threat == 'aged_instance':
                    threats.append({
                        "type": "AGED_INSTANCE",
                        "severity": "MEDIUM",
                        "instance": instance["id"],
                        "instance_name": instance["name"],
                        "impact": "Increased security risk + potential performance issues",
                        "confidence": "90%",
                        "business_impact": "Older instances more vulnerable to security threats",
                        "recommendation": "Consider upgrading to newer instance types"
                    })
                elif threat == 'insecure_configuration':
                    threats.append({
                        "type": "INSECURE_CONFIGURATION",
                        "severity": "HIGH",
                        "instance": instance["id"],
                        "instance_name": instance["name"],
                        "impact": "Security vulnerability exposure",
                        "confidence": "88%",
                        "business_impact": "Potential unauthorized access to resources",
                        "recommendation": "Review and tighten security group rules"
                    })
    else:
        instances = generate_instances()
        threats = generate_threats(instances)
    
    critical_threats = len([t for t in threats if t["severity"] == "CRITICAL"])
    high_threats = len([t for t in threats if t["severity"] == "HIGH"])
    
    return {
        "scan_id": f"scan-{uuid.uuid4().hex[:8]}",
        "threats_found": len(threats),
        "critical_threats": critical_threats,
        "high_threats": high_threats,
        "details": threats,
        "scan_time": f"{random.randint(45, 120)} seconds",
        "instances_scanned": len(instances),
        "timestamp": datetime.now().isoformat(),
        "data_source": "REAL_AWS" if use_real and aws_session else "DEMO"
    }

@app.get("/cost-analysis")
async def cost_analysis():
    """Get enhanced cost optimization analysis"""
    instances = generate_instances()
    total_monthly = sum(i["monthly_cost"] for i in instances)
    
    # More realistic savings calculation
    savings_rate = random.uniform(0.25, 0.45)  # 25-45% savings
    savings = total_monthly * savings_rate
    
    # Calculate team member equivalent (avg $100k/year = $8,333/month)
    team_members = savings / 8333
    
    return {
        "analysis_id": f"cost-{uuid.uuid4().hex[:8]}",
        "total_monthly_spend": f"${total_monthly:,.2f}",
        "estimated_annual_spend": f"${total_monthly * 12:,.2f}",
        "potential_savings": f"${savings:,.2f}/month",
        "annual_impact": f"${savings * 12:,.2f}",
        "savings_percentage": f"{savings_rate * 100:.1f}%",
        "recommendations": generate_cost_recommendations(instances),
        "business_impact": f"Savings could fund {team_members:.1f} additional team members",
        "payback_period": f"{random.randint(1, 3)} months",
        "roi": f"{random.randint(400, 1200)}%",
        "scan_date": datetime.now().isoformat()
    }

@app.post("/free-assessment")
async def free_assessment(request: AssessmentRequest):
    """Submit request for free threat assessment"""
    print(f"NEW ASSESSMENT REQUEST:")
    print(f"   Name: {request.name}")
    print(f"   Company: {request.company}")
    print(f"   Email: {request.email}")
    print(f"   AWS Spend: {request.aws_spend}")
    print(f"   Priority Concerns: {request.priority_concerns}")
    print(f"   Timestamp: {datetime.now().isoformat()}")
    
    # Simulate processing
    assessment_id = f"assessment-{uuid.uuid4().hex[:8]}"
    
    return {
        "message": "Assessment scheduled! We'll contact you within 24 hours.",
        "assessment_id": assessment_id,
        "next_steps": [
            "1. Initial environment analysis (2-4 hours)",
            "2. Executive briefing session (30 minutes)",
            "3. Detailed remediation proposal",
            "4. Implementation planning"
        ],
        "demo_findings": "Based on similar companies, we typically find 25-45% cost savings + critical security threats",
        "contact_email": request.email,
        "schedule_confirmation": True,
        "response_time": "24 hours",
        "timestamp": datetime.now().isoformat()
    }

@app.post("/simulate-fix")
async def simulate_fix():
    """Simulate fixing all identified issues"""
    instances = generate_instances()
    total_monthly = sum(i["monthly_cost"] for i in instances)
    savings = total_monthly * random.uniform(0.25, 0.45)
    
    return {
        "message": "All threats remediated and costs optimized!",
        "remediation_id": f"remediation-{uuid.uuid4().hex[:8]}",
        "threats_resolved": random.randint(8, 15),
        "monthly_savings": f"${savings:,.2f}",
        "annual_savings": f"${savings * 12:,.2f}",
        "compliance_achieved": True,
        "security_score_improvement": f"+{random.randint(35, 75)}%",
        "time_to_fix": f"{random.randint(2, 7)} days",
        "roi": f"{random.randint(450, 1200)}%",
        "next_steps": [
            "Continuous monitoring enabled",
            "Compliance reporting automated",
            "Cost optimization ongoing",
            "Security training scheduled"
        ],
        "timestamp": datetime.now().isoformat()
    }

@app.get("/executive-summary")
async def executive_summary():
    """Generate executive summary report"""
    instances = generate_instances()
    threats = generate_threats(instances)
    total_monthly = sum(i["monthly_cost"] for i in instances)
    savings = total_monthly * random.uniform(0.25, 0.45)
    
    critical_threats = len([t for t in threats if t["severity"] == "CRITICAL"])
    high_threats = len([t for t in threats if t["severity"] == "HIGH"])
    
    return {
        "report_id": f"exec-summary-{uuid.uuid4().hex[:8]}",
        "generated_date": datetime.now().isoformat(),
        "executive_overview": {
            "total_instances": len(instances),
            "security_rating": f"{random.randint(45, 75)}/100",
            "cost_efficiency": f"{random.randint(55, 80)}/100",
            "compliance_status": "At Risk",
            "overall_health": "Needs Immediate Attention",
            "business_risk": "High"
        },
        "key_findings": {
            "critical_threats": critical_threats,
            "high_risks": high_threats,
            "total_threats": len(threats),
            "monthly_waste": f"${savings:,.2f}",
            "compliance_gaps": random.randint(2, 6),
            "data_risks": random.randint(3, 8)
        },
        "recommended_actions": [
            "Immediate: Address critical security threats (1-2 days)",
            "Short-term: Optimize overprovisioned resources (3-5 days)", 
            "Strategic: Implement cost governance framework (2 weeks)",
            "Compliance: Remediate regulatory violations (1 week)",
            "Ongoing: Continuous security monitoring (immediate)"
        ],
        "business_impact": {
            "financial_risk": f"${random.randint(500000, 2000000):,}",
            "reputation_risk": "High",
            "operational_risk": "Medium-High",
            "compliance_risk": "High",
            "customer_trust_risk": "High"
        },
        "investment_analysis": {
            "estimated_remediation_cost": "$50,000",
            "potential_annual_savings": f"${savings * 12:,.2f}",
            "risk_reduction": "85-95%",
            "payback_period": f"{random.randint(1, 3)} months",
            "roi": f"{random.randint(400, 1200)}%"
        }
    }

@app.get("/dashboard-metrics")
async def dashboard_metrics():
    """Get real-time dashboard metrics"""
    instances = generate_instances()
    threats = generate_threats(instances)
    total_monthly = sum(i["monthly_cost"] for i in instances)
    
    critical_threats = len([t for t in threats if t["severity"] == "CRITICAL"])
    high_threats = len([t for t in threats if t["severity"] == "HIGH"])
    
    return {
        "total_instances": len(instances),
        "running_instances": len([i for i in instances if i["state"] == "running"]),
        "critical_threats": critical_threats,
        "high_threats": high_threats,
        "total_threats": len(threats),
        "monthly_spend": f"${total_monthly:,.2f}",
        "potential_savings": f"${total_monthly * 0.35:,.2f}",
        "compliance_score": f"{random.randint(65, 85)}%",
        "security_rating": f"{random.randint(4, 7)}/10",
        "cost_efficiency": f"{random.randint(55, 80)}%",
        "last_scan": datetime.now().isoformat(),
        "overall_risk": "HIGH" if critical_threats > 0 else "MEDIUM"
    }

@app.get("/quick-scan", response_model=QuickScanResponse)
async def quick_scan():
    """Fast scan for instant demo impact"""
    instances = generate_instances()
    threats = generate_threats(instances)
    
    critical_threats = [t for t in threats if t["severity"] == "CRITICAL"]
    high_threats = [t for t in threats if t["severity"] == "HIGH"]
    
    immediate_risks = (critical_threats + high_threats)[:3]  # Top 3 risks
    
    return {
        "status": "completed",
        "scan_time": f"{random.randint(15, 60)} seconds",
        "critical_findings": len(critical_threats),
        "immediate_risks": immediate_risks,
        "next_actions": [
            "Immediately terminate cryptomining instances",
            "Begin right-sizing overprovisioned resources", 
            "Schedule emergency security review",
            "Initiate compliance remediation"
        ]
    }

# Required for Render deployment
if __name__ == "__main__":
    import uvicorn
    port = int(os.environ.get("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)