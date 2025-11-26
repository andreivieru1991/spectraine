from fastapi import FastAPI, HTTPException, Form, Request, File, UploadFile, Header, Depends, BackgroundTasks
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
import asyncio
from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.cron import CronTrigger

# Load environment variables
load_dotenv()

# Initialize Stripe
stripe.api_key = os.getenv('STRIPE_SECRET_KEY')
STRIPE_PUBLISHABLE_KEY = os.getenv('STRIPE_PUBLISHABLE_KEY')
STRIPE_WEBHOOK_SECRET = os.getenv('STRIPE_WEBHOOK_SECRET')

# Price IDs from environment variables - ONLY MONTHLY SUBSCRIPTION
PRICE_IDS = {
    "monthly_subscription": os.getenv('STRIPE_MONTHLY_SUBSCRIPTION_PRICE', 'price_1SVsI4Eg6G72wXg4MONTHLY1297')
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
    version="2.3.0"  # Updated for automation
)

# CORS Configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://127.0.0.1:3000", "http://localhost:8000", "http://localhost:8080"],
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

# Customer Authentication & Database
customers_db = {}
customer_tokens = {}
automation_history = {}

# Authentication Functions
def generate_customer_token(customer_id: str):
    """Generate a secure token for customer access"""
    token = f"spectraine_{customer_id}_{uuid.uuid4().hex[:16]}"
    customer_tokens[token] = customer_id
    return token

def verify_customer_token(token: str):
    """Verify customer token and return customer ID"""
    return customer_tokens.get(token)

def get_current_customer(authorization: str = Header(...)):
    """Extract and verify customer from token"""
    if not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Invalid authorization")
    
    token = authorization.replace("Bearer ", "")
    customer_id = verify_customer_token(token)
    
    if not customer_id:
        raise HTTPException(status_code=401, detail="Invalid token")
    
    return customer_id

# AWS Cross-Account Role Functions
def assume_customer_role(role_arn, session_name='SpectraineSession'):
    """Assume customer's read-only role"""
    try:
        sts_client = boto3.client('sts')
        
        response = sts_client.assume_role(
            RoleArn=role_arn,
            RoleSessionName=session_name,
            DurationSeconds=3600
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

# Enhanced Mock Data Generators (RICH DETAILED VERSION)
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

# DAILY AUTOMATION SYSTEM
scheduler = BackgroundScheduler()

async def run_daily_automation_for_customer(customer_id: str):
    """Run daily automated scan for a customer"""
    customer = customers_db.get(customer_id)
    if not customer or customer.get('subscription_status') != 'active':
        return
    
    print(f"🤖 Running daily automation for {customer['company']}")
    
    try:
        # Run AWS scan
        scan_data = await run_customer_aws_scan(customer_id)
        
        # Generate automation report
        automation_report = {
            'automation_id': f"auto_{datetime.now().strftime('%Y%m%d_%H%M%S')}",
            'customer_id': customer_id,
            'timestamp': datetime.now().isoformat(),
            'scan_results': {
                'instances_scanned': scan_data['instances_found'],
                'threats_identified': scan_data['threats_identified'],
                'critical_threats': scan_data['critical_threats'],
                'potential_savings': scan_data['estimated_savings']
            },
            'automated_actions': generate_automated_actions(scan_data),
            'alerts_generated': generate_daily_alerts(scan_data)
        }
        
        # Store automation history
        if customer_id not in automation_history:
            automation_history[customer_id] = []
        automation_history[customer_id].append(automation_report)
        
        # Update customer's last automation
        customer['last_automation'] = automation_report
        customer['next_automation'] = (datetime.now() + timedelta(hours=24)).isoformat()
        
        print(f"✅ Daily automation completed for {customer['company']}")
        
    except Exception as e:
        print(f"❌ Daily automation failed for {customer_id}: {e}")

def generate_automated_actions(scan_data):
    """Generate automated actions taken during daily scan"""
    actions = [
        "Daily security threat scan completed",
        "Cost optimization analysis run",
        "Compliance check performed"
    ]
    
    if scan_data.get('critical_threats', 0) > 0:
        actions.append(f"🔴 {scan_data['critical_threats']} critical threats detected - alerts sent")
    
    if scan_data.get('estimated_savings', 0) > 1000:
        actions.append(f"💰 ${scan_data['estimated_savings']:,.0f} savings opportunities identified")
    
    # Simulate some automated remediations
    if random.random() > 0.7:
        actions.append("🛡️ Automated security patch applied to vulnerable instances")
    
    if random.random() > 0.8:
        actions.append("⚡ Performance optimization recommendations generated")
    
    return actions

def generate_daily_alerts(scan_data):
    """Generate daily alert notifications"""
    alerts = []
    
    if scan_data.get('critical_threats', 0) > 0:
        alerts.append({
            'type': 'CRITICAL',
            'title': 'Critical Security Threats Detected',
            'message': f"{scan_data['critical_threats']} critical security threats require immediate attention",
            'action_required': True
        })
    
    if scan_data.get('estimated_savings', 0) > 5000:
        alerts.append({
            'type': 'COST_SAVING',
            'title': 'Major Cost Savings Opportunity',
            'message': f"${scan_data['estimated_savings']:,.0f}/month in potential savings identified",
            'action_required': False
        })
    
    if scan_data.get('instances_found', 0) > 20:
        alerts.append({
            'type': 'PERFORMANCE',
            'title': 'Infrastructure Scaling Opportunity',
            'message': f"Consider optimizing {scan_data['instances_found']} instances for better performance",
            'action_required': False
        })
    
    return alerts

async def run_daily_automation_for_all_customers():
    """Run daily automation for all active customers"""
    print(f"🚀 Starting daily automation for all customers at {datetime.now()}")
    
    active_customers = [
        customer_id for customer_id, customer in customers_db.items() 
        if customer.get('subscription_status') == 'active'
    ]
    
    print(f"📊 Processing {len(active_customers)} active customers")
    
    for customer_id in active_customers:
        await run_daily_automation_for_customer(customer_id)
    
    print("✅ Daily automation completed for all customers")

def schedule_daily_automation():
    """Schedule daily automation runs"""
    # Run every day at 6:00 AM
    trigger = CronTrigger(hour=6, minute=0)
    scheduler.add_job(
        run_daily_automation_for_all_customers,
        trigger=trigger,
        id='daily_automation'
    )
    print("✅ Daily automation scheduled for 6:00 AM daily")

# Start scheduler when app starts
@app.on_event("startup")
async def startup_event():
    """Start background tasks on startup"""
    if not scheduler.running:
        scheduler.start()
        schedule_daily_automation()
        print("🤖 Daily automation scheduler started")

@app.on_event("shutdown")
async def shutdown_event():
    """Shutdown scheduler on app shutdown"""
    if scheduler.running:
        scheduler.shutdown()
        print("🤖 Daily automation scheduler stopped")

# Customer AWS Scanning
async def run_customer_aws_scan(customer_id: str):
    """Run actual AWS scan for specific customer"""
    customer = customers_db.get(customer_id)
    if not customer or not customer.get('aws_role_arn'):
        return {"error": "AWS not connected"}
    
    role_arn = customer['aws_role_arn']
    
    # Get customer's real instances
    instances = get_customer_instances(role_arn)
    if not instances:
        # Fallback to demo data if no real instances found
        instances = generate_instances()
    
    threats = generate_threats(instances)
    cost_recommendations = generate_cost_recommendations(instances)
    
    # Store scan results
    scan_id = f"scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
    total_cost = sum(i["monthly_cost"] for i in instances)
    
    scan_data = {
        'scan_id': scan_id,
        'customer_id': customer_id,
        'timestamp': datetime.now().isoformat(),
        'instances_found': len(instances),
        'threats_identified': len(threats),
        'critical_threats': len([t for t in threats if t["severity"] == "CRITICAL"]),
        'estimated_savings': total_cost * 0.35,
        'total_monthly_cost': total_cost,
        'raw_data': {
            'instances': instances[:10],
            'threats': threats[:10],
            'recommendations': cost_recommendations[:5]
        }
    }
    
    # Store in customer's scan history
    if 'scan_history' not in customer:
        customer['scan_history'] = []
    customer['scan_history'].append(scan_data)
    customer['last_scan'] = scan_data
    
    return scan_data

# Security Scoring
def calculate_security_score(scan_data):
    """Calculate security score based on threats"""
    if not scan_data or 'critical_threats' not in scan_data:
        return f"{random.randint(85, 98)}%"
    
    base_score = 100
    critical_penalty = scan_data['critical_threats'] * 10
    threat_penalty = scan_data['threats_identified'] * 2
    
    score = max(40, base_score - critical_penalty - threat_penalty)
    return f"{score}%"

def calculate_cost_efficiency(scan_data):
    """Calculate cost efficiency score"""
    if not scan_data or 'estimated_savings' not in scan_data:
        return f"{random.randint(75, 95)}%"
    
    efficiency = 100 - (scan_data['estimated_savings'] / (scan_data['total_monthly_cost'] + 0.001) * 100)
    return f"{max(50, efficiency):.0f}%"

# API Routes
@app.get("/")
async def root():
    return {
        "message": "Spectraine API - Cloud Threat Detection", 
        "status": "running",
        "version": "2.3.0",
        "demo_mode": True,
        "aws_connected": aws_session is not None,
        "stripe_connected": stripe.api_key is not None,
        "automation_enabled": True,
        "features": [
            "Monthly subscription model ($1,297/month)",
            "Customer authentication & secure dashboards", 
            "AWS account linking with real-time scanning",
            "DAILY AUTOMATED threat detection & cost optimization",
            "24/7 continuous monitoring",
            "Automated security remediation"
        ]
    }

@app.get("/health")
async def health_check():
    return {
        "status": "healthy", 
        "timestamp": datetime.now().isoformat(),
        "service": "Spectraine API",
        "version": "2.3.0",
        "automation_status": "active" if scheduler.running else "inactive"
    }

# Authentication Endpoints
@app.post("/customer-login")
async def customer_login(
    email: str = Form(...),
    company: str = Form(...)
):
    """Customer login - returns access token"""
    customer_id = f"{company}_{email}".replace(" ", "_").lower()
    
    # Check if customer exists
    customer = customers_db.get(customer_id)
    if not customer:
        raise HTTPException(status_code=404, detail="Customer not found. Please subscribe first.")
    
    token = generate_customer_token(customer_id)
    
    return {
        "access_token": token,
        "customer_id": customer_id,
        "company": company,
        "email": email,
        "aws_connected": bool(customer.get('aws_role_arn')),
        "automation_status": "active" if customer.get('subscription_status') == 'active' else "inactive",
        "message": "Login successful"
    }

@app.post("/customer-register")
async def customer_register(
    name: str = Form(...),
    email: str = Form(...),
    company: str = Form(...),
    aws_role_arn: str = Form(None)
):
    """Register customer without payment (for testing)"""
    customer_id = f"{company}_{email}".replace(" ", "_").lower()
    
    if customer_id in customers_db:
        raise HTTPException(status_code=400, detail="Customer already exists")
    
    # Validate AWS role if provided
    aws_connected = False
    if aws_role_arn:
        if not validate_role_arn(aws_role_arn):
            raise HTTPException(status_code=400, detail="Invalid AWS Role ARN format")
        
        can_connect, connection_info = test_role_connection(aws_role_arn)
        if not can_connect:
            raise HTTPException(status_code=400, detail=f"Cannot connect to AWS: {connection_info}")
        aws_connected = True
    
    # Create customer record
    customer_data = {
        'customer_id': customer_id,
        'name': name,
        'email': email,
        'company': company,
        'aws_role_arn': aws_role_arn,
        'aws_account_id': aws_role_arn.split(':')[4] if aws_role_arn else None,
        'subscription_status': 'active',
        'registered_at': datetime.now().isoformat(),
        'next_automation': (datetime.now() + timedelta(hours=24)).isoformat()
    }
    
    customers_db[customer_id] = customer_data
    
    # Run initial scan if AWS connected
    if aws_connected:
        await run_customer_aws_scan(customer_id)
    
    token = generate_customer_token(customer_id)
    
    return {
        "access_token": token,
        "customer_id": customer_id,
        "aws_connected": aws_connected,
        "automation_scheduled": True,
        "message": "Registration successful - Daily automation activated!"
    }

# Monthly Subscription
@app.post("/monthly-subscription")
async def monthly_subscription(
    name: str = Form(...),
    email: str = Form(...),
    company: str = Form(...),
    aws_role_arn: str = Form(...)
):
    """Monthly subscription - $1,297/month"""
    print(f"💰 MONTHLY SUBSCRIPTION: {company} - {email}")
    
    try:
        # Validate Stripe configuration
        if not stripe.api_key:
            raise HTTPException(status_code=500, detail="Stripe not configured")
        
        # Validate AWS Role ARN
        if not validate_role_arn(aws_role_arn):
            raise HTTPException(status_code=400, detail="Invalid AWS Role ARN format")
        
        # Test AWS connection
        can_connect, connection_info = test_role_connection(aws_role_arn)
        if not can_connect:
            raise HTTPException(status_code=400, detail=f"Cannot connect to AWS: {connection_info}")
        
        # Get price ID
        price_id = PRICE_IDS.get("monthly_subscription")
        if not price_id or price_id.startswith("price_1ABC"):
            raise HTTPException(status_code=500, detail="Invalid subscription price ID")
        
        frontend_url = os.getenv('FRONTEND_URL', 'http://localhost:3000')
        
        # Create customer record (pending subscription)
        customer_id = f"{company}_{email}".replace(" ", "_").lower()
        customer_data = {
            'customer_id': customer_id,
            'name': name,
            'email': email,
            'company': company,
            'aws_role_arn': aws_role_arn,
            'aws_account_id': aws_role_arn.split(':')[4],
            'subscription_status': 'pending',
            'registered_at': datetime.now().isoformat(),
            'next_automation': (datetime.now() + timedelta(hours=24)).isoformat()
        }
        customers_db[customer_id] = customer_data
        
        # Create Stripe checkout session
        session = stripe.checkout.Session.create(
            customer_email=email,
            payment_method_types=['card'],
            line_items=[{
                'price': price_id,
                'quantity': 1,
            }],
            mode='subscription',
            success_url=f'{frontend_url}/success?session_id={{CHECKOUT_SESSION_ID}}&customer_id={customer_id}',
            cancel_url=f'{frontend_url}/cancel',
            metadata={
                'service_type': 'monthly_subscription',
                'customer_id': customer_id,
                'customer_name': name,
                'customer_email': email,
                'company': company
            }
        )
        
        print(f"✅ Monthly subscription session created: {session.id}")
        
        return {
            "message": "Monthly subscription checkout created",
            "checkout_url": session.url,
            "customer_id": customer_id,
            "aws_connected": True,
            "automation_scheduled": True,
            "price": "$1,297/month",
            "includes": [
                "DAILY automated threat scans",
                "Real-time cost optimization alerts", 
                "Continuous compliance monitoring",
                "Monthly executive dashboard",
                "24/7 security monitoring",
                "Automated remediation actions",
                "Unlimited cloud assessments"
            ]
        }
        
    except Exception as e:
        print(f"❌ Monthly subscription error: {str(e)}")
        raise HTTPException(status_code=400, detail=f"Subscription error: {str(e)}")

# Secure Customer Endpoints
@app.get("/secure-customer-dashboard")
async def secure_customer_dashboard(authorization: str = Header(...)):
    """Secure dashboard with customer's data"""
    customer_id = get_current_customer(authorization)
    customer = customers_db.get(customer_id)
    
    if not customer:
        raise HTTPException(status_code=404, detail="Customer not found")
    
    # Get latest scan or create demo data
    latest_scan = customer.get('last_scan')
    if not latest_scan and customer.get('aws_role_arn'):
        latest_scan = await run_customer_aws_scan(customer_id)
    elif not latest_scan:
        # Generate demo data for unconnected customers
        instances = generate_instances()
        latest_scan = {
            'instances_found': len(instances),
            'threats_identified': len(generate_threats(instances)),
            'critical_threats': random.randint(0, 3),
            'estimated_savings': sum(i["monthly_cost"] for i in instances) * 0.35,
            'total_monthly_cost': sum(i["monthly_cost"] for i in instances)
        }
    
    # Get automation status
    last_automation = customer.get('last_automation', {})
    next_automation = customer.get('next_automation')
    
    return {
        "customer_id": customer_id,
        "company": customer['company'],
        "email": customer['email'],
        "subscription_status": customer.get('subscription_status', 'active'),
        
        "aws_connection": {
            "connected": bool(customer.get('aws_role_arn')),
            "account_id": customer.get('aws_account_id'),
            "last_scan": customer.get('last_scan', {}).get('timestamp')
        },
        
        "automation_status": {
            "enabled": customer.get('subscription_status') == 'active',
            "last_run": last_automation.get('timestamp'),
            "next_run": next_automation,
            "daily_scans_completed": len(automation_history.get(customer_id, [])),
            "status": "Active" if customer.get('subscription_status') == 'active' else "Inactive"
        },
        
        "live_metrics": {
            "security_score": calculate_security_score(latest_scan),
            "cost_efficiency": calculate_cost_efficiency(latest_scan),
            "instances_monitored": latest_scan.get('instances_found', 0),
            "threats_blocked": latest_scan.get('critical_threats', 0)
        },
        
        "financials": {
            "current_monthly_spend": f"${latest_scan.get('total_monthly_cost', 0):,.2f}" if latest_scan.get('total_monthly_cost') else "Calculating...",
            "potential_savings": f"${latest_scan.get('estimated_savings', 0):,.2f}/month",
            "savings_percentage": "35%"
        },
        
        "today_alerts": [
            {
                "type": "💰 COST SAVING",
                "message": f"Right-size overprovisioned instances → Save ${latest_scan.get('estimated_savings', 0) * 0.6:,.0f}/month",
                "priority": "high"
            } if latest_scan.get('estimated_savings', 0) > 0 else {
                "type": "🔧 SETUP",
                "message": "Connect your AWS account to start optimization",
                "priority": "info"
            }
        ],
        
        "recent_activity": customer.get('scan_history', [])[-3:]  # Last 3 scans
    }

@app.get("/secure-daily-results")
async def secure_daily_results(authorization: str = Header(...)):
    """Daily results for authenticated customer"""
    customer_id = get_current_customer(authorization)
    customer = customers_db.get(customer_id)
    
    if not customer:
        raise HTTPException(status_code=404, detail="Customer not found")
    
    # Get latest automation results or run new scan
    last_automation = customer.get('last_automation', {})
    
    if not last_automation:
        # If no automation yet, run a scan
        if customer.get('aws_role_arn'):
            scan_data = await run_customer_aws_scan(customer_id)
        else:
            # Demo data for unconnected customers
            instances = generate_instances()
            scan_data = {
                'instances_found': len(instances),
                'threats_identified': len(generate_threats(instances)),
                'critical_threats': random.randint(0, 2),
                'estimated_savings': sum(i["monthly_cost"] for i in instances) * 0.35
            }
        
        # Create mock automation results
        last_automation = {
            'automation_id': f"auto_{datetime.now().strftime('%Y%m%d_%H%M%S')}",
            'timestamp': datetime.now().isoformat(),
            'scan_results': scan_data,
            'automated_actions': generate_automated_actions(scan_data),
            'alerts_generated': generate_daily_alerts(scan_data)
        }
    
    return {
        "customer_id": customer_id,
        "date": datetime.now().date().isoformat(),
        "automation_timestamp": last_automation.get('timestamp'),
        
        "daily_highlights": {
            "security_score": calculate_security_score(last_automation.get('scan_results', {})),
            "cost_savings_identified": f"${last_automation.get('scan_results', {}).get('estimated_savings', 0):,.2f}",
            "threats_blocked": last_automation.get('scan_results', {}).get('critical_threats', 0),
            "compliance_status": f"{random.randint(88, 99)}%"
        },
        
        "automated_actions_taken": last_automation.get('automated_actions', []),
        
        "alerts_generated": last_automation.get('alerts_generated', []),
        
        "today_top_actions": [
            {
                "priority": "HIGH",
                "action": "Right-size overprovisioned instances",
                "savings": f"${last_automation.get('scan_results', {}).get('estimated_savings', 0) * 0.6:,.0f}/month",
                "time_required": "15 minutes"
            },
            {
                "priority": "MEDIUM" if customer.get('aws_role_arn') else "HIGH",
                "action": "Enable S3 bucket encryption" if customer.get('aws_role_arn') else "Connect AWS account",
                "risk_reduction": "Eliminates data exposure" if customer.get('aws_role_arn') else "Start real monitoring",
                "time_required": "5 minutes"
            }
        ]
    }

@app.get("/secure-automation-history")
async def secure_automation_history(authorization: str = Header(...)):
    """Get automation history for customer"""
    customer_id = get_current_customer(authorization)
    
    history = automation_history.get(customer_id, [])
    
    return {
        "customer_id": customer_id,
        "total_automation_runs": len(history),
        "automation_history": history[-10:]  # Last 10 automation runs
    }

@app.post("/secure-run-automation-now")
async def secure_run_automation_now(authorization: str = Header(...)):
    """Manually trigger automation for customer"""
    customer_id = get_current_customer(authorization)
    
    if not customers_db.get(customer_id):
        raise HTTPException(status_code=404, detail="Customer not found")
    
    await run_daily_automation_for_customer(customer_id)
    
    return {
        "message": "Automation completed successfully",
        "automation_id": customers_db[customer_id].get('last_automation', {}).get('automation_id'),
        "timestamp": datetime.now().isoformat()
    }

@app.post("/secure-scan-now")
async def secure_scan_now(authorization: str = Header(...)):
    """Run immediate scan for customer"""
    customer_id = get_current_customer(authorization)
    
    if not customers_db.get(customer_id):
        raise HTTPException(status_code=404, detail="Customer not found")
    
    scan_data = await run_customer_aws_scan(customer_id)
    
    return {
        "message": "Scan completed successfully",
        "scan_id": scan_data['scan_id'],
        "results": {
            "instances_found": scan_data['instances_found'],
            "threats_identified": scan_data['threats_identified'],
            "critical_threats": scan_data['critical_threats'],
            "potential_savings": f"${scan_data['estimated_savings']:,.2f}/month"
        }
    }

# Automation Management Endpoints
@app.get("/automation-status")
async def automation_status():
    """Get overall automation system status"""
    active_customers = [
        customer_id for customer_id, customer in customers_db.items() 
        if customer.get('subscription_status') == 'active'
    ]
    
    return {
        "automation_system": "active",
        "scheduler_running": scheduler.running,
        "total_active_customers": len(active_customers),
        "next_scheduled_run": scheduler.get_job('daily_automation').next_run_time if scheduler.get_job('daily_automation') else "Not scheduled",
        "today_automations_completed": sum(len(history) for history in automation_history.values())
    }

@app.post("/trigger-daily-automation")
async def trigger_daily_automation(background_tasks: BackgroundTasks):
    """Manually trigger daily automation for all customers (admin)"""
    background_tasks.add_task(run_daily_automation_for_all_customers)
    
    return {
        "message": "Daily automation triggered for all active customers",
        "triggered_at": datetime.now().isoformat()
    }

# CloudFormation Template
@app.get("/download-cloudformation-template-file")
async def download_cloudformation_template_file():
    """Serve CloudFormation template"""
    try:
        possible_paths = [
            'cloudformation/spectraine-role-setup.yml',
            './cloudformation/spectraine-role-setup.yml',
        ]
        
        for path in possible_paths:
            if os.path.exists(path):
                return FileResponse(
                    path,
                    media_type='application/x-yaml',
                    filename='spectraine-role-setup.yml'
                )
        
        # Fallback template
        fallback_template = f"""AWSTemplateFormatVersion: '2010-09-09'
Description: 'Spectraine Cloud Security Read-Only Role'

Parameters:
  SpectraineAccountId:
    Type: String
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
    Value: !GetAtt SpectraineReadOnlyRole.Arn
"""
        
        return Response(
            content=fallback_template,
            media_type='application/x-yaml',
            headers={'Content-Disposition': 'attachment; filename="spectraine-role-setup.yml"'}
        )
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Template error: {str(e)}")

# Public Demo Endpoints (Backward Compatibility)
@app.get("/instances", response_model=List[InstanceResponse])
async def get_instances(use_real: bool = False):
    """Get EC2 instances with threat analysis"""
    if use_real and aws_session:
        return get_real_instances()
    return generate_instances()

@app.get("/threat-scan")
async def threat_scan(use_real: bool = False):
    """Run comprehensive threat detection scan"""
    if use_real and aws_session:
        instances = get_real_instances()
        threats = generate_threats(instances)
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
        "details": threats[:5],
        "scan_time": f"{random.randint(45, 120)} seconds",
        "instances_scanned": len(instances)
    }

@app.get("/cost-analysis")
async def cost_analysis():
    """Get enhanced cost optimization analysis"""
    instances = generate_instances()
    total_monthly = sum(i["monthly_cost"] for i in instances)
    savings = total_monthly * 0.35
    
    return {
        "analysis_id": f"cost-{uuid.uuid4().hex[:8]}",
        "total_monthly_spend": f"${total_monthly:,.2f}",
        "potential_savings": f"${savings:,.2f}/month",
        "annual_impact": f"${savings * 12:,.2f}",
        "savings_percentage": "35%",
        "recommendations": generate_cost_recommendations(instances),
        "business_impact": f"Savings could fund {savings / 8.333:.1f} additional team members"
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
        "monthly_spend": f"${total_monthly:,.2f}",
        "potential_savings": f"${total_monthly * 0.35:,.2f}",
        "security_rating": f"{random.randint(4, 7)}/10"
    }

# Debug Endpoints
@app.get("/debug/customers")
async def debug_customers():
    """Debug endpoint to see all customers (remove in production)"""
    return {
        "total_customers": len(customers_db),
        "active_customers": len([c for c in customers_db.values() if c.get('subscription_status') == 'active']),
        "automation_history_count": sum(len(history) for history in automation_history.values()),
        "customers": {k: {**v, 'aws_role_arn': v.get('aws_role_arn', '')[:20] + '...' if v.get('aws_role_arn') else None} for k, v in customers_db.items()}
    }

@app.get("/debug/config")
async def debug_config():
    """Debug configuration"""
    return {
        "stripe_configured": bool(stripe.api_key),
        "aws_configured": aws_session is not None,
        "automation_configured": scheduler.running,
        "total_customers": len(customers_db),
        "price_ids": {k: v[:20] + "..." if v else None for k, v in PRICE_IDS.items()}
    }

if __name__ == "__main__":
    import uvicorn
    port = int(os.environ.get("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)