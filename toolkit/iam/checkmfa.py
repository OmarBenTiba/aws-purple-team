"""
What it does:
  - Lists all IAM users in the account
  - Checks MFA status for each user
  - Flags users with no MFA as high priority targets
  - Shows users with MFA enabled for context

"""

import boto3
import botocore

def check_mfa():
    try:
        iam       = boto3.client('iam')
        paginator = iam.get_paginator('list_users')
        users     = []

        for page in paginator.paginate():
            users.extend(page['Users'])

        print(f"\n[i] Total users found: {len(users)}\n")

        no_mfa  = []
        has_mfa = []

        for user in users:
            username = user['UserName']
            try:
                mfa_devices = iam.list_mfa_devices(
                    UserName=username
                )['MFADevices']

                if not mfa_devices:
                    no_mfa.append(username)
                    print(f"  [!] NO MFA : {username} — potential takeover target")
                else:
                    has_mfa.append(username)
                    print(f"  [+] MFA OK : {username}")

            except botocore.exceptions.ClientError as e:
                print(f"  [x] ERROR  : {username} — {e}")

        print(f"\n  Summary:")
        print(f"  - Users WITHOUT MFA : {len(no_mfa)}")
        print(f"  - Users WITH MFA    : {len(has_mfa)}")

    except botocore.exceptions.ClientError as e:
        code = e.response['Error']['Code']
        if code == 'AccessDenied':
            print("[x] AccessDenied — need iam:ListUsers permission")
        else:
            print(f"[x] Error: {e}")
    except botocore.exceptions.NoCredentialsError:
        print("[x] No credentials — run: aws configure")

if __name__ == "__main__":
    check_mfa()
