"""
What it does:
  - Takes a role ARN as input
  - Assumes that role using current credentials
  - Returns temporary AccessKeyId, SecretAccessKey, SessionToken
  - Confirms new identity with GetCallerIdentity
  - Prints credentials ready to export as environment variables

"""

import boto3
import botocore
import sys

def assume_role(role_arn, session_name="attack-session"):

    try:
        sts = boto3.client('sts')

        print(f"\n[i] Attempting to assume role:")
        print(f"    Role ARN     : {role_arn}")
        print(f"    Session name : {session_name}")

        response = sts.assume_role(
            RoleArn=role_arn,
            RoleSessionName=session_name
        )

        creds = response['Credentials']

        print(f"\n[+] Role assumed successfully")
        print(f"\n[+] Temporary credentials:")
        print(f"    AccessKeyId     : {creds['AccessKeyId']}")
        print(f"    SecretAccessKey : {creds['SecretAccessKey']}")
        print(f"    SessionToken    : {creds['SessionToken'][:30]}...")
        print(f"    Expiration      : {creds['Expiration']}")

        # Verify new identity
        new_session = boto3.Session(
            aws_access_key_id     = creds['AccessKeyId'],
            aws_secret_access_key = creds['SecretAccessKey'],
            aws_session_token     = creds['SessionToken']
        )
        new_sts  = new_session.client('sts')
        identity = new_sts.get_caller_identity()

        print(f"\n[+] New identity confirmed:")
        print(f"    Account : {identity['Account']}")
        print(f"    ARN     : {identity['Arn']}")

        print(f"\n[i] Export credentials to environment:")
        print(f"    export AWS_ACCESS_KEY_ID={creds['AccessKeyId']}")
        print(f"    export AWS_SECRET_ACCESS_KEY={creds['SecretAccessKey']}")
        print(f"    export AWS_SESSION_TOKEN={creds['SessionToken']}")

    except botocore.exceptions.ClientError as e:
        code = e.response['Error']['Code']
        if code == 'AccessDenied':
            print(f"[x] AccessDenied — current identity cannot assume this role")
            print(f"[i] Check: does the role trust policy allow your identity?")
        elif code == 'NoSuchEntity':
            print(f"[x] Role not found: {role_arn}")
        else:
            print(f"[x] Error {code}: {e}")
    except botocore.exceptions.NoCredentialsError:
        print("[x] No credentials — run: aws configure")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("\n[!] Usage: python3 assume_role.py <role_arn> [session_name]")
        print("    Example: python3 assume_role.py arn:aws:iam::123456789:role/AdminRole")
        sys.exit(1)

    role_arn     = sys.argv[1]
    session_name = sys.argv[2] if len(sys.argv) > 2 else "attack-session"
    assume_role(role_arn, session_name)
