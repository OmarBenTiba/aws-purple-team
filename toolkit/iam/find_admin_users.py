"""
What it does:
  - Lists all IAM users
  - Checks directly attached managed policies
  - Checks inline policies for wildcard actions
  - Checks group memberships and group policies
  - Flags any user with AdministratorAccess or Action: *

What it cannot do:
  - Detect admin access granted via Permission Boundaries
  - Detect admin access via Service Control Policies (SCPs)
  - Evaluate complex conditional policy statements
  - Requires iam:List* and iam:Get* permissions
"""

import boto3
import botocore
import json

def find_admin_users():

    try:
        iam       = boto3.client('iam')
        paginator = iam.get_paginator('list_users')
        users     = []

        for page in paginator.paginate():
            users.extend(page['Users'])

        print(f"\n[i] Total users found: {len(users)}\n")

        admin_users = []

        for user in users:
            username  = user['UserName']
            is_admin  = False
            reason    = []

            # Check 1: directly attached managed policies
            try:
                attached = iam.list_attached_user_policies(
                    UserName=username
                )['AttachedPolicies']

                for policy in attached:
                    if policy['PolicyName'] == 'AdministratorAccess' \
                    or 'Admin' in policy['PolicyName']:
                        is_admin = True
                        reason.append(
                            f"Managed policy: {policy['PolicyName']}"
                        )
            except botocore.exceptions.ClientError:
                pass

            # Check 2: inline policies
            try:
                inline_names = iam.list_user_policies(
                    UserName=username
                )['PolicyNames']

                for policy_name in inline_names:
                    doc = iam.get_user_policy(
                        UserName=username,
                        PolicyName=policy_name
                    )['PolicyDocument']

                    for stmt in doc.get('Statement', []):
                        actions  = stmt.get('Action', [])
                        effect   = stmt.get('Effect', '')
                        resource = stmt.get('Resource', [])

                        if isinstance(actions, str):
                            actions = [actions]
                        if isinstance(resource, str):
                            resource = [resource]

                        if effect == 'Allow' and (
                            '*' in actions or 'iam:*' in actions
                        ) and '*' in resource:
                            is_admin = True
                            reason.append(
                                f"Inline policy: {policy_name} "
                                f"(Action: {actions}, Resource: *)"
                            )
            except botocore.exceptions.ClientError:
                pass

            # Check 3: group memberships
            try:
                groups = iam.list_groups_for_user(
                    UserName=username
                )['Groups']

                for group in groups:
                    group_name = group['GroupName']
                    group_policies = iam.list_attached_group_policies(
                        GroupName=group_name
                    )['AttachedPolicies']

                    for policy in group_policies:
                        if policy['PolicyName'] == 'AdministratorAccess' \
                        or 'Admin' in policy['PolicyName']:
                            is_admin = True
                            reason.append(
                                f"Group: {group_name} → "
                                f"policy: {policy['PolicyName']}"
                            )
            except botocore.exceptions.ClientError:
                pass

            # Report
            if is_admin:
                admin_users.append(username)
                print(f"  [!] ADMIN USER: {username}")
                for r in reason:
                    print(f"      → {r}")
            else:
                print(f"  [+] Normal user: {username}")

        print(f"\n  Summary:")
        print(f"  - Admin users  : {len(admin_users)}")
        print(f"  - Normal users : {len(users) - len(admin_users)}")

        if admin_users:
            print(f"\n  High value targets:")
            for u in admin_users:
                print(f"    - {u}")

    except botocore.exceptions.ClientError as e:
        code = e.response['Error']['Code']
        if code == 'AccessDenied':
            print("[x] AccessDenied — need iam:ListUsers permission")
        else:
            print(f"[x] Error: {e}")
    except botocore.exceptions.NoCredentialsError:
        print("[x] No credentials — run: aws configure")

if __name__ == "__main__":
    find_admin_users()
