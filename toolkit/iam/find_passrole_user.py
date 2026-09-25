"""
What it does:
  - Lists all IAM users
  - Checks managed policies for iam:PassRole permission
  - Checks inline policies for iam:PassRole permission
  - Checks group policies for iam:PassRole permission
  - Flags any user that can pass a role to an AWS service
  - Shows which roles they can pass (Resource field)
"""

import boto3
import botocore

def check_policy_for_passrole(statements, source):
    """Check policy statements for iam:PassRole."""
    findings = []
    for stmt in statements:
        effect   = stmt.get('Effect', '')
        actions  = stmt.get('Action', [])
        resource = stmt.get('Resource', [])

        if isinstance(actions, str):
            actions = [actions]
        if isinstance(resource, str):
            resource = [resource]

        if effect == 'Allow' and (
            'iam:PassRole' in actions or
            'iam:*' in actions or
            '*' in actions
        ):
            findings.append({
                'source'   : source,
                'actions'  : actions,
                'resource' : resource
            })
    return findings


def find_passrole_users():

    try:
        iam       = boto3.client('iam')
        paginator = iam.get_paginator('list_users')
        users     = []

        for page in paginator.paginate():
            users.extend(page['Users'])

        print(f"\n[i] Total users found: {len(users)}\n")

        passrole_users = []

        for user in users:
            username = user['UserName']
            findings = []

            # Check 1: attached managed policies
            try:
                attached = iam.list_attached_user_policies(
                    UserName=username
                )['AttachedPolicies']

                for policy in attached:
                    version_id = iam.get_policy(
                        PolicyArn=policy['PolicyArn']
                    )['Policy']['DefaultVersionId']

                    doc = iam.get_policy_version(
                        PolicyArn=policy['PolicyArn'],
                        VersionId=version_id
                    )['PolicyVersion']['Document']

                    results = check_policy_for_passrole(
                        doc.get('Statement', []),
                        f"Managed policy: {policy['PolicyName']}"
                    )
                    findings.extend(results)

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

                    results = check_policy_for_passrole(
                        doc.get('Statement', []),
                        f"Inline policy: {policy_name}"
                    )
                    findings.extend(results)

            except botocore.exceptions.ClientError:
                pass

            # Check 3: group policies
            try:
                groups = iam.list_groups_for_user(
                    UserName=username
                )['Groups']

                for group in groups:
                    group_name     = group['GroupName']
                    group_attached = iam.list_attached_group_policies(
                        GroupName=group_name
                    )['AttachedPolicies']

                    for policy in group_attached:
                        version_id = iam.get_policy(
                            PolicyArn=policy['PolicyArn']
                        )['Policy']['DefaultVersionId']

                        doc = iam.get_policy_version(
                            PolicyArn=policy['PolicyArn'],
                            VersionId=version_id
                        )['PolicyVersion']['Document']

                        results = check_policy_for_passrole(
                            doc.get('Statement', []),
                            f"Group: {group_name} → "
                            f"policy: {policy['PolicyName']}"
                        )
                        findings.extend(results)

            except botocore.exceptions.ClientError:
                pass

            # Report
            if findings:
                passrole_users.append(username)
                print(f"  [!] PASSROLE FOUND: {username}")
                for f in findings:
                    print(f"      Source   : {f['source']}")
                    print(f"      Actions  : {f['actions']}")
                    print(f"      Resource : {f['resource']}")
            else:
                print(f"  [+] No PassRole: {username}")


    except botocore.exceptions.ClientError as e:
        code = e.response['Error']['Code']
        if code == 'AccessDenied':
            print("[x] AccessDenied — need iam:ListUsers permission")
        else:
            print(f"[x] Error: {e}")
    except botocore.exceptions.NoCredentialsError:
        print("[x] No credentials — run: aws configure")

if __name__ == "__main__":
    find_passrole_users()
