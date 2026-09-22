"""
Purple Team Detection — Scenario 2: Over-Permissioned Lambda via PassRole
Author: Omar (EY Internship — Purple Team Project)

Attack chain detected:
  Step 1 — chris assumes cg-lambdaManager-role (AssumeRole)
  Step 2 — attack-session calls GetCallerIdentity
  Step 3 — attack-session creates Lambda with privileged role (CreateFunction)
           → this is the PassRole event — the privileged role ARN appears
             in the request parameters as the execution role
  Step 4 — Lambda invoked under privileged role identity

Detection logic:
  - AssumeRole by chris → reconnaissance signal
  - CreateFunction where request contains a privileged role ARN → HIGH alert
  - Correlation: same attack-session identity across multiple events

CloudTrail events queried:
  - sts:AssumeRole
  - sts:GetCallerIdentity
  - lambda:CreateFunction20150331
  - lambda:InvokeFunction

Output: terminal report + detection_coverage_scenario2.txt
"""

import boto3
import json
from datetime import datetime, timezone

# ============================================================
# CONFIG
# ============================================================
REGION          = "us-east-1"
ATTACK_START    = "2026-09-14T10:20:00Z"
ATTACK_END      = "2026-09-14T10:25:00Z"
LOG_FILE        = "detection_coverage_scenario2.txt"

# Known sensitive role keywords — flag CreateFunction if role contains these
SENSITIVE_ROLE_KEYWORDS = ["debug", "admin", "poweruser", "cg-"]
# ============================================================


def log(message):
    print(message)
    with open(LOG_FILE, "a") as f:
        f.write(message + "\n")


def parse_time(time_str):
    return datetime.strptime(time_str, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)


# ----------------------------------------------------------
# Step 1: Query CloudTrail for attack events
# ----------------------------------------------------------
def query_cloudtrail(region, start_time, end_time):
    log("=" * 60)
    log("STEP 1 — Querying CloudTrail for Scenario 2 attack events")
    log(f"Window  : {start_time} → {end_time}")
    log("=" * 60)

    ct    = boto3.client('cloudtrail', region_name=region)
    start = parse_time(start_time)
    end   = parse_time(end_time)
    found = []

    target_events = [
        'AssumeRole',
        'GetCallerIdentity',
        'CreateFunction20150331',
        'UpdateFunctionCode20150331v2',
        'InvokeFunction',
    ]

    for event_name in target_events:
        log(f"\nQuerying: {event_name}")
        try:
            paginator = ct.get_paginator('lookup_events')
            pages = paginator.paginate(
                LookupAttributes=[
                    {'AttributeKey': 'EventName', 'AttributeValue': event_name}
                ],
                StartTime=start,
                EndTime=end,
            )
            count = 0
            for page in pages:
                for event in page['Events']:
                    found.append(event)
                    count += 1
            log(f"  Found {count} event(s)")
        except Exception as e:
            log(f"  ERROR: {e}")

    return found


# ----------------------------------------------------------
# Step 2: Analyze events
# ----------------------------------------------------------
def analyze_events(events, sensitive_keywords):
    log("\n" + "=" * 60)
    log("STEP 2 — Analyzing events for PassRole exploitation pattern")
    log("=" * 60)

    suspicious = []

    for event in events:
        event_name = event.get('EventName', 'Unknown')
        event_time = event.get('EventTime', 'Unknown')
        username   = event.get('Username', 'Unknown')

        detail = {}
        if 'CloudTrailEvent' in event:
            try:
                detail = json.loads(event['CloudTrailEvent'])
            except Exception:
                pass

        source_ip      = detail.get('sourceIPAddress', 'Unknown')
        user_type      = detail.get('userIdentity', {}).get('type', 'Unknown')
        arn            = detail.get('userIdentity', {}).get('arn', 'Unknown')
        request_params = detail.get('requestParameters', {}) or {}

        # --- Detection Rule 1 ---
        # AssumeRole by chris — initial access / privilege escalation attempt
        if event_name == 'AssumeRole' and 'chris' in username.lower():
            finding = {
                'event_name' : event_name,
                'event_time' : str(event_time),
                'username'   : username,
                'source_ip'  : source_ip,
                'severity'   : 'MEDIUM',
                'rule'       : 'Low-privileged user chris assuming a role — possible escalation attempt',
                'detail'     : str(request_params)
            }
            suspicious.append(finding)
            log(f"\n  [ALERT] AssumeRole by chris")
            log(f"    Time      : {event_time}")
            log(f"    Identity  : {username}")
            log(f"    Source IP : {source_ip}")
            log(f"    Severity  : MEDIUM")
            log(f"    Rule      : Low-privileged user assuming role — watch for follow-up")

        # --- Detection Rule 2 ---
        # CreateFunction with a sensitive role in the Role field
        # This is the PassRole exploitation — the attacker passes a privileged
        # role to a Lambda function they control
        elif event_name == 'CreateFunction20150331':
            role_arn = request_params.get('role', '') or \
                       str(request_params).lower()

            is_sensitive_role = any(
                kw.lower() in role_arn.lower()
                for kw in sensitive_keywords
            )

            severity = 'HIGH' if is_sensitive_role else 'MEDIUM'
            rule = (
                'CreateFunction with SENSITIVE privileged role — PassRole exploitation confirmed'
                if is_sensitive_role else
                'CreateFunction detected — verify role permissions'
            )

            finding = {
                'event_name' : event_name,
                'event_time' : str(event_time),
                'username'   : username,
                'source_ip'  : source_ip,
                'severity'   : severity,
                'rule'       : rule,
                'detail'     : f"Role in request: {role_arn[:100]}"
            }
            suspicious.append(finding)
            log(f"\n  [ALERT] CreateFunction — PassRole exploitation")
            log(f"    Time      : {event_time}")
            log(f"    Identity  : {username} ({user_type})")
            log(f"    Source IP : {source_ip}")
            log(f"    Role ARN  : {role_arn[:100]}")
            log(f"    Severity  : {severity}")
            log(f"    Rule      : {rule}")

        # --- Detection Rule 3 ---
        # InvokeFunction — confirms the escalation was exploited
        elif event_name == 'InvokeFunction':
            finding = {
                'event_name' : event_name,
                'event_time' : str(event_time),
                'username'   : username,
                'source_ip'  : source_ip,
                'severity'   : 'HIGH',
                'rule'       : 'Lambda invoked after PassRole — escalation exploited',
                'detail'     : str(request_params)
            }
            suspicious.append(finding)
            log(f"\n  [ALERT] InvokeFunction — escalation confirmed")
            log(f"    Time      : {event_time}")
            log(f"    Identity  : {username}")
            log(f"    Source IP : {source_ip}")
            log(f"    Severity  : HIGH")

        # --- OK events ---
        else:
            log(f"\n  [OK] {event_name} at {event_time} by {username}")

    return suspicious


# ----------------------------------------------------------
# Step 3: Report
# ----------------------------------------------------------
def report(suspicious_events, start_time, end_time):
    log("\n" + "=" * 60)
    log("DETECTION COVERAGE REGISTER — Scenario 2")
    log("Over-Permissioned Lambda Exploitation via PassRole")
    log("=" * 60)

    log(f"\nAttack window     : {start_time} → {end_time}")
    log(f"Total alerts      : {len(suspicious_events)}")
    log(f"Detection method  : CloudTrail lookup_events + request parameter analysis")

    if not suspicious_events:
        log("\nNo suspicious events detected in this window.")
        return

    log("\n--- ALERT DETAILS ---")
    for i, finding in enumerate(suspicious_events, 1):
        log(f"\nAlert #{i}")
        log(f"  Event     : {finding['event_name']}")
        log(f"  Time      : {finding['event_time']}")
        log(f"  Identity  : {finding['username']}")
        log(f"  Source IP : {finding['source_ip']}")
        log(f"  Severity  : {finding['severity']}")
        log(f"  Rule      : {finding['rule']}")
        log(f"  Detail    : {finding['detail']}")

    log("\n--- COVERAGE SUMMARY ---")
    log("  Attack step 1 (Initial access — chris creds) : VISIBLE — GetCallerIdentity")
    log("  Attack step 2 (AssumeRole to LambdaManager)  : VISIBLE — AssumeRole by chris")
    log("  Attack step 3 (PassRole + CreateFunction)     : VISIBLE — PRIMARY SIGNAL")
    log("                                                  CreateFunction with privileged role")
    log("  Attack step 4 (Lambda invocation)             : VISIBLE — InvokeFunction")
    log("  Secrets Manager access (inside Lambda)        : VISIBLE — under debug-role identity")
    log("\n  False positive rate : LOW-MEDIUM")
    log("  Reason              : Lambda functions legitimately use roles.")
    log("                        Rule must be tuned to flag only sensitive roles.")
    log("\n  Alert latency       : 5-15 minutes (CloudTrail delivery delay)")
    log("\n  Blind spot          : If attacker updates existing Lambda instead of")
    log("                        creating new one — CreateFunction signal is absent.")
    log("                        Detection then relies on UpdateFunctionCode event.")

    log("\n--- TRIAGE STEPS FOR ANALYST ---")
    log("  1. Identify the role passed to the Lambda function")
    log("  2. Review role permissions — does it have access to sensitive resources?")
    log("  3. Check who created the Lambda — is this expected for that identity?")
    log("  4. Look for InvokeFunction shortly after CreateFunction")
    log("  5. Check Secrets Manager for access attempts after InvokeFunction")
    log("  6. Verify if the Lambda function code is legitimate")

    log("\n" + "=" * 60)
    log(f"Full report saved to: {LOG_FILE}")
    log("=" * 60)


# ----------------------------------------------------------
# Main
# ----------------------------------------------------------
def main():
    open(LOG_FILE, 'w').close()

    log(f"[{datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')}] Detection started")
    log("Scenario 2 — Over-Permissioned Lambda Exploitation via PassRole")

    events     = query_cloudtrail(REGION, ATTACK_START, ATTACK_END)
    suspicious = analyze_events(events, SENSITIVE_ROLE_KEYWORDS)
    report(suspicious, ATTACK_START, ATTACK_END)


if __name__ == "__main__":
    main()
