"""
Purple Team Detection — Scenario 3: CloudTrail Disabling & Gap Analysis
Author: Omar (EY Internship — Purple Team Project)

Detection logic:
  - Any StopLogging event is HIGH severity — always investigate
  - Gap between StopLogging and StartLogging = blind window
  - All actions during the gap leave zero CloudTrail trace
  - The gap duration itself is the key metric for the SOC

CloudTrail events queried:
  - cloudtrail:DescribeTrails   (reconnaissance)
  - cloudtrail:GetTrailStatus   (reconnaissance)
  - cloudtrail:StopLogging      (PRIMARY SIGNAL — last event before gap)
  - cloudtrail:StartLogging     (first event after gap)

Output: terminal report + detection_coverage_scenario3.txt
"""

import boto3
import json
from datetime import datetime, timezone

# ============================================================
# CONFIG
# ============================================================
REGION       = "us-east-1"
ATTACK_START = "2026-09-15T09:48:00Z"
ATTACK_END   = "2026-09-15T09:50:00Z"
LOG_FILE     = "detection_coverage_scenario3.txt"
# ============================================================


def log(message):
    print(message)
    with open(LOG_FILE, "a") as f:
        f.write(message + "\n")


def parse_time(time_str):
    return datetime.strptime(time_str, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)


# ----------------------------------------------------------
# Step 1: Query CloudTrail
# ----------------------------------------------------------
def query_cloudtrail(region, start_time, end_time):
    log("=" * 60)
    log("STEP 1 — Querying CloudTrail for Scenario 3 attack events")
    log(f"Window  : {start_time} → {end_time}")
    log("=" * 60)

    ct    = boto3.client('cloudtrail', region_name=region)
    start = parse_time(start_time)
    end   = parse_time(end_time)
    found = []

    target_events = [
        'DescribeTrails',
        'GetTrailStatus',
        'StopLogging',
        'StartLogging',
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

    # Sort all events by time
    found.sort(key=lambda e: e.get('EventTime', datetime.min.replace(tzinfo=timezone.utc)))
    return found


# ----------------------------------------------------------
# Step 2: Analyze events and calculate gap
# ----------------------------------------------------------
def analyze_events(events):
    log("\n" + "=" * 60)
    log("STEP 2 — Analyzing events and calculating blind window")
    log("=" * 60)

    suspicious   = []
    stop_event   = None
    start_event  = None
    gap_duration = None

    for event in events:
        event_name = event.get('EventName', 'Unknown')
        event_time = event.get('EventTime')
        username   = event.get('Username', 'Unknown')

        detail = {}
        if 'CloudTrailEvent' in event:
            try:
                detail = json.loads(event['CloudTrailEvent'])
            except Exception:
                pass

        source_ip      = detail.get('sourceIPAddress', 'Unknown')
        user_type      = detail.get('userIdentity', {}).get('type', 'Unknown')
        request_params = detail.get('requestParameters', {}) or {}
        trail_name     = request_params.get('name', 'Unknown')

        # Reconnaissance signals
        if event_name in ['DescribeTrails', 'GetTrailStatus']:
            if username == 'purple-team-lab':
                log(f"\n  [INFO] {event_name} by {username} at {event_time}")
                log(f"    Source IP : {source_ip}")
                log(f"    Note      : Attacker performing trail reconnaissance")
                suspicious.append({
                    'event_name' : event_name,
                    'event_time' : str(event_time),
                    'username'   : username,
                    'source_ip'  : source_ip,
                    'severity'   : 'LOW',
                    'rule'       : 'CloudTrail reconnaissance by non-service identity'
                })

        # PRIMARY SIGNAL — StopLogging
        elif event_name == 'StopLogging':
            stop_event = event_time
            log(f"\n  [ALERT] *** StopLogging DETECTED ***")
            log(f"    Time      : {event_time}")
            log(f"    Identity  : {username} ({user_type})")
            log(f"    Source IP : {source_ip}")
            log(f"    Trail     : {trail_name}")
            log(f"    Severity  : HIGH")
            log(f"    Rule      : CloudTrail logging disabled — blind window started")
            log(f"    WARNING   : All subsequent API calls are INVISIBLE to CloudTrail")
            suspicious.append({
                'event_name' : event_name,
                'event_time' : str(event_time),
                'username'   : username,
                'source_ip'  : source_ip,
                'severity'   : 'HIGH',
                'rule'       : 'StopLogging — blind window started',
                'trail'      : trail_name
            })

        # Gap end signal — StartLogging
        elif event_name == 'StartLogging':
            start_event = event_time
            log(f"\n  [INFO] StartLogging detected — logging restored")
            log(f"    Time      : {event_time}")
            log(f"    Identity  : {username}")
            log(f"    Source IP : {source_ip}")
            log(f"    Trail     : {trail_name}")

            # Calculate gap if we have both events
            if stop_event:
                gap_seconds  = (event_time - stop_event).total_seconds()
                gap_duration = gap_seconds
                log(f"\n  [GAP ANALYSIS]")
                log(f"    Gap started : {stop_event}")
                log(f"    Gap ended   : {event_time}")
                log(f"    Duration    : {gap_seconds:.1f} seconds ({gap_seconds/60:.2f} minutes)")
                log(f"    Visibility  : ZERO — all actions during gap are unrecoverable")

    return suspicious, stop_event, start_event, gap_duration


# ----------------------------------------------------------
# Step 3: Report
# ----------------------------------------------------------
def report(suspicious, stop_event, start_event, gap_duration, start_time, end_time):
    log("\n" + "=" * 60)
    log("DETECTION COVERAGE REGISTER — Scenario 3")
    log("CloudTrail Disabling & Blind Window Operation")
    log("=" * 60)

    high_alerts = [e for e in suspicious if e['severity'] == 'HIGH']

    log(f"\nAttack window     : {start_time} → {end_time}")
    log(f"Total alerts      : {len(suspicious)}")
    log(f"HIGH alerts       : {len(high_alerts)}")

    if stop_event and start_event and gap_duration is not None:
        log(f"\n--- GAP ANALYSIS ---")
        log(f"  StopLogging time  : {stop_event}")
        log(f"  StartLogging time : {start_event}")
        log(f"  Gap duration      : {gap_duration:.1f} seconds ({gap_duration/60:.2f} minutes)")
        log(f"  Actions in gap    : IAM enum, S3 enum, Secrets enum (from attack log)")
        log(f"  CloudTrail view   : ZERO events during gap — completely blind")
    elif stop_event and not start_event:
        log(f"\n  WARNING: StopLogging found but NO StartLogging")
        log(f"  Trail may still be disabled — check immediately")

    log("\n--- COVERAGE SUMMARY ---")
    log("  Attack step 1 (DescribeTrails + GetTrailStatus) : VISIBLE — reconnaissance")
    log("  Attack step 2 (GetCallerIdentity)               : VISIBLE — attacker identity")
    log("  Attack step 3 (StopLogging)                     : VISIBLE — PRIMARY SIGNAL")
    log("                                                    Last event before blind window")
    log("  Attack step 4 (Blind window operations)         : NOT VISIBLE")
    log("                                                    ListUsers, ListRoles,")
    log("                                                    ListBuckets, ListSecrets")
    log("                                                    — all invisible, unrecoverable")
    log("  Attack step 5 (StartLogging)                    : VISIBLE — gap end marker")

    log("\n  Detection method  : CloudTrail lookup_events")
    log("  Primary signal    : StopLogging event + gap between Stop/Start")
    log("  False positive    : VERY LOW — legitimate StopLogging is extremely rare")
    log("  Alert latency     : 5-15 min for StopLogging alert")
    log("                      Gap itself is real-time — every second counts")

    log("\n--- TRIAGE STEPS FOR ANALYST ---")
    log("  1. Identify who called StopLogging — is this identity authorized?")
    log("  2. Check how this identity gained cloudtrail:StopLogging permission")
    log("  3. Calculate gap duration: time between StopLogging and StartLogging")
    log("  4. Review all other log sources during the gap:")
    log("     - VPC Flow Logs")
    log("     - S3 server access logs")
    log("     - Any other independent logging services")
    log("  5. Assume attacker performed recon during gap — audit all resources")
    log("  6. If no StartLogging found: trail still disabled — restore immediately")

    log("\n" + "=" * 60)
    log(f"Full report saved to: {LOG_FILE}")
    log("=" * 60)


# ----------------------------------------------------------
# Main
# ----------------------------------------------------------
def main():
    open(LOG_FILE, 'w').close()

    log(f"[{datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')}] Detection started")
    log("Scenario 3 — CloudTrail Disabling & Gap Analysis")

    events                                    = query_cloudtrail(REGION, ATTACK_START, ATTACK_END)
    suspicious, stop_event, start_event, gap  = analyze_events(events)
    report(suspicious, stop_event, start_event, gap, ATTACK_START, ATTACK_END)


if __name__ == "__main__":
    main()
