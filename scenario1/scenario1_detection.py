"""
Purple Team Detection — Scenario 1: S3 Misconfiguration & Data Exfiltration
Author: Omar (EY Internship — Purple Team Project)

Detection method 1 — boto3 lookup_events:
  Queries CloudTrail management events for GetCallerIdentity and ListBuckets
  called by an EC2 instance identity (username starting with i-)

Detection method 2 — Amazon Athena:
  Queries CloudTrail data events (GetObject) stored in S3 to identify
  exactly which files were exfiltrated by the attacker

Output: terminal report + detection_coverage_scenario1.txt
"""

import boto3
import json
import time
from datetime import datetime, timezone

# ============================================================
# CONFIG
# ============================================================
REGION          = "us-east-1"
ATTACK_START    = "2026-09-16T13:39:00Z"
ATTACK_END      = "2026-09-16T13:41:00Z"
LOG_FILE        = "detection_coverage_scenario1.txt"

# Athena config
ATHENA_DATABASE = "default"
ATHENA_TABLE    = "cloudtrail_logs_aws_cloudtrail_logs_964525385628_eaf08120"
ATHENA_OUTPUT   = "s3://aws-cloudtrail-logs-964525385628-eaf08120/athena-results/"
# ============================================================


def log(message):
    print(message)
    with open(LOG_FILE, "a") as f:
        f.write(message + "\n")


def parse_time(time_str):
    return datetime.strptime(time_str, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)


# ----------------------------------------------------------
# Method 1: lookup_events — management events
# ----------------------------------------------------------
def query_management_events(region, start_time, end_time):
    log("=" * 60)
    log("STEP 1 — Querying CloudTrail management events (lookup_events)")
    log(f"Window  : {start_time} → {end_time}")
    log(f"Events  : GetCallerIdentity, ListBuckets")
    log("=" * 60)

    ct     = boto3.client('cloudtrail', region_name=region)
    start  = parse_time(start_time)
    end    = parse_time(end_time)
    found  = []

    for event_name in ['GetCallerIdentity', 'ListBuckets']:
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


def analyze_management_events(events):
    log("\n" + "=" * 60)
    log("STEP 2 — Analyzing management events")
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

        source_ip = detail.get('sourceIPAddress', 'Unknown')
        user_type = detail.get('userIdentity', {}).get('type', 'Unknown')

        is_ec2_identity = username.startswith('i-')

        if is_ec2_identity:
            suspicious.append({
                'event_name' : event_name,
                'event_time' : str(event_time),
                'username'   : username,
                'user_type'  : user_type,
                'source_ip'  : source_ip,
                'severity'   : 'HIGH',
                'rule'       : 'EC2 identity performing S3/STS enumeration from external IP'
            })
            log(f"\n  [ALERT] {event_name}")
            log(f"    Time      : {event_time}")
            log(f"    Identity  : {username} ({user_type})")
            log(f"    Source IP : {source_ip}")
            log(f"    Severity  : HIGH")
        else:
            log(f"\n  [OK] {event_name} by {username} — expected identity")

    return suspicious


# ----------------------------------------------------------
# Method 2: Athena — data events (GetObject)
# ----------------------------------------------------------
def query_athena_getobject(database, table, output, attack_start, attack_end, region):
    log("\n" + "=" * 60)
    log("STEP 3 — Querying Athena for GetObject data events")
    log(f"Table   : {database}.{table}")
    log(f"Window  : {attack_start} → {attack_end}")
    log("=" * 60)

    athena = boto3.client('athena', region_name=region)

    # Query 1: all GetObject by EC2 identity
    query_all = f"""
    SELECT
        eventtime,
        sourceipaddress,
        useridentity.arn,
        useridentity.type,
        json_extract_scalar(requestparameters, '$.bucketName') AS bucket,
        json_extract_scalar(requestparameters, '$.key') AS object_key
    FROM {database}.{table}
    WHERE eventname = 'GetObject'
    AND eventtime BETWEEN '{attack_start}' AND '{attack_end}'
    AND useridentity.type = 'AssumedRole'
    ORDER BY eventtime ASC
    """

    # Query 2: sensitive files only (cardholder bucket)
    query_sensitive = f"""
    SELECT
        eventtime,
        sourceipaddress,
        json_extract_scalar(requestparameters, '$.bucketName') AS bucket,
        json_extract_scalar(requestparameters, '$.key') AS object_key
    FROM {database}.{table}
    WHERE eventname = 'GetObject'
    AND eventtime BETWEEN '{attack_start}' AND '{attack_end}'
    AND json_extract_scalar(requestparameters, '$.bucketName') LIKE '%cardholder%'
    ORDER BY eventtime ASC
    """

    results = {}

    for label, query in [('all_getobject', query_all), ('sensitive_files', query_sensitive)]:
        try:
            log(f"\nExecuting Athena query: {label}")

            response = athena.start_query_execution(
                QueryString=query,
                QueryExecutionContext={'Database': database},
                ResultConfiguration={'OutputLocation': output}
            )

            query_id = response['QueryExecutionId']
            log(f"  Query ID: {query_id}")
            log(f"  Waiting for results...")

            # Wait for query to complete
            while True:
                status = athena.get_query_execution(QueryExecutionId=query_id)
                state  = status['QueryExecution']['Status']['State']

                if state == 'SUCCEEDED':
                    log(f"  Query SUCCEEDED")
                    break
                elif state in ['FAILED', 'CANCELLED']:
                    reason = status['QueryExecution']['Status'].get('StateChangeReason', 'Unknown')
                    log(f"  Query {state}: {reason}")
                    results[label] = []
                    break
                else:
                    time.sleep(2)

            if state == 'SUCCEEDED':
                result = athena.get_query_results(QueryExecutionId=query_id)
                rows   = result['ResultSet']['Rows']
                # Skip header row
                data_rows = rows[1:] if len(rows) > 1 else []
                results[label] = data_rows
                log(f"  Rows returned: {len(data_rows)}")

        except Exception as e:
            log(f"  ERROR running Athena query '{label}': {e}")
            results[label] = []

    return results


def analyze_athena_results(athena_results):
    log("\n" + "=" * 60)
    log("STEP 4 — Analyzing Athena GetObject results")
    log("=" * 60)

    all_rows       = athena_results.get('all_getobject', [])
    sensitive_rows = athena_results.get('sensitive_files', [])

    if not all_rows:
        log("  No GetObject events found in Athena results")
        log("  Possible reason: S3 data events were not enabled during the attack")
        return [], []

    log(f"\n  Total GetObject events by attacker : {len(all_rows)}")

    # Group by bucket
    buckets = {}
    for row in all_rows:
        cells  = row.get('Data', [])
        bucket = cells[4].get('VarCharValue', 'Unknown') if len(cells) > 4 else 'Unknown'
        key    = cells[5].get('VarCharValue', 'Unknown') if len(cells) > 5 else 'Unknown'
        if bucket not in buckets:
            buckets[bucket] = []
        buckets[bucket].append(key)

    log(f"  Buckets accessed                   : {len(buckets)}")
    for bucket, keys in buckets.items():
        log(f"\n    Bucket: {bucket} ({len(keys)} objects)")
        for key in keys[:5]:  # show first 5
            log(f"      - {key}")
        if len(keys) > 5:
            log(f"      ... and {len(keys) - 5} more")

    log(f"\n  [ALERT] Sensitive files exfiltrated ({len(sensitive_rows)}):")
    for row in sensitive_rows:
        cells  = row.get('Data', [])
        time_  = cells[0].get('VarCharValue', '') if len(cells) > 0 else ''
        ip     = cells[1].get('VarCharValue', '') if len(cells) > 1 else ''
        bucket = cells[2].get('VarCharValue', '') if len(cells) > 2 else ''
        key    = cells[3].get('VarCharValue', '') if len(cells) > 3 else ''
        log(f"    [{time_}] {bucket}/{key} from {ip} — SEVERITY: HIGH")

    return all_rows, sensitive_rows


# ----------------------------------------------------------
# Final report
# ----------------------------------------------------------
def report(management_alerts, all_getobject, sensitive_files, start_time, end_time):
    log("\n" + "=" * 60)
    log("DETECTION COVERAGE REGISTER — Scenario 1")
    log("S3 Misconfiguration & Data Exfiltration via SSRF")
    log("=" * 60)

    log(f"\nAttack window          : {start_time} → {end_time}")
    log(f"Management alerts      : {len(management_alerts)}")
    log(f"GetObject events total : {len(all_getobject)}")
    log(f"Sensitive files hit    : {len(sensitive_files)}")

    log("\n--- COVERAGE SUMMARY ---")
    log("  Attack step 1 (SSRF)              : NOT visible in CloudTrail")
    log("                                      SSRF hits metadata service — no AWS API")
    log("  Attack step 2 (Pivot)             : VISIBLE — GetCallerIdentity by EC2 identity")
    log("  Attack step 3 (Bucket enum)       : VISIBLE — ListBuckets by EC2 identity")
    log("  Attack step 3 (File downloads)    : VISIBLE via Athena — GetObject data events")
    log(f"                                      {len(all_getobject)} total files downloaded")
    log(f"                                      {len(sensitive_files)} sensitive files (cardholder data)")
    log("\n  Detection method 1 : CloudTrail lookup_events (management events)")
    log("  Detection method 2 : Amazon Athena SQL (data events)")
    log("\n  False positive rate : LOW")
    log("  Alert latency       : 5-15 minutes (CloudTrail delivery delay)")
    log("  Blind spot          : SSRF step — requires VPC Flow Logs or WAF logs")

    log("\n--- TRIAGE STEPS FOR ANALYST ---")
    log("  1. Confirm EC2 instance ID in EC2 console")
    log("  2. Check IAM role attached to that EC2")
    log("  3. Verify if S3 access is expected for that role")
    log("  4. Compare source IP with EC2 public IP — mismatch = SSRF")
    log("  5. Run Athena query to get full list of exfiltrated files")
    log("  6. Check if cardholder or sensitive data was accessed")

    log("\n" + "=" * 60)
    log(f"Full report saved to: {LOG_FILE}")
    log("=" * 60)


# ----------------------------------------------------------
# Main
# ----------------------------------------------------------
def main():
    open(LOG_FILE, 'w').close()

    log(f"[{datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')}] Detection started")
    log("Scenario 1 — S3 Misconfiguration & Data Exfiltration")

    # Step 1 & 2: management events via lookup_events
    mgmt_events    = query_management_events(REGION, ATTACK_START, ATTACK_END)
    mgmt_alerts    = analyze_management_events(mgmt_events)

    # Step 3 & 4: data events via Athena
    athena_results = query_athena_getobject(
        ATHENA_DATABASE, ATHENA_TABLE, ATHENA_OUTPUT,
        ATTACK_START, ATTACK_END, REGION
    )
    all_getobject, sensitive_files = analyze_athena_results(athena_results)

    # Final report
    report(mgmt_alerts, all_getobject, sensitive_files, ATTACK_START, ATTACK_END)


if __name__ == "__main__":
    main()
