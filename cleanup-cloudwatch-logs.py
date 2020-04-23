#!/usr/bin/env python
"""Created by Joe Awad

Set the expiration on cloudwatch logs that match a given prefix and delete
any empty log groups
"""

import argparse
import boto3

client = boto3.client("logs")

def get_log_groups(prefix: str) -> list:
    """Get all log groups that match the given prefix"""
    log_groups = []
    next_token = prefix

    print(f"Getting log groups that match {prefix}:")
    while prefix in next_token:
        response = client.describe_log_groups(
            logGroupNamePrefix=prefix,
            nextToken=next_token)

        if response["ResponseMetadata"]["HTTPStatusCode"] != 200:
            print(response)
            exit(1)

        for log_group in response["logGroups"]:
            log_groups.append(log_group["logGroupName"])

        next_token = response.get("nextToken", "")

        print(next_token)

    print(f"{len(log_groups)} matching log groups found\n")
    return log_groups

def check_expiration_eligible(
        log_group_name: str, retention_days: int, overwrite: bool) -> bool:
    """Check if we should change the log group's expiration setting"""
    if overwrite:
        return True

    matching_log_groups = client.describe_log_groups(
        logGroupNamePrefix=log_group_name)["logGroups"]

    for log_group in matching_log_groups:
        if log_group.get("logGroupName") == log_group_name:
            retention = log_group.get("retentionInDays")
            if retention == retention_days:
                print(f"{log_group_name} is already set to {retention_days}, "
                      f"nothing to do")
                return False
            elif retention is not None:
                print(f"{log_group_name} already has a retention policy of "
                      f"{retention}, skipping. Use --overwrite to overwrite "
                      f"existing policy")
                return False

    return True

def set_expiration(log_group_name: str, expire: bool, retention_days: int):
    """Change the log group's expiration setting"""
    if expire:
        response = client.put_retention_policy(
            logGroupName=log_group_name,
            retentionInDays=retention_days)
        if response["ResponseMetadata"]["HTTPStatusCode"] != 200:
            print(response)
            exit(1)
    else:
        print(f"Dry run, not setting expiration of {log_group_name}")


def check_delete_eligible(log_group_name: str) -> bool:
    """Check if the log group is empty and we can delete it or not"""
    streams_response = client.describe_log_streams(
        logGroupName=log_group_name, orderBy="LastEventTime", descending=True)

    if streams_response["ResponseMetadata"]["HTTPStatusCode"] != 200:
        print(streams_response)
        exit(1)

    # if no streams, can already know we can delete group and can exit early
    if len(streams_response["logStreams"]) == 0:
        return True

    log_stream_name = streams_response["logStreams"][0]["logStreamName"]
    events_response = client.get_log_events(
        logGroupName=log_group_name, logStreamName=log_stream_name)

    if events_response["ResponseMetadata"]["HTTPStatusCode"] != 200:
        print(events_response)
        exit(1)

    if len(events_response["events"]) == 0:
        return True
    else:
        return False

def delete_log_group(log_group_name: str, delete: bool):
    """Delete the log group"""
    if delete:
        print(f"Deleting log group {log_group_name}")
        response = client.delete_log_group(logGroupName=log_group_name)
        if response["ResponseMetadata"]["HTTPStatusCode"] != 200:
            print(response)
            exit(1)
    else:
        print(f"Dry run, not deleting {log_group_name}")

def main(prefix, expire, retention_days, overwrite, delete):
    log_group_names = get_log_groups(args.prefix)

    for log_group_name in log_group_names:
        print(f"Checking log group {log_group_name}")
        expiration_elibible = check_expiration_eligible(
            log_group_name, retention_days, overwrite)
        if expiration_elibible:
            set_expiration(log_group_name, expire, retention_days)
        delete_eligible = check_delete_eligible(log_group_name)
        if delete_eligible:
            delete_log_group(log_group_name, delete)

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "prefix", help="Prefix of log groups such as '/aws/lambda'")
    parser.add_argument(
        "--expire", action="store_true", default=False,
        help="Set expiration of log group to --retention-days")
    parser.add_argument(
        "--retention-days", default=30, help="Days to retain logs")
    parser.add_argument(
        "--overwrite", action="store_true", default=False,
        help="Force overwrite of expiration")
    parser.add_argument(
        "--delete", action="store_true", default=False,
        help="Delete empty log groups")
    args = parser.parse_args()

    main(args.prefix, args.expire, args.retention_days, args.overwrite,
         args.delete)
