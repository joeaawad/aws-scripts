"""Created by Joe Awad

This script provides an easy way to keep track of and enforce what security
groups have protocols and ports open to the internet. Simply add the
protocols you care about to IMPORTANT_PROTOCOLS and ports you care about to
IMPORTANT_PORTS. Then add any protocol exceptions to the PROTOCOL_WHITELIST
and any port exceptions to the PORT_WHITELIST. You can use a regex when
adding security group names in the whitelists so that it will whitelist
new security groups that follow the same naming convention automatically.
The script then writes the results to CSV.
"""
import boto3
import csv
import re

CSV = "security_groups.csv"

# "-1" protocol is how AWS indicates all protocols and ports are open
IMPORTANT_PROTOCOLS = [
    "-1"
]

IMPORTANT_PORTS = [
    22,
    80,
    443,
]

PROTOCOL_WHITELIST = {
    "NAT security group": "-1"
}

PORT_WHITELIST = {
    # SFTP
    "sftp security group": [
        "22",
    ],
    # App server
    "app server security group": [
        "443",
    ],
}

def check_ingress(sg_name: str, ingress: dict) -> str:
    """Check if the ingress rule needs attention"""
    from_port = ingress.get("FromPort")
    ip_ranges = ingress["IpRanges"]
    ingress_protocol = ingress["IpProtocol"]

    # If this is a blacklisted protocol, flag if not whitelisted
    if ingress_protocol in IMPORTANT_PROTOCOLS:
        for name, protocol in PROTOCOL_WHITELIST.items():
            if re.match(name, sg_name) and protocol == ingress_protocol:
                return "whitelisted"
        else:
            return "unauthorized"

    # If this is a port that we care about, run the following checks
    if from_port in IMPORTANT_PORTS:
        # Check against the PORT_WHITELIST
        for name, ports in PORT_WHITELIST.items():
            if re.match(name, sg_name):
                for port in ports:
                    if port == from_port:
                        return "whitelisted"

        # Check if the port is open to the world
        for ip in ip_ranges:
            if ip.get("CidrIp") == "0.0.0.0/0":
                return "unauthorized"

        # If IP addresses are specified, check if these are still necessary
        if len(ip_ranges) >= 1:
            return "investigate"
    else:
        # Even if it's not in IMPORTANT_PORTS, should still look into anything
        # open to the world
        for ip in ip_ranges:
            if ip.get("CidrIp") == "0.0.0.0/0":
                return "investigate"

def main():
    ec2 = boto3.client("ec2")
    securitygroups = ec2.describe_security_groups()["SecurityGroups"]

    with open(CSV, "w+") as f:
        csvwriter = csv.writer(f)
        for sg in securitygroups:
            for ingress in sg["IpPermissions"]:
                status = check_ingress(sg["GroupName"], ingress)
                csvwriter.writerow([
                    sg["GroupName"],
                    sg["GroupId"],
                    "ingress",
                    ingress.get("FromPort"),
                    ingress["IpProtocol"],
                    ingress["IpRanges"],
                    status])

    print(f"{CSV} created")

if __name__ == "__main__":
    main()
