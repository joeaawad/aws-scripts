import argparse
import boto3

autoscaling = boto3.client('autoscaling')
ecs = boto3.client('ecs')

def main(cluster_name: str, asg_name: str, desired_count: int):
    desired_change = get_change(asg_name, desired_count)

    instances = get_instances_to_remove(cluster_name, desired_change)

    drain_instances(cluster_name, instances)

    terminate_instances(instances)

    if get_change(asg_name, desired_count) != 0:
        raise RuntimeError(
            "Something went wrong and the ASG desired capacity does not match "
            "the desired value. Please investigate and improve this script.")

def get_change(asg_name: str, desired_count: int) -> int:
    asgs = autoscaling.describe_auto_scaling_groups(
        AutoScalingGroupNames=[asg_name]
    )['AutoScalingGroups']
    if len(asgs) == 0:
        raise ValueError("Unable to find Auto Scaling Group")
    elif len(asgs) > 1:
        raise ValueError("More than one Auto Scaling Group was found")

    desired_change = asgs[0]['DesiredCapacity'] - desired_count

    if desired_change < 0:
        raise ValueError(
            f"ASG {asg_name} has fewer than {desired_count} instances")
    elif desired_change == 0:
        print(f"ASG is at {desired_count} instances, nothing to do")
        exit()

    return desired_change

def get_instances_to_remove(cluster_name: str, desired_change: int) -> list:
    container_instance_arns = ecs.list_container_instances(
        cluster=cluster_name,
    )['containerInstanceArns']

    raw_instances = ecs.describe_container_instances(
        cluster=cluster_name,
        containerInstances=container_instance_arns
    )['containerInstances']

    sorted_instances = sorted(raw_instances, key = lambda i: i['registeredAt'])

    instances_to_remove = sorted_instances[:desired_change]

    instance_ids = [
        instance['ec2InstanceId'] for instance in instances_to_remove]

    return instance_ids

def drain_instances(cluster_name: str, instances: list):
    print(f"Draining the following instances: {instances}")

    response = ecs.update_container_instances_state(
        cluster=cluster_name,
        containerInstances=instances,
        status="DRAINING"
    )

    retries = 30

    while retries > 0:
        instance_descriptions = ecs.describe_container_instances(
            cluster=cluster_name,
            containerInstances=instances
        )['containerInstances']

        if all(instance['runningTasksCount'] == 0
                for instance in instance_descriptions):
            break

        retries -= 1
        print("Waiting on instances to drain...")
        sleep(10)
    else:
        raise RuntimeError(
            "Timed out waiting for instances to drain. The script can be "
            "safely rerun and will pick up from where it left off. This may "
            "be expected behavior if the tasks take longer than "
            f"{retries*10} seconds to drain.")

def terminate_instance(instances: list):
    print(f"Terminating the following instances: {instances}")

    for instance_id in instances:
        response = autoscaling.terminate_instance_in_auto_scaling_group(
            InstanceId=instance_id,
            ShouldDecrementDesiredCapacity=True
        )

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Scale down ECS hosts')

    parser.add_argument('cluster_name', type=str)
    parser.add_argument('asg_name', type=str)
    parser.add_argument('desired_count', type=int)

    args = parser.parse_args()

    main(args.cluster_name, args.asg_name, args.desired_count)
