import boto.elasticache
import boto.exception
from boto.s3.key import Key

# This prevents pylint from yelling at me
__pillar__ = {}

def create_or_modify_parameter_group(
    name,
    region):
    pass

def create_parameter_group(
    name,
    region):
    pass

def modify_parameter_group(
    name,
    region):
    pass

def launch_or_modify(
    name,
    region,
    node_type,
    engine,
    engine_version=None,
    num_nodes=1,
    replication_group=None,
    subnet_group=None,
    cache_security_groups=None,
    security_group_ids=None,
    snapshot_arns=None,
    snapshot_optional=False,
    preferred_availability_zone=None,
    preferred_maintenance_window=None,
    notification_topic_arn=None,
    notification_topic_status=None,
    parameter_group=None,
    port=None,
    auto_minor_version_upgrade=True,
    preserve_nodes=None,
    remove_nodes=None,
    apply_immediately=None,
    test=False,
    aws_key=None,
    aws_secret=None):

    if aws_key is None:
        aws_key = __pillar__.get('aws', {}).get('key')
    if aws_secret is None:
        aws_secret = __pillar__.get('aws', {}).get('secret')

    if not aws_key or not aws_secret:
        raise TypeError("No aws credentials found! You need to define the "
                        "pillar values 'aws:key' and 'aws:secret'")


    ecconn = boto.elasticache.connect_to_region(
        region,
        aws_access_key_id=aws_key,
        aws_secret_access_key=aws_secret)

    try:
        response = ecconn.describe_cache_clusters(name,
                                                  show_cache_node_info=True)
        cache = response['DescribeCacheClustersResponse']\
            ['DescribeCacheClustersResult']['CacheClusters']
    except boto.exception.BotoServerError as e:
        if e.code == 'LoadBalancerNotFound':
            cache = None
        else:
            raise

    if cache is None:
        # Create cache
        if not test:
            launch(name, region, node_type, engine, engine_version, num_nodes,
                   replication_group, subnet_group, cache_security_groups,
                   security_group_ids, snapshot_arns, snapshot_optional,
                   preferred_availability_zone, preferred_maintenance_window,
                   notification_topic_arn, parameter_group, port,
                   auto_minor_version_upgrade, aws_key, aws_secret, ecconn)

            # Some fields (like notification_topic_status) cannot be specified
            # on launch, and must be mutated after the fact
            modify(name, region, engine_version, num_nodes,
                   replication_group, cache_security_groups,
                   security_group_ids, preferred_maintenance_window,
                   notification_topic_arn, notification_topic_status,
                   parameter_group, auto_minor_version_upgrade, preserve_nodes,
                   remove_nodes, apply_immediately, test, aws_key, aws_secret,
                   ecconn)

        return {'action': 'launch'}
    else:
        # Modify cache
        if engine != cache['Engine']:
            raise ValueError("Engine '{0}' is not '{1}', but engine cannot be "
                             "changed!".format(cache['Engine'], engine))
        if subnet_group != cache['CacheSubnetGroupName']:
            raise ValueError("Subnet '{0}' is not '{1}', but subnet cannot be "
                             "changed!".format(cache['CacheSubnetGroupName'],
                                               subnet_group))
        if preferred_availability_zone != cache['PreferredAvailabilityZone']:
            raise ValueError("Preferred availability zone '{0}' is not '{1}', "
                             "but it cannot be changed!"
                             .format(cache['PreferredAvailabilityZone'],
                                     preferred_availability_zone))
        if node_type != cache['CacheNodeType']:
            raise ValueError("Node type '{0}' is not '{1}', but node type "
                             "cannot be changed!".format(cache['CacheNodeType'],
                                                         node_type))
        for node in cache.get('CacheNodes', []):
            if port != node['Endpoint']['Port']:
                raise ValueError("Port '{0:d}' is not '{1:d}', but port "
                                 "cannot be changed!"
                                 .format(node['Endpoint']['Port'], port))

        changes = modify(
            name, region, engine_version, num_nodes,
            replication_group, cache_security_groups, security_group_ids,
            preferred_maintenance_window, notification_topic_arn,
            notification_topic_status, parameter_group,
            auto_minor_version_upgrade, preserve_nodes, remove_nodes,
            apply_immediately, test, aws_key, aws_secret, ecconn)
        changes['action'] = 'modify'
        return changes


def launch(
    name,
    region,
    node_type,
    engine,
    engine_version=None,
    num_nodes=1,
    replication_group=None,
    subnet_group=None,
    cache_security_groups=None,
    security_group_ids=None,
    snapshot_arns=None,
    snapshot_optional=False,
    preferred_availability_zone=None,
    preferred_maintenance_window=None,
    notification_topic_arn=None,
    parameter_group=None,
    port=None,
    auto_minor_version_upgrade=True,
    aws_key=None,
    aws_secret=None,
    ecconn=None):

    if aws_key is None:
        aws_key = __pillar__.get('aws', {}).get('key')
    if aws_secret is None:
        aws_secret = __pillar__.get('aws', {}).get('secret')

    if not aws_key or not aws_secret:
        raise TypeError("No aws credentials found! You need to define the "
                        "pillar values 'aws:key' and 'aws:secret'")

    if snapshot_arns is not None:
        if snapshot_optional:
            s3conn = boto.connect_s3(aws_access_key_id=aws_key,
                                     aws_secret_access_key=aws_secret)
            # If the snapshot doesn't exist, ignore it
            i = 0
            while i < len(snapshot_arns):
                snapshot = snapshot_arns[i]
                path = snapshot.split(':::')[1]
                path_components = path.split('/')
                bucket = s3conn.get_bucket(path_components[0])
                key = Key(bucket, '/'.join(path_components[1:]))
                if not key.exists():
                    del snapshot_arns[i]
                else:
                    i += 1
            if len(snapshot_arns) == 0:
                snapshot_arns = None

    if ecconn is None:
        ecconn = boto.elasticache.connect_to_region(
            region,
            aws_access_key_id=aws_key,
            aws_secret_access_key=aws_secret)

    ecconn.create_cache_cluster(
            name,
            num_nodes,
            node_type,
            engine,
            replication_group_id=replication_group,
            engine_version=engine_version,
            cache_parameter_group_name=parameter_group,
            cache_subnet_group_name=subnet_group,
            cache_security_group_names=cache_security_groups,
            security_group_ids=security_group_ids,
            snapshot_arns=snapshot_arns,
            preferred_availability_zone=preferred_availability_zone,
            preferred_maintenance_window=preferred_maintenance_window,
            port=port,
            notification_topic_arn=notification_topic_arn,
            auto_minor_version_upgrade=auto_minor_version_upgrade)


def modify(
    name,
    region,
    engine_version=None,
    num_nodes=1,
    replication_group=None, # Maybe we can't change this?
    cache_security_groups=None,
    security_group_ids=None,
    preferred_maintenance_window=None,
    notification_topic_arn=None,
    notification_topic_status=None,
    parameter_group=None,
    auto_minor_version_upgrade=True,
    preserve_nodes=None,
    remove_nodes=None,
    apply_immediately=None,
    test=False,
    aws_key=None,
    aws_secret=None,
    ecconn=None):

    if aws_key is None:
        aws_key = __pillar__.get('aws', {}).get('key')
    if aws_secret is None:
        aws_secret = __pillar__.get('aws', {}).get('secret')

    if not aws_key or not aws_secret:
        raise TypeError("No aws credentials found! You need to define the "
                        "pillar values 'aws:key' and 'aws:secret'")

    if ecconn is None:
        ecconn = boto.elasticache.connect_to_region(
            region,
            aws_access_key_id=aws_key,
            aws_secret_access_key=aws_secret)

    changes = {}

    response = ecconn.describe_cache_clusters(name)
    cache = response['DescribeCacheClustersResponse']\
        ['DescribeCacheClustersResult']['CacheClusters']


    # Num nodes
    to_remove = None

    if remove_nodes != None:
        to_remove = remove_nodes
    elif num_nodes < len(cache['CacheNodes']):
        preserve_nodes = preserve_nodes or []
        for node in reversed(cache['CacheNodes']):
            if node['CacheNodeId'] not in preserve_nodes:
                to_remove.append(node['CacheNodeId'])

    if to_remove:
        changes['Removed nodes'] = to_remove
    if num_nodes > len(cache['CacheNodes']):
        changes['Added nodes'] = num_nodes - cache['CacheNodes']


    # TODO: Cache security group names


    # TODO: Security group ids


    # preferred_maintenance_window
    if preferred_maintenance_window is not None and \
    preferred_maintenance_window != cache['PreferredMaintenanceWindow']:
        changes['Preferred maintenance window'] = \
                "Changed to {0}".format(preferred_maintenance_window)


    # TODO: Notification topic arn


    # Parameter group
    if parameter_group is not None and \
    parameter_group != cache['CacheParameterGroup']:
        changes['Parameter group'] = ("Changed to {0}".format(parameter_group))


    # TODO: Notification topic status


    # Engine version
    if engine_version is not None and \
    engine_version != cache['EngineVersion']:
        changes['EngineVersion'] = "Changed to {0}".format(engine_version)


    # Auto minor version upgrade
    if auto_minor_version_upgrade is not None and \
    auto_minor_version_upgrade != cache['AutoMinorVersionUpgrade']:
        changes['Auto minor version upgrade'] = ("Enabled" if
                                                 auto_minor_version_upgrade
                                                 else "Disabled")

    if not test:
        ecconn.modify_cache_cluster(
            name,
            num_cache_nodes=num_nodes,
            cache_node_ids_to_remove=to_remove,
            cache_security_group_names=cache_security_groups,
            security_group_ids=security_group_ids,
            preferred_maintenance_window=preferred_maintenance_window,
            notification_topic_arn=notification_topic_arn,
            cache_parameter_group_name=parameter_group,
            notification_topic_status=notification_topic_status,
            apply_immediately=apply_immediately,
            engine_version=engine_version,
            auto_minor_version_upgrade=auto_minor_version_upgrade)

    return changes

def delete(
    name,
    region,
    test=False,
    aws_key=None,
    aws_secret=None):

    if aws_key is None:
        aws_key = __pillar__.get('aws', {}).get('key')
    if aws_secret is None:
        aws_secret = __pillar__.get('aws', {}).get('secret')

    if not aws_key or not aws_secret:
        raise TypeError("No aws credentials found! You need to define the "
                        "pillar values 'aws:key' and 'aws:secret'")

    ecconn = boto.elasticache.connect_to_region(region,
                                                aws_access_key_id=aws_key,
                                                aws_secret_access_key=aws_secret)

    try:
        ecconn.describe_cache_clusters(name)
        if not test:
            ecconn.delete_cache_cluster(name)
        return True
    except boto.exception.BotoServerError as e:
        if e.code == 'LoadBalancerNotFound':
            return None
        else:
            raise

def reboot(
    name,
    region,
    nodes=None):
    pass

def create_replication_group(
    name,
    region):
    pass

def modify_replication_group(
    name,
    region):
    pass

def delete_replication_group(
    name,
    region):
    pass
