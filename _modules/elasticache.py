"""
:maintainer:    Steven Arcangeli <steven@highlig.ht>
:maturity:      new
:depends:       boto
:platform:      all

Module for manipulating Amazon Elasticache clusters

"""
try:
    import boto.elasticache
    import boto.exception
    from boto.s3.key import Key
    HAS_BOTO = True
except ImportError:
    HAS_BOTO = False

import json


# This prevents pylint from yelling at me
__salt__ = {}

__virtualname__ = 'elasticache'

def __virtual__():
    return __virtualname__ if HAS_BOTO else False


def get_cache_cluster(
    name,
    region,
    aws_key=None,
    aws_secret=None,
    ecconn=None):
    """
    Convenience method for retrieving a cache cluster

    """
    if ecconn is None:
        ecconn = __salt__['aws_util.ecconn'](region, aws_key, aws_secret)

    cache = None
    try:
        response = ecconn.describe_cache_clusters(name,
                                                  show_cache_node_info=True)
        cache = response['DescribeCacheClustersResponse']\
            ['DescribeCacheClustersResult']['CacheClusters'][0]
    except boto.exception.BotoServerError as e:
        if e.code is None:
            exc = json.loads(e.message)
            if exc.get('Error', {}).get('Code') != 'CacheClusterNotFound':
                raise
        elif e.code != 'CacheClusterNotFound':
            raise

    return cache


def manage(
    name,
    region,
    node_type,
    engine,
    engine_version=None,
    num_nodes=1,
    subnet_group=None,
    cache_security_groups=None,
    security_group_ids=None,
    snapshots=None,
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
    """
    Launch an Elasticache cluster or put it in the right state

    Parameters
    ----------
    name : str
        The name of the cluster
    region : str
        The AWS region to launch in
    node_type : str
        What size node the cluster contains. Node types can be found
        here: http://aws.amazon.com/elasticache/faqs/#g8
    engine : str, {'redis', 'memcached'}
        The name of the cache engine to be used for this cluster
    engine_version : str, optional
        The version number of the cache engine to be used for this cluster
    num_nodes : int, optional
        The number of nodes that should be present in the cluster
    subnet_group : str, optional
        The name of the cache subnet group to be used for the cache cluster.
    cache_security_groups : list, optional
        A list of cache security group names to associate with this cache
        cluster. Must be used outside of VPC.
    security_group_ids : list, optional
        One or more VPC security groups associated with the cache cluster.
    snapshots : list, optional
        A single-element string list containing an S3 object name that uniquely
        identifies a Redis RDB snapshot file stored in Amazon S3.  The snapshot
        file will be used to populate the Redis cache in the new cache cluster.
        The Amazon S3 object name cannot contain any commas.
    snapshot_optional : bool, optional
        If True, ignore the ``snapshots`` argument when the S3 object does not
        exist.
    preferred_availability_zone : str, optional
        The EC2 Availability Zone in which the cluster will be created
    preferred_maintenance_window : str, optional
        The weekly time range (in UTC) during which system maintenance can occur
        (ex. sun:05:00-sun:09:00)
    notification_topic_arn : str, optional
        The Amazon Resource Name (ARN) of the Amazon Simple Notification
        Service (SNS) topic to which notifications will be sent.  The Amazon
        SNS topic owner must be the same as the cache cluster owner.
    notification_topic_status : str, optional, {'active', 'inactive'}
        The status of the Amazon SNS notification topic. Notifications are sent
        only if the status is active.
    parameter_group : str, optional
        The name of the cache parameter group to associate with this cluster.
        If this argument is omitted, the default cache parameter group for the
        specified engine will be used.
    port : int, optional
        The port number on which each of the cache nodes will accept
        connections
    auto_minor_version_upgrade : bool, optional
        Determines whether minor engine upgrades will be applied automatically
        to the cache cluster during the maintenance window.
    preserve_nodes : list, optional
        List of node ids to *not* remove if ``num_nodes`` is less than the
        current number of nodes.
    remove_nodes : list, optional
        List of node ids to remove if ``num_nodes`` is less than the current
        number of nodes. The length of this list must exactly equal the number
        of nodes that will be terminated. If not specified then nodes will be
        chosen arbitrarily to be terminated.
    apply_immediately : bool, optional
        If True, this parameter causes any modifications (and any pending
        modifications) to be applied asynchronously and as soon as possible,
        regardless of the PreferredMaintenanceWindow setting for the cluster.
    test : bool, optional
        If true, don't actually perform any changes
    aws_key : str, optional
        The access key id for AWS. May also be specified as 'aws:key' in a
        pillar.
    aws_secret : str, optional
        The secret access key for AWS. May also be specified as 'aws:secret' in
        a pillar.

    Returns
    -------
    changes : dict
        The changes dict plus an additional key named 'action'. The 'action'
        will either be 'create' or 'modify'.

    Notes
    -----
    The boto launch method is documented here:
    http://boto.readthedocs.org/en/latest/ref/elasticache.html#boto.elasticache.layer1.ElastiCacheConnection.create_cache_cluster

    """
    ecconn = __salt__['aws_util.ecconn'](region, aws_key, aws_secret)

    cache = get_cache_cluster(name, region, aws_key, aws_secret, ecconn)

    if cache is None:
        # Create cache
        if not test:
            launch(name, region, node_type, engine, engine_version, num_nodes,
                   subnet_group, cache_security_groups, security_group_ids,
                   snapshots, snapshot_optional, preferred_availability_zone,
                   preferred_maintenance_window, notification_topic_arn,
                   parameter_group, port, auto_minor_version_upgrade, aws_key,
                   aws_secret, ecconn)

        return {'action': 'create'}
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

        if port is not None:
            nodes = cache.get('CacheNodes') or []
            for node in nodes:
                if port != node['Endpoint']['Port']:
                    raise ValueError("Port '{0}' is not '{1:d}', but port "
                                     "cannot be changed!"
                                     .format(node['Endpoint']['Port'], port))

        changes = modify(
            name, region, engine_version, num_nodes,
            cache_security_groups, security_group_ids,
            preferred_maintenance_window, notification_topic_arn,
            notification_topic_status, parameter_group,
            auto_minor_version_upgrade, preserve_nodes, remove_nodes,
            apply_immediately, test, aws_key, aws_secret, ecconn)
        changes['action'] = 'modify'
        return changes


def launch_replica(
    name,
    region,
    replication_group,
    preferred_availability_zone=None,
    test=None,
    aws_key=None,
        aws_secret=None):
    """
    Launch an Elasticache replica redis cluster

    Parameters
    ----------
    name : str
        The name of the cluster
    region : str
        The AWS region to launch in
    replication_group : str
        The name of the replication group to add the cluster to
    preferred_availability_zone : str, optional
        The EC2 Availability Zone in which the cluster will be created

    """
    ecconn = __salt__['aws_util.ecconn'](region, aws_key, aws_secret)

    cache = get_cache_cluster(name, region, aws_key, aws_secret, ecconn)

    if cache is None:
        if not test:
            params = {
                'CacheClusterId': name,
                'ReplicationGroupId': replication_group,
            }
            if preferred_availability_zone is not None:
                params['PreferredAvailabilityZone'] = \
                    preferred_availability_zone
            # This is a temporary hack around boto's broken API
            ecconn._make_request(
                action='CreateCacheCluster',
                verb='POST',
                path='/', params=params)
        return {'action': 'create'}
    return {'action': 'noop'}


def launch(
    name,
    region,
    node_type,
    engine,
    engine_version=None,
    num_nodes=1,
    subnet_group=None,
    cache_security_groups=None,
    security_group_ids=None,
    snapshot=None,
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
    """
    Launch an Elasticache cluster

    Most arguments are the same as :meth:`.manage`

    """
    if ecconn is None:
        ecconn = __salt__['aws_util.ecconn'](region, aws_key, aws_secret)

    if snapshot is not None:
        snapshots = [snapshot]
        if snapshot_optional:
            s3conn = __salt__['aws_util.s3conn'](aws_key, aws_secret)
            # If the snapshot doesn't exist, ignore it
            i = 0
            while i < len(snapshots):
                path = snapshots[i]
                path_components = path.split('/')
                bucket = s3conn.get_bucket(path_components[0])
                key = Key(bucket, '/'.join(path_components[1:]))
                if not key.exists():
                    del snapshots[i]
                else:
                    # Add read-only access to the snapshot if necessary
                    acl = key.get_acl().acl
                    can_read = False
                    for grant in acl.grants:
                        if grant.permission.lower() == 'read' and \
                                grant.email_address == 'aws-scs-s3-readonly@amazon.com':
                            can_read = True
                            break
                    if not can_read:
                        key.add_email_grant('READ',
                                            'aws-scs-s3-readonly@amazon.com')
                    i += 1
        for i in range(len(snapshots)):
            snapshots[i] = 'arn:aws:s3:::' + snapshots[i]
    else:
        snapshots = []

    ecconn.create_cache_cluster(
        name,
        num_nodes,
        node_type,
        engine,
        engine_version=engine_version,
        cache_parameter_group_name=parameter_group,
        cache_subnet_group_name=subnet_group,
        cache_security_group_names=cache_security_groups,
        security_group_ids=security_group_ids,
        snapshot_arns=snapshots,
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
    """
    Modify an Elasticache cluster

    Most arguments are the same as :meth:`.manage`

    """
    if ecconn is None:
        ecconn = __salt__['aws_util.ecconn'](region, aws_key, aws_secret)

    changes = {}

    response = ecconn.describe_cache_clusters(name, show_cache_node_info=True)
    cache = response['DescribeCacheClustersResponse']\
        ['DescribeCacheClustersResult']['CacheClusters'][0]

    # Num nodes
    to_remove = None

    nodes = cache.get('CacheNodes') or []
    if remove_nodes != None:
        to_remove = remove_nodes
    elif num_nodes < len(nodes):
        preserve_nodes = preserve_nodes or []
        for node in reversed(nodes):
            if node['CacheNodeId'] not in preserve_nodes:
                to_remove.append(node['CacheNodeId'])
                if len(nodes) - len(to_remove) == num_nodes:
                    break
        if len(nodes) - len(to_remove) != num_nodes:
            raise ValueError("Could not find enough nodes to terminate")

    if to_remove:
        changes['Removed nodes'] = to_remove
    elif num_nodes > len(nodes):
        # Don't try to add more nodes if the cluster isn't available
        if cache.get('CacheClusterStatus') == 'available':
            changes['Added nodes'] = num_nodes - len(nodes)

    # TODO: Cache security group names
    # TODO: Security group ids
    # preferred_maintenance_window
    if preferred_maintenance_window is not None and \
            preferred_maintenance_window != cache['PreferredMaintenanceWindow']:
        changes['Preferred maintenance window'] = \
            "Changed to '{0}'".format(preferred_maintenance_window)

    # TODO: Notification topic arn
    # Parameter group
    group_name = cache['CacheParameterGroup']['CacheParameterGroupName']
    if parameter_group is not None and parameter_group != group_name:
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

    if not test and changes:
        group = cache.get('ReplicationGroupId')
        if group is None:
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
        else:
            ecconn.modify_replication_group(
                group,
                cache_security_group_names=cache_security_groups,
                security_group_ids=security_group_ids,
                preferred_maintenance_window=preferred_maintenance_window,
                notification_topic_arn=notification_topic_arn,
                cache_parameter_group_name=parameter_group,
                notification_topic_status=notification_topic_status,
                apply_immediately=apply_immediately,
                engine_version=engine_version,
                auto_minor_version_upgrade=auto_minor_version_upgrade,
            )

    return changes


def delete(
    name,
    region,
    test=False,
    aws_key=None,
        aws_secret=None):
    """
    Delete an Elasticache cluster

    Most arguments are the same as :meth:`.manage`

    """
    ecconn = __salt__['aws_util.ecconn'](region, aws_key, aws_secret)


    cache = get_cache_cluster(name, region, aws_key, aws_secret, ecconn)

    if cache is not None:
        if not test:
            # If this is the primary of a replication group, delete it instead
            if cache.get('ReplicationGroupId'):
                group = get_replication_group(cache['ReplicationGroupId'],
                                              region, aws_key, aws_secret,
                                              ecconn)
                if len(group['MemberClusters']) == 1:
                    ecconn.delete_replication_group(cache['ReplicationGroupId'])
                    return True
            ecconn.delete_cache_cluster(name)
        return True


def manage_parameter_group(
    name,
    region,
    family,
    description,
    parameters,
    test=False,
    aws_key=None,
        aws_secret=None):
    """
    Create a parameter group or put it in the right state

    Parameters
    ----------
    name : str
        The name of the parameter group
    region : str
        The AWS region that contains the parameter group
    family : str, {'memcached1.4', 'redis2.6'}
        The name of the cache engine family the cache parameter group can be
        used with
    description : str
        A user-specified description for the cache parameter group
    parameters : dict
        Dictionary of key-value parameters
    test : bool, optional
        If true, don't actually perform any changes
    aws_key : str, optional
        The access key id for AWS. May also be specified as 'aws:key' in a
        pillar.
    aws_secret : str, optional
        The secret access key for AWS. May also be specified as 'aws:secret' in
        a pillar.

    Returns
    -------
    changes : dict
        The changes dict plus an additional key named 'action'. The 'action'
        will either be 'create' or 'modify'.

    Notes
    -----
    The boto create method is documented here:
    http://boto.readthedocs.org/en/latest/ref/elasticache.html#boto.elasticache.layer1.ElastiCacheConnection.create_cache_parameter_group

    Parameters for memcached are here:
    http://docs.aws.amazon.com/AmazonElastiCache/latest/UserGuide/CacheParameterGroups.Memcached.html

    Parameters for redis are here:
    http://docs.aws.amazon.com/AmazonElastiCache/latest/UserGuide/CacheParameterGroups.Redis.html

    """
    ecconn = __salt__['aws_util.ecconn'](region, aws_key, aws_secret)

    group = None
    try:
        response = ecconn.describe_cache_parameters(name)
        group = response['DescribeCacheParametersResponse']\
                        ['DescribeCacheParametersResult']
    except boto.exception.BotoServerError as e:
        if e.code is None:
            exc = json.loads(e.message)
            code = exc.get('Error', {}).get('Code')
            if code != 'CacheParameterGroupNotFound':
                raise
        elif e.code != 'CacheParameterGroupNotFound':
            raise

    if group is None:
        if not test:
            create_parameter_group(name, region, family, description,
                                   parameters, aws_key, aws_secret, ecconn)
        return {'action': 'create'}
    else:
        changes = modify_parameter_group(name, region, parameters, test,
                                         aws_key, aws_secret, ecconn, group)
        changes['action'] = 'modify'
        return changes


def create_parameter_group(
    name,
    region,
    family,
    description,
    parameters,
    aws_key=None,
    aws_secret=None,
        ecconn=None):
    """
    Create an Elasticache parameter group

    Most arguments are the same as :meth:`.create_or_modify_parameter_group`

    """
    if ecconn is None:
        ecconn = __salt__['aws_util.ecconn'](region, aws_key, aws_secret)

    ecconn.create_cache_parameter_group(name, family, description)

    modify_parameter_group(name, region, parameters, False, aws_key,
                           aws_secret, ecconn)


def modify_parameter_group(
    name,
    region,
    parameters,
    test=False,
    aws_key=None,
    aws_secret=None,
    ecconn=None,
        group=None):
    """
    Modify an Elasticache parameter group

    Most arguments are the same as :meth:`.create_or_modify_parameter_group`

    """
    if len(parameters) == 0:
        return

    if ecconn is None:
        ecconn = __salt__['aws_util.ecconn'](region, aws_key, aws_secret)

    if group is None:
        response = ecconn.describe_cache_parameters(name)
        group = response['DescribeCacheParametersResponse']\
                        ['DescribeCacheParametersResult']

    changes = {}
    to_modify = []

    for param in group['Parameters']:
        key = param['ParameterName']
        if key in parameters:
            val = parameters[key]
            if val is True:
                val = 'yes'
            elif val is False:
                val = 'no'
            elif isinstance(val, int):
                val = str(val)

            if val != param['ParameterValue']:
                changes[key] = "Changed to '{0}'".format(val)
                to_modify.append((key, val))

    if not test:
        # We can only modify up to 20 parameters per request
        for i in xrange(0, len(to_modify), 20):
            params = to_modify[i:i+20]
            ecconn.modify_cache_parameter_group(name, params)

    return changes


def delete_parameter_group(
    name,
    region,
    test=False,
    aws_key=None,
        aws_secret=None):
    """
    Delete an Elasticache parameter group

    Most arguments are the same as :meth:`.create_or_modify_parameter_group`

    """
    ecconn = __salt__['aws_util.ecconn'](region, aws_key, aws_secret)

    group = None
    try:
        groups = ecconn.describe_cache_parameter_groups(name)
        group = groups[0]
    except boto.exception.BotoServerError as e:
        if e.code is None:
            exc = json.loads(e.message)
            code = exc.get('Error', {}).get('Code')
            if code != 'CacheParameterGroupNotFound':
                raise
        elif e.code != 'CacheParameterGroupNotFound':
            raise

    if group is not None:
        if not test:
            ecconn.delete_cache_parameter_group(name)
            return True


def manage_security_group(
        name,
        region,
        description,
        authorized=(),
        test=False,
        aws_key=None,
        aws_secret=None):
    """
    Create a Cache Security Group and set the ACL

    Parameters
    ----------
    name : str
        The name of the cache security group
    region : str
        The AWS region that contains the cache security group
    description : str
        Human-readable description
    authorized : list
        List of items. Each item is either the name of an EC2 security group,
        or it is a (name, owner_id) tuple for an EC2 security group.
    test : bool, optional
        If true, don't actually perform any changes
    aws_key : str, optional
        The access key id for AWS. May also be specified as 'aws:key' in a
        pillar.
    aws_secret : str, optional
        The secret access key for AWS. May also be specified as 'aws:secret' in
        a pillar.

    Returns
    -------
    changes : dict
        The changes dict plus an additional key named 'action'. The 'action'
        will either be 'create' or 'modify'.

    """

    ecconn = __salt__['aws_util.ecconn'](region, aws_key, aws_secret)

    group = None
    try:
        response = ecconn.describe_cache_security_groups(name)
        group = response['DescribeCacheSecurityGroupsResponse']\
                        ['DescribeCacheSecurityGroupsResult']\
                        ['CacheSecurityGroups'][0]
    except boto.exception.BotoServerError as e:
        if e.code is None:
            exc = json.loads(e.message)
        e.code = exc.get('Error', {}).get('Code')
        if e.code != 'CacheSecurityGroupNotFound':
            raise

    if group is None:
        if not test:
            create_security_group(name, region, description, authorized,
                                  aws_key, aws_secret, ecconn)
        return {'action': 'create'}
    else:
        changes = modify_security_group(name, region, authorized, test,
                                        aws_key, aws_secret, ecconn)
        changes['action'] = 'modify'
        return changes


def create_security_group(
        name,
        region,
        description,
        authorized=(),
        aws_key=None,
        aws_secret=None,
        ecconn=None):
    """
    Create a Cache Security Group

    Most arguments are the same as :meth:`.manage_security_group`

    """
    if ecconn is None:
        ecconn = __salt__['aws_util.ecconn'](region, aws_key, aws_secret)

    ecconn.create_cache_security_group(name, description)

    modify_security_group(name, region, authorized, False, aws_key, aws_secret,
                          ecconn)


def modify_security_group(
        name,
        region,
        authorized=(),
        test=False,
        aws_key=None,
        aws_secret=None,
        ecconn=None):
    """
    Modify a Cache Security Group

    Most arguments are the same as :meth:`.manage_security_group`

    """
    if ecconn is None:
        ecconn = __salt__['aws_util.ecconn'](region, aws_key, aws_secret)

    ec2conn = __salt__['aws_util.ec2conn'](region, aws_key, aws_secret)

    changes = {}

    response = ecconn.describe_cache_security_groups(name)
    group = response['DescribeCacheSecurityGroupsResponse']\
                    ['DescribeCacheSecurityGroupsResult']\
                    ['CacheSecurityGroups'][0]

    ec2_groups = ec2conn.get_all_security_groups()
    ec2_group_map = {g.name: g for g in ec2_groups}
    for i, item in enumerate(list(authorized)):
        # Find the owner_id if necessary
        if isinstance(item, basestring):
            authorized[i] = (item, int(ec2_group_map[item].owner_id))

    groups_authorized = [(g['EC2SecurityGroupName'],
                          int(g['EC2SecurityGroupOwnerId'])) for g in
                         group['EC2SecurityGroups']]

    to_add = set(authorized) - set(groups_authorized)
    to_remove = set(groups_authorized) - set(authorized)

    if to_add:
        changes['Allow'] = [g[0] for g in to_add]
        if not test:
            for ec2_name, owner_id in to_add:
                ecconn.authorize_cache_security_group_ingress(name, ec2_name,
                                                              owner_id)

    if to_remove:
        changes['Revoke'] = [g[0] for g in to_remove]
        if not test:
            for ec2_name, owner_id in to_remove:
                ecconn.revoke_cache_security_group_ingress(name, ec2_name,
                                                           owner_id)

    return changes


def delete_security_group(
        name,
        region,
        test=None,
        aws_key=None,
        aws_secret=None):
    """
    Delete a Cache Security Group

    Most arguments are the same as :meth:`.manage_security_group`

    """
    ecconn = __salt__['aws_util.ecconn'](region, aws_key, aws_secret)

    try:
        response = ecconn.describe_cache_security_groups(name)
        group = response['DescribeCacheSecurityGroupsResponse']\
                        ['DescribeCacheSecurityGroupsResult']\
                        ['CacheSecurityGroups'][0]
    except boto.exception.BotoServerError as e:
        if e.code is None:
            exc = json.loads(e.message)
        e.code = exc.get('Error', {}).get('Code')
        if e.code != 'CacheSecurityGroupNotFound':
            raise

    if group is not None:
        if not test:
            ecconn.delete_cache_security_group(name)
        return True


def get_replication_group(
    name,
    region,
    aws_key=None,
    aws_secret=None,
    ecconn=None):
    """
    Convenience method for retrieving a replication group

    """
    if ecconn is None:
        ecconn = __salt__['aws_util.ecconn'](region, aws_key, aws_secret)

    group = None
    try:
        response = ecconn.describe_replication_groups(name)
        group = response['DescribeReplicationGroupsResponse']\
                        ['DescribeReplicationGroupsResult']\
                        ['ReplicationGroups'][0]
    except boto.exception.BotoServerError as e:
        if e.code is None:
            exc = json.loads(e.message)
        e.code = exc.get('Error', {}).get('Code')
        if e.code != 'ReplicationGroupNotFoundFault':
            raise
    return group


def create_replication_group(
    name,
    region,
    primary,
    description,
    test=False,
    aws_key=None,
        aws_secret=None):
    """
    Create a Replication Group

    Parameters
    ----------
    name : str
        The name of the replication group
    region : str
        The AWS region to contain the replication group
    primary : str
        The name of the ElastiCache cluster to replicate from
    description : str
        Human-readable description of the group
    test : bool, optional
        If true, don't actually perform any changes
    aws_key : str, optional
        The access key id for AWS. May also be specified as 'aws:key' in a
        pillar.
    aws_secret : str, optional
        The secret access key for AWS. May also be specified as 'aws:secret' in
        a pillar.

    """
    ecconn = __salt__['aws_util.ecconn'](region, aws_key, aws_secret)

    group = get_replication_group(name, region, aws_key, aws_secret, ecconn)

    if group is None:
        if not test:

            ecconn.create_replication_group(name, primary, description)
        return {'action': 'create'}
    return {'action': 'noop'}


def reboot(
    name,
    region,
        nodes=None):
    """
    Reboot some nodes in an Elasticache cluster

    Parameters
    ----------
    name : str
        The name of the cluster
    region : str
        The AWS region that contains the cluster
    nodes : list
        List of node ids to reboot

    """
    # TODO:
