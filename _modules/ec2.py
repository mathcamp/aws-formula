"""
:maintainer:    Steven Arcangeli <steven@highlig.ht>
:maturity:      new
:depends:       boto
:platform:      all

Module for manipulating Amazon EC2 servers

"""
import random
try:
    import boto.ec2
    import boto.exception
    HAS_BOTO = True
except ImportError:
    HAS_BOTO = False


# This prevents pylint from yelling at me
__salt__ = {}

__virtualname__ = 'ec2'


def __virtual__():
    return __virtualname__ if HAS_BOTO else False


# EC2 servers

def manage(
    name,
    region,
    key_name,
    ami,
    security_groups=None,
    instance_type='m1.small',
    kernel=None,
    user_data=None,
    termination_protection=False,
    addressing_type=None,
    placement=None,
    ramdisk_id=None,
    monitoring_enabled=False,
    subnet_id=None,
    block_device_map=None,
    instance_initiated_shutdown_behavior=None,
    private_ip_address=None,
    placement_group=None,
    additional_info=None,
    instance_profile_name=None,
    instance_profile_arn=None,
    tenancy=None,
    ebs_optimized=False,
    network_interfaces=None,
    test=False,
    aws_key=None,
        aws_secret=None):
    """
    Manage a single instance

    Parameters
    ----------
    name : str
        Base name for launched servers. The server names will have a digit
        appended, such as "name1", "name2", etc.
    region : str
        The AWS region to launch the servers in
    key_name : str
        The name of the SSH key that will have access to the servers
    ami : str
        The ID of the image to run
    security_groups : list, optional
        List of EC2 security groups these servers belong to
    instance_type : str, optional
        The type of instances to launch (default m1.small)
    kernel : str, optional
        The ID of the kernel with which to launch the instances
    user_data : str, optional
        The Base64-encoded MIME user data to be made available to the
        instance(s) in this reservation.
    termination_protection : bool, optional
        If True, the instances will will not be able to be terminated via the
        API
    addressing_type : ???, optional
        There is suspiciously no documentation on this parameter. GOOD LUCK.
    placement : str, optional
        The Availability Zone to launch instances into
    ramdisk_id : str, optional
        The ID of the RAM disk with which to launch the instances
    monitoring_enabled : bool, optional
        Enable CloudWatch monitoring on the instance
    subnet_id : str, optional
        The subnet ID within which to launch the instances for VPC
    block_device_map : dict
        Dict of dicts that map device name (e.g. /dev/sda1) to a dict of
        keyword arguments to the constructor for
        :class:`boto.ec2.blockdevicemapping.BlockDeviceType`
    instance_initiated_shutdown_behavior : str, {'stop', 'terminate'}, optional
        Specifies whether the instance stops or terminates on
        instance-initiated shutdown
    private_ip_address : str, optional
        If you're using VPC, you can optionally use this parameter to assign
        the instance a specific available IP address from the subnet. I don't
        quite know how this works when launching multiple instances.
    placement_group : str, optional
        If specified, this is the name of the placement group in which the
        instance(s) will be launched
    additional_info : str, optional
        Specifies additional information to make available to the instances
    instance_profile_name : str, optional
        The name of the IAM Instance Profile (IIP) to associate with the
        instances
    instance_profile_arn : str, optional
        The Amazon resource name (ARN) of the IAM Instance Profile (IIP) to
        associate with the instances
    tenancy : str, optional
        The tenancy of the instance you want to launch. An instance with a
        tenancy of 'dedicated' runs on single-tenant hardware and can only be
        launched into a VPC. Valid values are:"default" or "dedicated". NOTE:
        To use dedicated tenancy you MUST specify a VPC subnet-ID as well.
    ebs_optimized : bool, optional
        Whether the instance is optimized for EBS I/O. This optimization
        provides dedicated throughput to Amazon EBS and an optimized
        configuration stack to provide optimal EBS I/O performance. This
        optimization isn't available with all instance types.
    network_interfaces : list
        List of dicts. Dicts are keyword argument constructors for
        :class:`boto.ec2.networkinterface.NetworkInterfaceSpecification`
    remove_ids : list, optional
        Instance ids to be removed if ``count`` is less than the number of
        active servers. remove_ids must be exactly the correct length. If
        remove_ids is not specified, salt will pick servers at random to
        terminate.
    preserve_ids : list, optional
        Instance ids to *not* be removed if ``count`` is less than the number of
        active servers. The servers to terminate will be chosen at random from
        the remaining available instances.
    force_termination : bool, optional
        If True, terminate the instances even if they have disabled API
        termination
    test : bool, optional
        If true, don't actually perform any changes
    aws_key : str, optional
        The access key id for AWS. May also be specified as 'aws:key' in a
        pillar.
    aws_secret : str, optional
        The secret access key for AWS. May also be specified as 'aws:secret' in
        a pillar.

    Notes
    -----
    The boto launch method is documented here:
    http://boto.readthedocs.org/en/latest/ref/ec2.html#boto.ec2.connection.EC2Connection.run_instances

    TODO: This does not modify attributes on existing instances.

    """
    ec2conn = __salt__['aws_util.ec2conn'](region, aws_key, aws_secret)

    tags = ec2conn.get_all_tags()
    present = False
    for tag in tags:
        if tag.name.lower() == 'name' and tag.value == name:
            present = True
            break

    if not present:
        if not test:
            launch(name, region, key_name, [name], ami, security_groups,
                   instance_type, kernel, user_data, termination_protection,
                   addressing_type, placement, ramdisk_id, monitoring_enabled,
                   subnet_id, block_device_map,
                   instance_initiated_shutdown_behavior, private_ip_address,
                   placement_group, None, additional_info,
                   instance_profile_name, instance_profile_arn, tenancy,
                   ebs_optimized, network_interfaces, aws_key, aws_secret,
                   ec2conn)
        return {'action': 'create'}
    return {'action': 'noop'}


def launch(
    name,
    region,
    key_name,
    hostnames,
    ami,
    security_groups=None,
    instance_type='m1.small',
    kernel=None,
    user_data=None,
    termination_protection=False,
    addressing_type=None,
    placement=None,
    ramdisk_id=None,
    monitoring_enabled=False,
    subnet_id=None,
    block_device_map=None,
    instance_initiated_shutdown_behavior=None,
    private_ip_address=None,
    placement_group=None,
    client_token=None,
    additional_info=None,
    instance_profile_name=None,
    instance_profile_arn=None,
    tenancy=None,
    ebs_optimized=False,
    network_interfaces=None,
    aws_key=None,
    aws_secret=None,
        ec2conn=None):
    """
    Launch servers with a base name

    Most parameters are described in :meth:`.manage`

    Parameters
    ----------
    hostnames : list
        List of names of servers to launch. Will launch one server per name.
    client_token : str
        Unique, case-sensitive identifier you provide to ensure idempotency of
        the request. Maximum 64 ASCII characters.

    """

    if ec2conn is None:
        ec2conn = __salt__['aws_util.ec2conn'](region, aws_key, aws_secret)

    if network_interfaces is not None:
        network_interfaces = [boto.ec2.networkinterface.NetworkInterfaceSpecification(
            **args) for args in network_interfaces]

    if block_device_map is not None:
        bdm = boto.ec2.blockdevicemapping.BlockDeviceMapping()
        for dev, args in block_device_map.iteritems():
            bdm[dev] = boto.ec2.blockdevicemapping.BlockDeviceType(**args)
        block_device_map = bdm

    reservation = ec2conn.run_instances(
        image_id=ami,
        min_count=len(hostnames),
        max_count=len(hostnames),
        key_name=key_name,
        security_groups=security_groups,
        instance_type=instance_type,
        kernel_id=kernel,
        user_data=user_data,
        disable_api_termination=termination_protection,
        addressing_type=addressing_type,
        placement=placement,
        ramdisk_id=ramdisk_id,
        monitoring_enabled=monitoring_enabled,
        subnet_id=subnet_id,
        block_device_map=block_device_map,
        instance_initiated_shutdown_behavior=
        instance_initiated_shutdown_behavior,
        private_ip_address=private_ip_address,
        placement_group=placement_group,
        client_token=client_token,
        additional_info=additional_info,
        instance_profile_name=instance_profile_name,
        instance_profile_arn=instance_profile_arn,
        tenancy=tenancy,
        ebs_optimized=ebs_optimized,
        network_interfaces=network_interfaces)

    for name, instance in zip(hostnames, reservation.instances):
        ec2conn.create_tags([instance.id], {"Name": name})


def terminate(name,
              region,
              force_termination=False,
              test=False,
              aws_key=None,
              aws_secret=None):
    """
    Terminate an instance

    Parameters are described in :meth:`.manage`

    """
    ec2conn = __salt__['aws_util.ec2conn'](region, aws_key, aws_secret)

    tags = ec2conn.get_all_tags()
    all_names = set([tag.value for tag in tags if tag.name.lower() == 'name'])
    server_tag = None
    for tag in tags:
        if tag.name.lower() == 'name' and tag.value == name:
            server_tag = tag
            break

    if server_tag is not None:
        if not test:
            instances = ec2conn.get_only_instances(
                instance_ids=[server_tag.res_id])
            server = instances[0]

            if force_termination:
                if server.get_attribute('disableApiTermination'):
                    server.modify_attribute('disableApiTermination', False)

            ec2conn.terminate_instances([server.id])
            _rename_tag_deleted(ec2conn, server_tag, all_names)
        return True

    return False


def _rename_tag_deleted(ec2conn, tag, all_names):
    """
    Rename a name tag on a server to mark it as deleted

    This helps to avoid naming conflicts with servers that have been terminated
    but are still visible.

    """
    attempts = 3
    for i in range(attempts):
        try:
            ec2conn.delete_tags([tag.res_id], {'Name': tag.value})
            break
        except boto.exception.EC2ResponseError:
            if i == attempts - 1:
                raise
    del_name = _find_free_name(all_names, 'deleted-' + tag.value)
    for i in range(attempts):
        try:
            ec2conn.create_tags([tag.res_id], {'Name': del_name})
            break
        except boto.exception.EC2ResponseError:
            if i == attempts - 1:
                raise


def _find_free_name(all_names, name):
    """
    Find server names that are available

    Parameters
    ----------
    all_names : list or set
        All names for all servers in the region
    name : str
        The base name to look for

    Returns
    -------
    name : str

    """
    i = 1
    search_name = name + str(i)
    while name in all_names:
        i += 1
        search_name = name + str(i)
    return search_name


# Security groups

def manage_security_group(
        name,
        region,
        description,
        vpc_id=None,
        rules=None,
        rules_egress=None,
        test=False,
        aws_key=None,
        aws_secret=None):
    """
    Launch or modify a security group

    Parameters
    ----------
    name : str
        Name of the security group
    region : str
        The AWS region to create the security group in
    description : str
        Short description of the security group
    vpc_id : str, optional
        The ID of the VPC to create the security group in
    rules : list, optional
        A list of firewall rules for the security group. Each rule is a dict
        with the keys 'ip_protocol' (tcp, udp, icmp), 'from_port' and 'to_port'
        (denoting a port range, e.g. 8080-8090), and *either* cidr_ip (e.g.
        '0.0.0.0/0') *or* src_security_group (e.g. 'other-group')
    rules_egress : list, optional
        TODO: This is not hooked up yet
    test : bool, optional
        If true, don't actually perform any changes
    aws_key : str, optional
        The access key id for AWS. May also be specified as 'aws:key' in a
        pillar.
    aws_secret : str, optional
        The secret access key for AWS. May also be specified as 'aws:secret' in
        a pillar.

    """
    ec2conn = __salt__['aws_util.ec2conn'](region, aws_key, aws_secret)

    groups = ec2conn.get_all_security_groups()
    group = None
    for security_group in groups:
        if security_group.name == name:
            group = security_group
            break

    if group is None:
        if not test:
            create_security_group(name, region, description, vpc_id, rules,
                                  rules_egress, aws_key, aws_secret, ec2conn)
        return {'action': 'create'}
    else:
        changes = modify_security_group(name, region, rules, rules_egress,
                                        None, test, aws_key, aws_secret,
                                        ec2conn)
        changes['action'] = 'modify'
        return changes


def create_security_group(
        name,
        region,
        description,
        vpc_id=None,
        rules=None,
        rules_egress=None,
        aws_key=None,
        aws_secret=None,
        ec2conn=None):
    """
    Create a security group.

    Most parameters are described in :meth:`.manage_security_group`

    """
    if ec2conn is None:
        ec2conn = __salt__['aws_util.ec2conn'](region, aws_key, aws_secret)

    group = ec2conn.create_security_group(name, description, vpc_id)

    modify_security_group(name, region, rules, rules_egress, group.id, False,
                          aws_key, aws_secret, ec2conn, group)


def create_bare_security_group(
    name,
    region,
    description,
    vpc_id=None,
    test=False,
    aws_key=None,
        aws_secret=None):
    """
    Make sure a security group is present

    Parameters
    ----------
    name : str
        Name of the security group
    region : str
        The AWS region to create the security group in
    description : str
        Short description of the security group
    vpc_id : str, optional
        The ID of the VPC to create the security group in
    test : bool, optional
        If true, don't actually perform any changes
    aws_key : str, optional
        The access key id for AWS. May also be specified as 'aws:key' in a
        pillar.
    aws_secret : str, optional
        The secret access key for AWS. May also be specified as 'aws:secret' in
        a pillar.

    """

    ec2conn = __salt__['aws_util.ec2conn'](region, aws_key, aws_secret)

    groups = ec2conn.get_all_security_groups()
    group = None
    for security_group in groups:
        if security_group.name == name:
            group = security_group
            break

    if group is None:
        if not test:
            ec2conn.create_security_group(name, description, vpc_id)
        return {'action': 'create'}
    else:
        return {'action': 'noop'}


def modify_security_group(
        name,
        region,
        rules,
        rules_egress,
        group_id=None,
        test=False,
        aws_key=None,
        aws_secret=None,
        ec2conn=None,
        group=None):
    """
    Modify the rules of a security group

    Most parameters are described in :meth:`.manage_security_group`

    """
    rules = rules or []
    rules_egress = rules_egress or []

    if ec2conn is None:
        ec2conn = __salt__['aws_util.ec2conn'](region, aws_key, aws_secret)

    groups = ec2conn.get_all_security_groups()
    if group is None:
        for security_group in groups:
            if (group_id is None and security_group.name == name) or \
                    (group_id is not None and security_group.id == group_id):
                group = security_group
                break

    group_map = {g.name: g for g in groups}

    changes = {}

    grp_rules = []
    for rule in group.rules:
        for grant in rule.grants:
            grp_dict = {
                'ip_protocol': rule.ip_protocol,
                'from_port': int(rule.from_port),
                'to_port': int(rule.to_port),
            }
            if grant.cidr_ip is None:
                grp_dict['src_security_group_name'] = grant.name
                grp_dict['src_security_group_owner_id'] = grant.owner_id
            else:
                grp_dict['cidr_ip'] = grant.cidr_ip
            grp_rules.append(grp_dict)

    for rule in rules:
        if 'src_security_group' in rule:
            rule['src_security_group_name'] = rule['src_security_group']
            rule['src_security_group_owner_id'] = group_map[
                rule['src_security_group']].owner_id
            del rule['src_security_group']

    freeze = lambda rule_dict: tuple(sorted([(k, v) for k, v in
                                             rule_dict.iteritems()]))

    to_add = (set([freeze(rule) for rule in rules]) -
              set([freeze(rule) for rule in grp_rules]))
    to_add = [dict(rule) for rule in to_add]

    for rule in to_add:
        if not test:
            ec2conn.authorize_security_group(group_id=group.id, **rule)
    if len(to_add) > 0:
        changes['Added'] = "{0:d} rule{1}".format(len(to_add), '' if
                                                  len(to_add) == 1 else 's')

    to_remove = (set([freeze(rule) for rule in grp_rules]) -
                 set([freeze(rule) for rule in rules]))
    to_remove = [dict(rule) for rule in to_remove]

    for rule in to_remove:
        if not test:
            ec2conn.revoke_security_group(group_id=group.id, **rule)
    if len(to_remove) > 0:
        changes['Removed'] = "{0:d} rule{1}".format(len(to_remove), '' if
                                                    len(to_remove) == 1 else 's')

    return changes


def delete_security_group(
        name,
        region,
        group_id=None,
        test=None,
        aws_key=None,
        aws_secret=None):
    """
    Delete a security group.

    Most parameters are described in :meth:`.manage_security_group`

    """

    ec2conn = __salt__['aws_util.ec2conn'](region, aws_key, aws_secret)

    if group_id is not None:
        groups = ec2conn.get_all_security_groups(group_ids=[group_id])
    else:
        groups = ec2conn.get_all_security_groups(groupnames=[name])

    if len(groups) > 0:
        group = groups[0]
        if not test:
            ec2conn.delete_security_group(name, group.id)
        return True
    else:
        return False


# Key pairs

def manage_keypair(
    name,
    region,
    content,
    test=False,
    aws_key=None,
        aws_secret=None):
    """
    Create or replace an EC2 Keypair

    Parameters
    ----------
    name : str
        Name of the keypair
    region : str
        The AWS region to create the keypair in
    content : str
        The public key
    test : bool, optional
        If true, don't actually perform any changes
    aws_key : str, optional
        The access key id for AWS. May also be specified as 'aws:key' in a
        pillar.
    aws_secret : str, optional
        The secret access key for AWS. May also be specified as 'aws:secret' in
        a pillar.

    """

    ec2conn = __salt__['aws_util.ec2conn'](region, aws_key, aws_secret)

    keypair = ec2conn.get_key_pair(name)
    if keypair is None:
        if not test:
            ec2conn.import_key_pair(name, content)
        return {'action': 'create'}
    else:
        # We have to upload a test keypair and check the fingerprint because
        # Amazon uses some sort of weird mutant fingerprint instead of MD5
        # like EVERYONE ELSE IN THE WORLD
        testname = 'test' + str(random.randint(0, 1000000))
        test_keypair = ec2conn.import_key_pair(testname, content)
        if test_keypair.fingerprint == keypair.fingerprint:
            ec2conn.delete_key_pair(testname)
            return {'action': 'noop'}
        else:
            ec2conn.delete_key_pair(testname)
            if not test:
                ec2conn.delete_key_pair(name)
                ec2conn.import_key_pair(name, content)
            return {
                'action': 'modify',
                'Replaced': "Keypair '%s' with new content" % name,
            }


def delete_keypair(
    name,
    region,
    test=False,
    aws_key=None,
        aws_secret=None):
    """
    Delete an EC2 Keypair

    Parameters
    ----------
    name : str
        Name of the keypair
    region : str
        The AWS region to create the keypair in
    test : bool, optional
        If true, don't actually perform any changes
    aws_key : str, optional
        The access key id for AWS. May also be specified as 'aws:key' in a
        pillar.
    aws_secret : str, optional
        The secret access key for AWS. May also be specified as 'aws:secret' in
        a pillar.

    """

    ec2conn = __salt__['aws_util.ec2conn'](region, aws_key, aws_secret)
    keypair = ec2conn.get_key_pair(name)
    if keypair is not None:
        if not test:
            ec2conn.delete_key_pair(name)
        return True
    else:
        return False
