"""
:maintainer:    Steven Arcangeli <steven@highlig.ht>
:maturity:      new
:depends:       boto
:platform:      all

Module for manipulating Amazon ELBs

"""
try:
    import boto.ec2.elb
    import boto.exception
    HAS_BOTO = True
except ImportError:
    HAS_BOTO = False

# This prevents pylint from yelling at me
__salt__ = {}

__virtualname__ = 'elb'

def _convert_server_names(names, region, aws_key=None, aws_secret=None):
    """ Convert a list of server names/instance ids to just instance ids """
    ec2conn = __salt__['aws_util.ec2conn'](region, aws_key, aws_secret)
    tags = ec2conn.get_all_tags()
    name_map = {tag.value: tag.res_id for tag in tags
                if tag.name.lower() == 'name'}

    for i in range(len(names)):
        if not names[i].startswith('i-'):
            names[i] = name_map[names[i]]


def _get_elb(
    name,
    region,
    aws_key=None,
    aws_secret=None,
    elbconn=None):
    """
    Convenience method for retrieving an ELB

    """
    if elbconn is None:
        elbconn = __salt__['aws_util.elbconn'](region, aws_key, aws_secret)

    try:
        elbs = elbconn.get_all_load_balancers(load_balancer_names=[name])
        return elbs[0]
    except boto.exception.BotoServerError as e:
        if e.code == 'LoadBalancerNotFound':
            return None
        else:
            raise


def __virtual__():
    return __virtualname__ if HAS_BOTO else False


def manage(
    name,
    region,
    zones,
    listeners=None,
    subnets=None,
    security_groups=None,
    scheme='internet-facing',
    health_check=None,
    policies=None,
    instances=None,
    test=False,
    aws_key=None,
        aws_secret=None):
    """
    Ensure an ELB exists with a certain configuration

    Parameters
    ----------
    region : str
        The availability region the ELB is in
    zones : list
        The names of the availability zone(s) that the ELB spans
    listeners : list, optional
        Each tuple contains four or five values, (LoadBalancerPortNumber,
        InstancePortNumber, Protocol, InstanceProtocol, SSLCertificateId).
        Where LoadBalancerPortNumber and InstancePortNumber are integer
        values between 1 and 65535.  Protocol and InstanceProtocol is a string
        containing either 'TCP', 'SSL', 'HTTP', or 'HTTPS'. SSLCertificateId is
        the ARN of an SSL certificate loaded into AWS IAM. You may specify just
        the name of the SSLCertificateId, and the state will fetch the ARN from
        IAM.
    subnets : list, optional
        A list of subnet IDs in your VPC to attach to your LoadBalancer.
    security_groups : list, optional
        The security groups assigned to your LoadBalancer within your VPC.
    scheme : str, optional
        The type of a LoadBalancer. By default, Elastic Load Balancing creates
        an internet-facing LoadBalancer with a publicly resolvable DNS name,
        which resolves to public IP addresses.  Specify the value internal for
        this option to create an internal LoadBalancer with a DNS name that
        resolves to private IP addresses.  This option is only available for
        LoadBalancers attached to an Amazon VPC.
    health_check : dict, optional
        interval : int, optional
            Frequency for the health check
        target : str, optional
            Specifies the instance being checked. The protocol is either TCP, HTTP,
            HTTPS, or SSL. TCP is the default, specified as a "TCP:port" pair, for example
            "TCP:5000". In this case a healthcheck simply attempts to open a TCP
            connection to the instance on the specified port. Failure to connect
            within the configured timeout is considered unhealthy.  SSL is also
            specified as "SSL:port" pair, for example, "SSL:5000".  For HTTP or HTTPS
            protocol, the situation is different. You have to include a ping path
            in the string. HTTP is specified as a "HTTP:port/PathToPing" grouping,
            for example "HTTP:80/weather/us/wa/seattle". In this case, a HTTP GET
            request is issued to the instance on the given port and path. Any
            answer other than "200 OK" within the timeout period is considered
            unhealthy.
        healthy_threshold : int, optional
            If the check succeeds this many times on an unhealthy server, re-enable
            it.
        timeout : int, optional
            Wait this long on the health check before timing out
        unhealthy_threshold : int, optional
            If the check fails this many times on a server, mark as out of service
    policies : dict, optional
        A dict mapping the ELB listen port to the policy args. The args must
        contain the key 'type', which may be 'app' or 'lb' (for app stickiness
        or load balancer stickiness). If it is 'app', add the key
        'cookie_name', which is the cookie name. If it is 'lb', add the key
        'cookie_expire', which is the time before the sticky cookie expires.
    instances : list, optional
        List of instance ids that should be attached to the ELB. If this
        argument is None or unspecified, no instances will be added or removed.
        You may also use server names instead of instance ids.
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
    http://boto.readthedocs.org/en/latest/ref/elb.html#boto.ec2.elb.ELBConnection.create_load_balancer

    """
    elbconn = __salt__['aws_util.elbconn'](region, aws_key, aws_secret)

    # Convert SSL certificate names into ARN
    iamconn = __salt__['aws_util.iamconn'](aws_key, aws_secret)
    certs = iamconn.get_all_server_certs()\
        ['list_server_certificates_response']\
        ['list_server_certificates_result']\
        ['server_certificate_metadata_list']
    find_cert = lambda cert: filter(lambda c: c['server_certificate_name']
                                    == cert, certs)[0]['arn']

    if listeners is not None:
        for listener in listeners:
            if len(listener) == 5 and not listener[4].startswith('arn:'):
                listener[4] = find_cert(listener[4])

    elb = _get_elb(name, region, aws_key, aws_secret, elbconn)

    if elb is None:
        if not test:
            launch(name, region, zones, listeners, subnets, security_groups,
                scheme, health_check, policies, instances, aws_key, aws_secret,
                elbconn)
        return {'action': 'create'}
    else:
        # Scheme
        if scheme != elb.scheme:
            raise ValueError("Scheme '{0}' is not '{1}', but scheme cannot be "
                             "changed!".format(elb.scheme, scheme))

        changes = modify(name, region, zones, listeners, subnets,
                         security_groups, health_check, policies, instances,
                         test, aws_key, aws_secret, elbconn, elb)
        changes['action'] = 'modify'
        return changes


def launch(
    name,
    region,
    zones,
    listeners=None,
    subnets=None,
    security_groups=None,
    scheme='internet-facing',
    health_check=None,
    policies=None,
    instances=None,
    aws_key=None,
    aws_secret=None,
        elbconn=None):
    """
    Launch an ELB

    Most arguments are the same as :meth:`.launch_or_modify`

    Parameters
    ----------
    elbconn : :class:`boto.ec2.elb.ELBConnection`, optional
        If present this function will not open a new elb connection

    """
    if elbconn is None:
        elbconn = __salt__['aws_util.elbconn'](region, aws_key, aws_secret)

    elb = elbconn.create_load_balancer(
        name,
        zones,
        subnets=subnets,
        security_groups=security_groups,
        scheme=scheme,
        complex_listeners=listeners,
    )

    # Some properties, like policies and instances, can only be set after
    # the elb launches
    modify(name, region, zones, listeners, subnets, security_groups,
            health_check, policies, instances, False, aws_key, aws_secret,
            elbconn, elb)


def modify(
    name,
    region,
    zones,
    listeners=None,
    subnets=None,
    security_groups=None,
    health_check=None,
    policies=None,
    instances=None,
    test=False,
    aws_key=None,
    aws_secret=None,
    elbconn=None,
        elb=None):
    """
    Launch an ELB

    Most arguments are the same as :meth:`.launch_or_modify`

    Parameters
    ----------
    elbconn : :class:`boto.ec2.elb.ELBConnection`, optional
        If present this function will not open a new elb connection
    elb : :class:`boto.ec2.elb.LoadBalancer`, optional
        If present this function will not make a call to fetch the load
        balancer

    """
    if elbconn is None:
        elbconn = __salt__['aws_util.elbconn'](region, aws_key, aws_secret)

    if elb is None:
        elbs = elbconn.get_all_load_balancers(load_balancer_names=[name])
        elb = elbs[0]

    changes = {}

    # Availability Zones
    if zones != elb.availability_zones:
        to_remove = set(elb.availability_zones) - set(zones)
        if to_remove:
            if not test:
                elb.disable_zones(list(to_remove))
            for zone in to_remove:
                changes['Zone {0}'.format(zone)] = "Disabled"
        to_add = set(zones) - set(elb.availability_zones)
        if to_add:
            if not test:
                elb.enable_zones(list(to_add))
            for zone in to_add:
                changes['Zone {0}'.format(zone)] = "Enabled"

    # Listeners
    elb_listeners = []
    # Convert the boto listeners to tuples
    for listener in elb.listeners:
        tup_listener = (
            listener.load_balancer_port,
            listener.instance_port,
            listener.protocol,
        )
        if listener.instance_protocol is not None:
            tup_listener += (listener.instance_protocol,)
        if listener.ssl_certificate_id is not None:
            tup_listener += (listener.ssl_certificate_id,)
        elb_listeners.append(tup_listener)
    listeners = listeners or []

    # Translate all protocols to uppercase
    for listener in listeners:
        listener[2] = listener[2].upper()
        listener[3] = listener[3].upper()

    listeners = [tuple(l) for l in listeners]
    if listeners != elb_listeners:
        to_delete = set(elb_listeners) - set(listeners)
        if to_delete:
            if not test:
                for listener in to_delete:
                    elb.delete_listener(listener[0])
            changes['Listeners Deleted'] = str(list(to_delete))
        to_create = set(listeners) - set(elb_listeners)
        if to_create:
            if not test:
                elbconn.create_load_balancer_listeners(
                    elb.name, complex_listeners=list(to_create))
            changes['Listeners Created'] = str(list(to_create))

    # Subnets
    # TODO: This is untested because my account doesn't have VPC
    elb_subnets = list(elb.subnets)
    subnets = subnets or []
    if subnets != elb_subnets:
        to_detach = set(elb_subnets) - set(subnets)
        if to_detach:
            if not test:
                elb.detach_subnets(list(to_detach))
            changes['Subnets Detached'] = str(list(to_detach))
        to_attach = set(subnets) - set(elb_subnets)
        if to_attach:
            if not test:
                elb.attach_subnets(list(to_attach))
            changes['Subnets Attached'] = str(list(to_attach))

    # Security Groups
    # TODO: This is untested because my account doesn't have VPC
    elb_security_groups = list(elb.security_groups)
    security_groups = security_groups or []
    if security_groups != elb_security_groups:
        to_remove = set(elb_security_groups) - set(security_groups)
        if to_remove:
            changes['Security Groups Removed'] = str(list(to_remove))
        to_add = set(security_groups) - set(elb_security_groups)
        if to_add:
            changes['Security Groups Added'] = str(list(to_add))
        if not test:
            elb.apply_security_groups(security_groups)

    # Health check
    if health_check is None:
        health_check = {}
    check = elb.health_check
    new_check = boto.ec2.elb.healthcheck.HealthCheck(
        access_point=name,
        interval=health_check.get('interval', 30),
        target=health_check.get('target'),
        healthy_threshold=health_check.get('healthy_threshold', 3),
        timeout=health_check.get('timeout', 5),
        unhealthy_threshold=health_check.get('unhealthy_threshold', 5))
    modified = False
    if check is None:
        modified = True
    if not modified:
        for attr in ('interval', 'target', 'healthy_threshold', 'timeout',
                     'unhealthy_threshold'):
            if getattr(new_check, attr) != getattr(check, attr):
                modified = True
                break
    if modified:
        changes['Health check'] = "Modified"
        if not test:
            elb.configure_health_check(new_check)

    # Instances
    if instances is not None:
        _convert_server_names(instances, region, aws_key, aws_secret)

        elb_instances = [i.id for i in elb.instances]
        if instances != elb_instances:
            to_remove = set(elb_instances) - set(instances)
            if to_remove:
                changes['Instances Removed'] = list(to_remove)
                if not test:
                    elb.deregister_instances(list(to_remove))
            to_add = set(instances) - set(elb_instances)
            if to_add:
                changes['Instances Added'] = list(to_add)
                if not test:
                    elb.register_instances(list(to_add))

    # Policies
    policies = policies or {}
    elb_policies = []
    for attr in ('app_cookie_stickiness_policies',
                 'lb_cookie_stickiness_policies'):
        for policy in getattr(elb.policies, attr):
            elb_policies.append(policy.policy_name)

    # Create any policies that don't exist yet
    for policy in policies.itervalues():
        if policy['type'] == 'lb':
            policy['name'] = 'lb' + str(policy['cookie_expire'])
        elif policy['type'] == 'app':
            policy['name'] = 'app' + str(hash(policy['cookie_name']))
        else:
            raise ValueError("Policy type '{0}' must be 'lb' or 'app'"
                             .format(policy['name']))

        if policy['name'] not in elb_policies:
            if not test:
                if policy['type'] == 'lb':
                    elb.create_cookie_stickiness_policy(
                        policy['cookie_expire'],
                        policy['name'])
                elif policy['type'] == 'app':
                    elb.create_app_cookie_stickiness_policy(
                        policy['cookie_name'], policy['name'])

    for listener in elb.listeners:
        if listener.load_balancer_port in policies:
            port = listener.load_balancer_port
            policy = policies[port]
            if len(listener.policy_names) == 0:
                if not test:
                    elb.set_policies_of_listener(port, [policy['name']])
                changes['Port {0:d}'.format(port)] = "Added policy"
            else:
                if policy['name'] != listener.policy_names[0]:
                    if not test:
                        elb.set_policies_of_listener(port,
                                                     [policy['name']])
                    changes['Port {0:d}'.format(port)] = "Changed policy"
        else:
            if len(listener.policy_names) > 0:
                if not test:
                    elb.set_policies_of_listener(port, [])
            changes['Port {0:d}'.format(port)] = "Removed policy"

    return changes


def delete(
    name,
    region,
    test=False,
    aws_key=None,
        aws_secret=None):
    """
    Ensure an ELB does not exist

    Parameters
    ----------
    region : str
        The availability region the ELB is in
    test : bool, optional
        If true, don't actually perform the delete
    aws_key : str, optional
        The access key id for AWS. May also be specified as 'aws:key' in a
        pillar.
    aws_secret : str, optional
        The secret access key for AWS. May also be specified as 'aws:secret' in
        a pillar.

    """
    elbconn = __salt__['aws_util.elbconn'](region, aws_key, aws_secret)
    elb = _get_elb(name, region, aws_key, aws_secret, elbconn)

    if elb is not None:
        if not test:
            elb.delete()
        return True


def add(
    name,
    region,
    elb,
    test=False,
    aws_key=None,
    aws_secret=None):
    """
    Idempotently add a server to an ELB

    Parameters
    ----------
    name : str
        Name or instance id of the server
    region : str
        The AWS region the server/ELB are in
    elb : str
        The name of the ELB

    """

    names = [name]
    _convert_server_names(names, region, aws_key, aws_secret)
    name = names[0]
    elb_instance = _get_elb(elb, region, aws_key, aws_secret)

    if name not in elb_instance.instances:
        if not test:
            elb_instance.register_instances(names)
        return {'action': 'modify',
                'Added': "Server '{0}' to ELB '{1}'".format(name, elb),
                }
    return {'action': 'noop'}


def remove(
    name,
    region,
    elb,
    test=False,
    aws_key=None,
    aws_secret=None):
    """
    Idempotently remove a server from an ELB

    Parameters
    ----------
    name : str
        Name or instance id of the server
    region : str
        The AWS region the server/ELB are in
    elb : str
        The name of the ELB

    """

    names = [name]
    _convert_server_names(names, region, aws_key, aws_secret)
    name = names[0]
    elb_instance = _get_elb(elb, region, aws_key, aws_secret)

    if name in elb_instance.instances:
        if not test:
            elb_instance.deregister_instances(names)
        return {'action': 'modify',
                'Removed': "Server '{0}' to ELB '{1}'".format(name, elb),
                }
    return {'action': 'noop'}
