"""
Summary
=======

The elb module is used to create and manage ELBs.

.. code-block:: yaml

    .webserver-elb:
      elb.present:
        - name: webserver-elb
        - region: us-west-1
        - zones:
            - us-west-1a
            - us-west-1c
        - listeners:
            - [80, 80, 'http', 'http']
            - [443, 80, 'https', 'http', 'my_ssl_certificate']
        - subnets:
            - subnet1
            - subnet2
        - security_groups:
            - my_elb_security_group
            - my_other_elb_security_group
        - scheme: internet-facing
        - health_check:
            target: HTTP:80/health
            timeout: 3
            interval: 30
            healthy_threshold: 4
            unhealthy_threshold: 2
        - policies:
            80:
              type: app
              cookie_name: my_cookie
            443:
              type: lb
              cookie_expire: 60
        - instances:
            - i-deadbeef
            - i-01234abc

    .bad-elb:
      elb.absent:
        - name: bad-elb
        - region: us-west-1

Notes
=====
Requires boto 2.12.0

"""
import boto.ec2.elb
import boto.exception

# This prevents pylint from yelling at me
__opts__ = {}
__pillar__ = {}

def present(
    name,
    region,
    zones,
    listeners=None,
    subnets=None,
    security_groups=None,
    scheme=None,
    health_check=None,
    policies=None,
    instances=None):
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

    Notes
    -----
    The boto method is documented here:
    http://boto.readthedocs.org/en/latest/ref/elb.html#boto.ec2.elb.ELBConnection.create_load_balancer

    """
    try:
        return _present(name, region, zones, listeners, subnets,
                        security_groups, scheme, health_check, policies,
                        instances)
    except boto.exception.BotoServerError as e:
        return {
            'name': name,
            'result': False,
            'comment': "{0}: {1}".format(e.code, e.message),
            'changes': {},
        }


def _present(
    name,
    region,
    zones,
    listeners=None,
    subnets=None,
    security_groups=None,
    scheme=None,
    health_check=None,
    policies=None,
    instances=None):
    """ The workhorse method """
    if scheme is None:
        scheme = 'internet-facing'
    ret = {'name': name, 'result': None, 'comment': '', 'changes': {}}
    aws_key = __pillar__.get('aws', {}).get('key')
    aws_secret = __pillar__.get('aws', {}).get('secret')

    if not aws_key or not aws_secret:
        ret['result'] = False
        ret['comment'] = ("No aws credentials found! You need to define the "
                          "pillar values 'aws:key' and 'aws:secret'")
        return ret

    elbconn = boto.ec2.elb.connect_to_region(region,
                                             aws_access_key_id=aws_key,
                                             aws_secret_access_key=aws_secret)

    # Convert SSL certificate names into ARN
    iamconn = boto.connect_iam(aws_key, aws_secret)
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


    try:
        elbs = elbconn.get_all_load_balancers(load_balancer_names=[name])
    except boto.exception.BotoServerError as e:
        if e.code == 'LoadBalancerNotFound':
            elbs = []
        else:
            raise
    if len(elbs) == 0:
        # Create new ELB
        if __opts__['test']:
            ret['comment'] = ("ELB '{0}' set to launch in region {1}"
                              .format(name, region))
            return ret

        elb = elbconn.create_load_balancer(
            name,
            zones,
            subnets=subnets,
            security_groups=security_groups,
            scheme=scheme,
            complex_listeners=listeners,
        )

        ret['result'] = True
        ret['comment'] = "Created ELB '{0}' in region {1}".format(name, region)
        ret['changes'][name] = "Launched in region {0}".format(region)
    else:
        # Modify the existing ELB
        elb = elbs[0]
        if __opts__['test']:
            ret['comment'] = ("Will Modify ELB '{0}' in region {1}"
                              .format(name, region))
        else:
            ret['comment'] = ("Modified ELB '{0}' in region {1}"
                              .format(name, region))


        # Availability Zones
        if zones != elb.availability_zones:
            ret['result'] = True
            to_remove = set(elb.availability_zones) - set(zones)
            if to_remove:
                if not __opts__['test']:
                    elb.disable_zones(list(to_remove))
                for zone in to_remove:
                    ret['changes']['Zone {0}'.format(zone)] = "Disabled"
            to_add = set(zones) - set(elb.availability_zones)
            if to_add:
                if not __opts__['test']:
                    elb.enable_zones(list(to_add))
                for zone in to_add:
                    ret['changes']['Zone {0}'.format(zone)] = "Enabled"


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
            ret['result'] = True
            to_delete = set(elb_listeners) - set(listeners)
            if to_delete:
                if not __opts__['test']:
                    for listener in to_delete:
                        elb.delete_listener(listener[0])
                ret['changes']['Listeners Deleted'] = str(list(to_delete))
            to_create = set(listeners) - set(elb_listeners)
            if to_create:
                if not __opts__['test']:
                    elbconn.create_load_balancer_listeners(
                        elb.name, complex_listeners=list(to_create))
                ret['changes']['Listeners Created'] = str(list(to_create))


        # Subnets
        # TODO: This is untested because my account doesn't have VPC
        elb_subnets = list(elb.subnets)
        subnets = subnets or []
        if subnets != elb_subnets:
            ret['result'] = True
            to_detach = set(elb_subnets) - set(subnets)
            if to_detach:
                if not __opts__['test']:
                    elb.detach_subnets(list(to_detach))
                ret['changes']['Subnets Detached'] = str(list(to_detach))
            to_attach = set(subnets) - set(elb_subnets)
            if to_attach:
                if not __opts__['test']:
                    elb.attach_subnets(list(to_attach))
                ret['changes']['Subnets Attached'] = str(list(to_attach))


        # Security Groups
        # TODO: This is untested because my account doesn't have VPC
        elb_security_groups = list(elb.security_groups)
        security_groups = security_groups or []
        if security_groups != elb_security_groups:
            ret['result'] = True
            to_remove = set(elb_security_groups) - set(security_groups)
            if to_remove:
                ret['changes']['Security Groups Removed'] = str(list(to_remove))
            to_add = set(security_groups) - set(elb_security_groups)
            if to_add:
                ret['changes']['Security Groups Added'] = str(list(to_add))
            if not __opts__['test']:
                elb.apply_security_groups(security_groups)


        # Scheme
        if scheme != elb.scheme:
            ret['result'] = False
            ret['comment'] = ("Scheme '{0}' is not '{1}', but schemes are "
                              "immutable!").format(elb.scheme, scheme)
            return ret

    # Some data is not specified during launch, so share the same code for them
    # in the same way for launch and edit.


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
        ret['changes']['Health check'] = "Modified"
        if not __opts__['test']:
            elb.configure_health_check(new_check)
        ret['result'] = True


    # Instances
    if instances is not None:
        elb_instances = [i.id for i in elb.instances]
        if instances != elb_instances:
            ret['result'] = True
            to_remove = set(elb_instances) - set(instances)
            if to_remove:
                ret['changes']['Instances Removed'] = list(to_remove)
                if not __opts__['test']:
                    elb.deregister_instances(list(to_remove))
            to_add = set(instances) - set(elb_instances)
            if to_add:
                ret['changes']['Instances Added'] = list(to_add)
                if not __opts__['test']:
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
            if not __opts__['test']:
                if policy['type'] == 'lb':
                    elb.create_cookie_stickiness_policy(policy['cookie_expire'],
                                                        policy['name'])
                elif policy['type'] == 'app':
                    elb.create_app_cookie_stickiness_policy(
                        policy['cookie_name'], policy['name'])

    for listener in elb.listeners:
        if listener.load_balancer_port in policies:
            port = listener.load_balancer_port
            policy = policies[port]
            if len(listener.policy_names) == 0:
                if not __opts__['test']:
                    elb.set_policies_of_listener(port, [policy['name']])
                ret['result'] = True
                ret['changes']['Port {0:d}'.format(port)] = "Added policy"
            else:
                if policy['name'] != listener.policy_names[0]:
                    if not __opts__['test']:
                        elb.set_policies_of_listener(port,
                                                    [policy['name']])
                    ret['result'] = True
                    ret['changes']['Port {0:d}'.format(port)] = "Changed policy"
        else:
            if len(listener.policy_names) > 0:
                if not __opts__['test']:
                    elb.set_policies_of_listener(port, [])
                ret['result'] = True
            ret['changes']['Port {0:d}'.format(port)] = "Removed policy"


    if ret['result'] is None:
        ret['result'] = True
        ret['comment'] = 'No changes'
    return ret


def absent(name, region):
    """
    Ensure an ELB does not exist

    Parameters
    ----------
    region : str
        The availability region the ELB is in

    """
    ret = {'name': name, 'result': None, 'comment': '', 'changes': {}}
    aws_key = __pillar__.get('aws', {}).get('key')
    aws_secret = __pillar__.get('aws', {}).get('secret')

    if not aws_key or not aws_secret:
        ret['result'] = False
        ret['comment'] = ("No aws credentials found! You need to define the "
                          "pillar values 'aws:key' and 'aws:secret'")
        return ret

    elbconn = boto.ec2.elb.connect_to_region(region,
                                             aws_access_key_id=aws_key,
                                             aws_secret_access_key=aws_secret)

    try:
        elbs = elbconn.get_all_load_balancers(load_balancer_names=[name])
        elb = elbs[0]
        elb.delete()
        ret['result'] = True
        ret['comment'] = ("Removed ELB '{0}' from region {1}"
                          .format(name, region))
        ret['changes'][name] = "Removed"
    except boto.exception.BotoServerError as e:
        if e.code != 'LoadBalancerNotFound':
            raise

    if ret['result'] is None:
        ret['result'] = True
        ret['comment'] = 'No changes'
    return ret
