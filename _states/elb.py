"""
This state is used to create and manage ELBs.

Examples
========

.. code-block:: yaml

    .webserver-elb:
      elb.managed:
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

    .add-server:
      elb.add:
        - name: my-server
        - region: us-west-1
        - elb: webserver-elb

    .rm-badserver:
      elb.remove:
        - name: badserver
        - region: us-west-1
        - elb: webserver-elb

"""

# This prevents pylint from yelling at me
__opts__ = {}
__salt__ = {}


def managed(
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
    Ensure an ELB exists

    The arguments are the same as the ``elb.manage`` module

    """

    return __salt__['aws_util.run_aws_module'](
        'elb.manage', 'ELB', name, region, name, region, zones, listeners,
        subnets, security_groups, scheme, health_check, policies, instances,
        __opts__['test'])


def absent(name, region):
    """
    Ensure an ELB does not exist

    Parameters
    ----------
    name : str
        The name of the ELB
    region : str
        The AWS region the ELB is in

    """
    return __salt__['aws_util.run_aws_module'](
        'elb.delete', 'ELB', name, region, name, region, test=__opts__['test'])

def add(
    name,
    region,
    elb):
    """
    Add a server to an ELB

    Parameters
    ----------
    name : str
        The name or instance id of the server
    region : str
        The AWS region
    elb : str
        The name of the ELB to add the server to

    """
    return __salt__['aws_util.run_aws_module'](
        'elb.add', "ELB", elb, region, name, region,
        elb, test=__opts__['test'])

def remove(
    name,
    region,
    elb):
    """
    Remove a server from an ELB

    Parameters
    ----------
    name : str
        The name or instance id of the server
    region : str
        The AWS region
    elb : str
        The name of the ELB to remove the server from

    """
    return __salt__['aws_util.run_aws_module'](
        'elb.remove', "ELB", elb, region, name, region,
        elb, test=__opts__['test'])
