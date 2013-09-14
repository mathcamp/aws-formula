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
import boto.ec2.elb
import boto.exception

# This prevents pylint from yelling at me
__opts__ = {}
__pillar__ = {}
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

    ret = {'name': name,
           'result': True,
           'comment': 'No changes',
           'changes': {},
           }
    try:
        changes = __salt__['elb.manage'](
            name, region, zones, listeners, subnets, security_groups, scheme,
            health_check, policies, instances, __opts__['test'])
        if changes.pop('action') == 'launch':
            if __opts__['test']:
                action = 'Will launch'
            else:
                action = 'Launched'
            msg = "ELB '{0}' in region '{1}'".format(name, region)
            ret['comment'] = action + ' ' + msg
            ret['changes'][action] = msg
        elif changes:
            if __opts__['test']:
                action = 'Will modify'
            else:
                action = 'Modified'
            msg = "ELB '{0}' in region '{1}'".format(name, region)
            ret['comment'] = action + ' ' + msg
            ret['changes'] = changes

    except (TypeError, ValueError) as e:
        ret['result'] = False
        ret['comment'] = e.message
    except boto.exception.BotoServerError as e:
        ret['result'] = False
        ret['comment'] = "{0}: {1}".format(e.code, e.message),
    return ret


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
    ret = {'name': name,
           'result': True,
           'comment': 'No changes',
           'changes': {},
           }
    try:
        changed = __salt__['elb.delete'](name, region, test=__opts__['test'])
        if changed:
            if __opts__['test']:
                action = 'Will delete'
            else:
                action = 'Deleted'
            msg = "ELB '{0}' in region '{1}'".format(name, region)
            ret['comment'] = action + ' ' + msg
            ret['changes'][action] = msg
    except TypeError as e:
        ret['result'] = False
        ret['comment'] = e.message
    except boto.exception.BotoServerError as e:
        ret['result'] = False
        ret['comment'] = "{0}: {1}".format(e.code, e.message),
    return ret

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

    ret = {'name': name,
           'result': True,
           'comment': 'No changes',
           'changes': {},
           }
    try:
        changed = __salt__['elb.add'](name, region, elb, test=__opts__['test'])
        if __opts__['test']:
            action = 'Will add'
        else:
            action = 'Added'
        msg = "'{0}' to '{1}' in region '{2}'".format(name, elb, region)
        if changed:
            ret['comment'] = action + ' ' + msg
            ret['changes'][action] = msg
    except (TypeError, ValueError) as e:
        ret['result'] = False
        ret['comment'] = e.message
    except boto.exception.BotoServerError as e:
        ret['result'] = False
        ret['comment'] = "{0}: {1}".format(e.code, e.message),
    return ret

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

    ret = {'name': name,
           'result': True,
           'comment': 'No changes',
           'changes': {},
           }
    try:
        changed = __salt__['elb.remove'](name, region, elb,
                                         test=__opts__['test'])
        if __opts__['test']:
            action = 'Will remove'
        else:
            action = 'Removed'
        msg = "'{0}' from '{1}' in region '{2}'".format(name, elb, region)
        if changed:
            ret['comment'] = action + ' ' + msg
            ret['changes'][action] = msg
    except (TypeError, ValueError) as e:
        ret['result'] = False
        ret['comment'] = e.message
    except boto.exception.BotoServerError as e:
        ret['result'] = False
        ret['comment'] = "{0}: {1}".format(e.code, e.message),
    return ret
