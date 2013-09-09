"""
Summary
=======

This module is used to create and manage EC2 instances and security groups

Examples
========

.. code-block:: yaml


  .webserver:
    ec2.present:
      - name: webserver
      - region: us-west-1
      - key_name: mykey
      - count: 1
      - ami: ami-fe002cbb
      - security_groups:
        - default
        - webserver
      - instance_type: t1.micro
      - termination_protection: true
      - placement: us-west-1a
      - block_device_map:
          /dev/sdb:
            ephemeral_name: ephemeral0

  .old-webserver:
    ec2.absent:
      - name: old-webserver
      - region: us-west-1
      - force_termination: true

  .webserver-security-group:
    ec2.security_group:
      - name: webserver
      - region: us-west-1
      - description: Webserver group
      - rules:
        - ip_protocol: tcp
          from_port: 80
          to_port: 80
          cidr_ip: 0.0.0.0/0
        - ip_protocol: tcp
          from_port: 8080
          to_port: 8090
          src_security_group: webserver

  .old-security-group:
    ec2.security_group_absent:
      - name: old-group
      - region: us-west-1

"""
import boto.ec2
import boto.exception

# This prevents pylint from yelling at me
__opts__ = {}
__pillar__ = {}
__salt__ = {}


def present(
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
        network_interfaces=None):
    """
    Ensure a server exists

    Most parameters are described in ``ec2.manage`` module

    """

    ret = {'name': name,
           'result': True,
           'comment': 'No changes',
           'changes': {},
           }
    try:
        changed = __salt__['ec2.manage'](
            name, region, key_name, ami, security_groups, instance_type,
            kernel, user_data, termination_protection, addressing_type,
            placement, ramdisk_id, monitoring_enabled, subnet_id,
            block_device_map, instance_initiated_shutdown_behavior,
            private_ip_address, placement_group, additional_info,
            instance_profile_name, instance_profile_arn, tenancy,
            ebs_optimized, network_interfaces, __opts__['test'])
        if changed:
            if __opts__['test']:
                action = 'Will create'
            else:
                action = 'Created'
            msg = "Instance in region '{0}'".format(region)
            ret['comment'] = action + ' ' + msg
            ret['changes'][action] = msg
    except TypeError as e:
        ret['result'] = False
        ret['comment'] = e.message
    except boto.exception.BotoServerError as e:
        ret['result'] = False
        ret['comment'] = "{0}: {1}".format(e.code, e.message),
    return ret


def absent(
    name,
    region,
        force_termination=False):
    """
    Ensure a server does not exist

    Most parameters are described in ``ec2.manage`` module

    """

    ret = {'name': name,
           'result': True,
           'comment': 'No changes',
           'changes': {},
           }
    try:
        changed = __salt__['ec2.terminate'](
            name, region, force_termination, __opts__['test'])
        if changed:
            if __opts__['test']:
                action = 'Will terminate'
            else:
                action = 'Terminated'
            msg = "Instance in region '{0}'".format(region)
            ret['comment'] = action + ' ' + msg
            ret['changes'][action] = msg
    except TypeError as e:
        ret['result'] = False
        ret['comment'] = e.message
    except boto.exception.BotoServerError as e:
        ret['result'] = False
        ret['comment'] = "{0}: {1}".format(e.code, e.message),
    return ret


def security_group(
    name,
    region,
    description,
    vpc_id=None,
    rules=None,
        rules_egress=None):
    """
    Create and manage a Security Group

    Most parameters are described in ``ec2.manage_security_group`` module

    """
    ret = {'name': name,
           'result': True,
           'comment': 'No changes',
           'changes': {},
           }
    try:
        changes = __salt__['ec2.manage_security_group'](
            name, region, description, vpc_id, rules, rules_egress,
            __opts__['test'])

        if changes.pop('action') == 'create':
            if __opts__['test']:
                action = 'Will create'
            else:
                action = 'Created'
            msg = "Security Group '{0}' in region '{1}'".format(name, region)
            ret['comment'] = action + ' ' + msg
            ret['changes'][action] = msg
        elif changes:
            if __opts__['test']:
                action = 'Will modify'
            else:
                action = 'Modified'
            ret['comment'] = ("{0} Security Group '{1}' in "
                              "region '{2}'".format(action, name, region))
            ret['changes'] = changes

    except (TypeError, ValueError) as e:
        ret['result'] = False
        ret['comment'] = e.message
    except boto.exception.BotoServerError as e:
        ret['result'] = False
        ret['comment'] = "{0}: {1}".format(e.code, e.message),
    return ret


def security_group_absent(
    name,
    region,
        group_id=None):
    """
    Ensure a Security Group does not exist

    Most parameters are described in ``ec2.manage_security_group`` module

    """
    ret = {'name': name,
           'result': True,
           'comment': 'No changes',
           'changes': {},
           }
    try:
        changed = __salt__['ec2.delete_security_group'](name, region, group_id,
                                                        __opts__['test'])
        if changed:
            if __opts__['test']:
                action = 'Will delete'
            else:
                action = 'Deleted'
            msg = "Security Group '{0}' in region '{1}'".format(name, region)
            ret['comment'] = action + ' ' + msg
            ret['changes'][action] = msg
    except TypeError as e:
        ret['result'] = False
        ret['comment'] = e.message
    except boto.exception.BotoServerError as e:
        ret['result'] = False
        ret['comment'] = "{0}: {1}".format(e.code, e.message),
    return ret
