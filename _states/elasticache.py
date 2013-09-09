"""
Summary
=======
This state is used to create and manage Elasticache clusters

Examples
========

.. code-block:: yaml

    .my-cache:
      elasticache.managed:
        - name: my-cache
        - region: us-west-1
        - node_type: cache.m1.small
        - security_group: mygroup
        - engine: redis
        - engine_version: 2.6.13
        - num_nodes: 1
        - snapshot: my-bucket/path/to/backup.rdb
        - snapshot_optional: true

    .old-cache:
      elasticache.absent:
        - name: old-cache
        - region: us-west-1

    .my-group:
      elasticache.parameter_group_managed:
        - name: mygroup
        - region: us-west-1
        - family: redis2.6
        - description: My test group
        - parameters:
            databases: 32
            maxmemory-policy: noeviction
            appendonly: true

    .old-group:
      elasticache.parameter_group_absent:
        - name: oldgroup
        - region: us-west-1

"""
import boto.exception
import json


# This prevents pylint from yelling at me
__opts__ = {}
__salt__ = {}

def managed(
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
    snapshot=None,
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
    apply_immediately=None):
    """
    Ensure an Elasticache cluster exists

    The arguments are the same as the ``elasticache.launch_or_modify`` module

    """
    ret = {'name': name,
           'result': True,
           'comment': 'No changes',
           'changes': {},
            }
    try:
        changes = __salt__['elasticache.launch_or_modify'](
            name, region, node_type, engine, engine_version, num_nodes,
            replication_group, subnet_group, cache_security_groups,
            security_group_ids, [snapshot], snapshot_optional,
            preferred_availability_zone, preferred_maintenance_window,
            notification_topic_arn, notification_topic_status, parameter_group,
            port, auto_minor_version_upgrade, preserve_nodes, remove_nodes,
            apply_immediately, __opts__['test'])

        if changes.pop('action') == 'launch':
            if __opts__['test']:
                action = 'Will launch'
            else:
                action = 'Launched'
            msg = "Elasticache cluster '{0}' in region '{1}'".format(name,
                                                                     region)
            ret['changes'][action] = msg
            ret['comment'] = action + ' '  + msg
        elif changes:
            if __opts__['test']:
                action = 'Will modify'
            else:
                action = 'Modified'
            ret['comment'] = ("{0} Elasticache cluster '{1}' in "
                                "region '{2}'".format(action, name, region))
            ret['changes'] = changes

    except (TypeError, ValueError) as e:
        ret['result'] = False
        ret['comment'] = e.message
        raise
    except boto.exception.BotoServerError as e:
        ret['result'] = False
        if e.code is None:
            exc = json.loads(e.message)
            ret['comment'] = "{0}: {1}".format(exc['Error']['Code'],
                                               exc['Error']['Message'])
        else:
            ret['comment'] = "{0}: {1}".format(e.code, e.message),
    return ret

def absent(
    name,
    region):
    """
    Ensure an Elasticache cluster does not exist

    The arguments are the same as the ``elasticache.launch_or_modify`` module

    """
    ret = {'name': name,
           'result': True,
           'comment': 'No changes',
           'changes': {},
            }
    try:
        changed = __salt__['elasticache.delete'](name, region,
                                                 test=__opts__['test'])
        if changed:
            if __opts__['test']:
                action = 'Will delete'
            else:
                action = 'Deleted'
            msg = "Elasticache cluster '{0}' in region '{1}'".format(name,
                                                                     region)
            ret['changes'][action] = msg
            ret['comment'] = action + ' '  + msg
    except TypeError as e:
        ret['result'] = False
        ret['comment'] = e.message
    except boto.exception.BotoServerError as e:
        ret['result'] = False
        if e.code is None:
            exc = json.loads(e.message)
            ret['comment'] = "{0}: {1}".format(exc['Error']['Code'],
                                               exc['Error']['Message'])
        else:
            ret['comment'] = "{0}: {1}".format(e.code, e.message),
    return ret

def parameter_group_managed(
    name,
    region,
    family,
    description,
    parameters):
    """
    Ensure an Elasticache parameter group exists

    The arguments are the same as the
    ``elasticache.create_or_modify_parameter_group`` module

    """

    ret = {'name': name,
           'result': True,
           'comment': 'No changes',
           'changes': {},
           }
    try:
        changes = __salt__['elasticache.create_or_modify_parameter_group'](
                name, region, family, description, parameters,
                __opts__['test'])
        if changes.pop('action') == 'create':
            if __opts__['test']:
                action = 'Will create'
            else:
                action = 'Created'
            msg = "Parameter group '{0}' in region '{1}'".format(name, region)
            ret['comment'] = action + ' ' + msg
            ret['changes'][action] = msg
        elif changes:
            if __opts__['test']:
                action = 'Will modify'
            else:
                action = 'Modified'
            msg = "Parameter group '{0}' in region '{1}'".format(name, region)
            ret['comment'] = action + ' ' + msg
            ret['changes'] = changes

    except (TypeError, ValueError) as e:
        ret['result'] = False
        ret['comment'] = e.message
        raise
    except boto.exception.BotoServerError as e:
        ret['result'] = False
        if e.code is None:
            exc = json.loads(e.message)
            ret['comment'] = "{0}: {1}".format(exc['Error']['Code'],
                                               exc['Error']['Message'])
        else:
            ret['comment'] = "{0}: {1}".format(e.code, e.message),
    return ret

def parameter_group_absent(
    name,
    region):
    """ Ensure an Elasticache parameter group does not exist """
    ret = {'name': name,
           'result': True,
           'comment': 'No changes',
           'changes': {},
           }
    try:
        changed = __salt__['elasticache.delete_parameter_group'](
                name, region, test=__opts__['test'])
        if changed:
            if __opts__['test']:
                action = 'Will delete'
            else:
                action = 'Deleted'
            msg = "Parameter group '{0}' in region '{1}'".format(name, region)
            ret['comment'] = action + ' ' + msg
            ret['changes'][action] = msg
    except TypeError as e:
        ret['result'] = False
        ret['comment'] = e.message
    except boto.exception.BotoServerError as e:
        ret['result'] = False
        if e.code is None:
            exc = json.loads(e.message)
            ret['comment'] = "{0}: {1}".format(exc['Error']['Code'],
                                               exc['Error']['Message'])
        else:
            ret['comment'] = "{0}: {1}".format(e.code, e.message),
    return ret
