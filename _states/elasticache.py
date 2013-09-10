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
        - preferred_availability_zone: us-west-1a
        - snapshot: my-bucket/path/to/backup.rdb
        - snapshot_optional: true

    .old-cache:
      elasticache.absent:
        - name: old-cache
        - region: us-west-1

    .backup-group:
      elasticache.replication_group:
        - name: repl-group
        - region: us-west-1
        - primary: my-cache
        - description: Backing up data

    .backup-cache:
      elasticache.replica:
        - name: my-backup
        - region: us-west-1
        - replication_group: repl-group
        - preferred_availability_zone: us-west-1c

    .my-parameters:
      elasticache.parameter_group:
        - name: myparameters
        - region: us-west-1
        - family: redis2.6
        - description: My test group
        - parameters:
            databases: 32
            maxmemory-policy: noeviction
            appendonly: true

    .old-parameters:
      elasticache.parameter_group_absent:
        - name: oldparameters
        - region: us-west-1

    .my-group:
      elasticache.security_group:
        - name: mygroup
        - region: us-west-1
        - description: My security group
        - authorized:
            - ec2_security_group
            - [ec2_security_group2, 123456789]

    .old-group:
      elasticache.security_group_absent:
        - name: oldgroup
        - region: us-west-1


"""
import boto.exception
import json


# This prevents pylint from yelling at me
__opts__ = {}
__salt__ = {}


def _run_module(module, obj_name, name, region, *args, **kwargs):
    """ Wraps the running of a create/delete module method """
    ret = {'name': name,
           'result': True,
           'comment': 'No changes',
           'changes': {},
           }
    try:
        changes = __salt__[module](*args, **kwargs)
        if isinstance(changes, dict):
            if changes.pop('action') == 'create':
                if __opts__['test']:
                    action = 'Will create'
                else:
                    action = 'Created'
                msg = "{0} '{1}' in region '{2}'".format(
                    obj_name, name, region)
                ret['comment'] = action + ' ' + msg
                ret['changes'][action] = msg
            elif changes:
                if __opts__['test']:
                    action = 'Will modify'
                else:
                    action = 'Modified'
                msg = "{0} '{1}' in region '{2}'".format(
                    obj_name, name, region)
                ret['comment'] = action + ' ' + msg
                ret['changes'] = changes
        else:
            if changes:
                if __opts__['test']:
                    action = 'Will delete'
                else:
                    action = 'Deleted'
                msg = "{0} '{1}' in region '{2}'".format(obj_name, name,
                                                         region)
                ret['changes'][action] = msg
                ret['comment'] = action + ' ' + msg

    except (TypeError, ValueError) as e:
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


def managed(
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
    notification_topic_status=None,
    parameter_group=None,  # pylint: disable=W0621
    port=None,
    auto_minor_version_upgrade=True,
    preserve_nodes=None,
    remove_nodes=None,
        apply_immediately=None):
    """
    Ensure an Elasticache cluster exists

    The arguments are the same as the ``elasticache.manage`` module

    """
    return _run_module('elasticache.manage',
                       'Cluster', name, region,
                       name, region, node_type, engine, engine_version,
                       num_nodes, None, subnet_group, cache_security_groups,
                       security_group_ids, [snapshot], snapshot_optional,
                       preferred_availability_zone,
                       preferred_maintenance_window, notification_topic_arn,
                       notification_topic_status, parameter_group, port,
                       auto_minor_version_upgrade, preserve_nodes,
                       remove_nodes, apply_immediately, __opts__['test'])


def replica(
    name,
    region,
    replication_group,  # pylint: disable=W0621
        preferred_availability_zone=None):
    """
    Ensure a replica Elasticache cluster exists

    The arguments are the same as the ``elasticache.manage`` module

    """
    return _run_module('elasticache.manage',
                       'Replica Cluster', name, region,
                       name, region,
                       replication_group=replication_group,
                       preferred_availability_zone=preferred_availability_zone,
                       test=__opts__['test'])


def absent(
    name,
        region):
    """
    Ensure an Elasticache cluster does not exist

    The arguments are the same as the ``elasticache.manage`` module

    """
    return _run_module('elasticache.delete', 'Cluster', name, region,
                       name, region, test=__opts__['test'])


def parameter_group(
    name,
    region,
    family,
    description,
        parameters):
    """
    Ensure an Elasticache parameter group exists

    The arguments are the same as the
    ``elasticache.manage_parameter_group`` module

    """
    return _run_module('elasticache.manage_parameter_group',
                       'Parameter group', name, region,
                       name, region, family, description, parameters,
                       __opts__['test'])


def parameter_group_absent(
    name,
        region):
    """ Ensure an Elasticache parameter group does not exist """
    return _run_module('elasticache.delete_parameter_group',
                       'Parameter group', name, region,
                       name, region, test=__opts__['test'])


def security_group(
        name,
        region,
        description,
        authorized):
    """
    Ensure an Elasticache security group exists

    The arguments are the same as the
    ``elasticache.manage_security_group`` module

    """
    return _run_module('elasticache.manage_security_group',
                       'Security group', name, region,
                       name, region, description, authorized, __opts__['test'])


def security_group_absent(
        name,
        region):
    """ Ensure an Elasticache security group does not exist """
    return _run_module('elasticache.delete_security_group',
                       'Security group', name, region,
                       name, region, __opts__['test'])


def replication_group(
    name,
    region,
    primary,
        description):
    """
    Ensure an Elasticache replication group exists

    The arguments are the same as the
    ``elasticache.manage_replication_group`` module

    """
    return _run_module('elasticache.create_replication_group',
                       'Replication group', name, region,
                       name, region, primary, description, __opts__['test'])
