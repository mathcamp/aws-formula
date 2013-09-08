import boto.exception

# This prevents pylint from yelling at me
__opts__ = {}
__salt__ = {}

def parameter_group_present(
    name,
    region,
    **kwargs):

    params = {k: v for k, v in kwargs.iteritems() if not k.startswith('_')}

def parameter_group_absent(
    name,
    region):
    pass

def present(
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
    apply_immediately=None):
    ret = {'name': name,
           'result': True,
           'comment': 'No changes',
           'changes': {},
            }
    try:
        changes = __salt__['elasticache.launch_or_modify'](
            name, region, node_type, engine, engine_version, num_nodes,
            replication_group, subnet_group, cache_security_groups,
            security_group_ids, snapshot_arns, snapshot_optional,
            preferred_availability_zone, preferred_maintenance_window,
            notification_topic_arn, notification_topic_status, parameter_group,
            port, auto_minor_version_upgrade, preserve_nodes, remove_nodes,
            apply_immediately, __opts__['test'])

        if changes.pop('action') == 'launch':
            if __opts__['test']:
                action = 'Will launch'
            else:
                action = 'Launched'
            ret['comment'] = ("{0} Elasticache cluster '{1}' in "
                                "region '{2}'".format(action, name, region))
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
    except boto.exception.BotoServerError as e:
        ret['result'] = False
        ret['comment'] = "{0}: {1}".format(e.code, e.message),
    return ret

def absent(
    name,
    region):
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
            ret['comment'] = ("{0} Elasticache cluster '{1}' in "
                              "region '{2}'".format(action, name, region))
    except TypeError as e:
        ret['result'] = False
        ret['comment'] = e.message
    except boto.exception.BotoServerError as e:
        ret['result'] = False
        ret['comment'] = "{0}: {1}".format(e.code, e.message),
    return ret
