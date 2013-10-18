"""
:maintainer:    Steven Arcangeli <steven@highlig.ht>
:maturity:      new
:depends:       boto
:platform:      all

Utility methods for the other AWS modules/states

"""
import json
try:
    import boto.elasticache
    import boto.exception
    HAS_BOTO = True
except ImportError:
    HAS_BOTO = False


# This prevents pylint from yelling at me
__pillar__ = {}
__opts__ = {}
__salt__ = {}

__virtualname__ = 'aws_util'

def __virtual__():
    return __virtualname__ if HAS_BOTO else False


def get_credentials(aws_key=None, aws_secret=None):
    """ Convenience method for retrieving AWS credentials """
    if aws_key is None:
        aws_key = __pillar__.get('aws', {}).get('key')
    if aws_secret is None:
        aws_secret = __pillar__.get('aws', {}).get('secret')

    if not aws_key or not aws_secret:
        raise TypeError("No aws credentials found! You need to define the "
                        "pillar values 'aws:key' and 'aws:secret'")
    return aws_key, aws_secret


def ecconn(region, aws_key=None, aws_secret=None):
    """ Convenience method for constructing an elasticache connection """
    aws_key, aws_secret = get_credentials(aws_key, aws_secret)
    return boto.elasticache.connect_to_region(
        region,
        aws_access_key_id=aws_key,
        aws_secret_access_key=aws_secret)


def ec2conn(region, aws_key=None, aws_secret=None):
    """ Convenience method for constructing an ec2 connection """
    aws_key, aws_secret = get_credentials(aws_key, aws_secret)
    return boto.ec2.connect_to_region(
        region,
        aws_access_key_id=aws_key,
        aws_secret_access_key=aws_secret)


def elbconn(region, aws_key=None, aws_secret=None):
    """ Convenience method for constructing an ELB connection """
    aws_key, aws_secret = get_credentials(aws_key, aws_secret)
    return boto.ec2.elb.connect_to_region(
        region,
        aws_access_key_id=aws_key,
        aws_secret_access_key=aws_secret)


def s3conn(aws_key=None, aws_secret=None):
    """ Convenience method for constructing an s3 connection """
    aws_key, aws_secret = get_credentials(aws_key, aws_secret)
    return boto.connect_s3(aws_access_key_id=aws_key,
                           aws_secret_access_key=aws_secret)


def iamconn(aws_key=None, aws_secret=None):
    """ Convenience method for constructing an IAM connection """
    aws_key, aws_secret = get_credentials(aws_key, aws_secret)
    return boto.connect_iam(aws_key, aws_secret)


def run_aws_module(module, obj_name, name, region, *args, **kwargs):
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
        import traceback
        ret['comment'] = traceback.format_exc()
    except boto.exception.BotoServerError as e:
        ret['result'] = False
        if e.code is None:
            exc = json.loads(e.message)
            e.code = exc['Error']['Code']
            e.message = exc['Error']['Message']
        ret['comment'] = "{0}: {1}".format(e.code, e.message),
    return ret
