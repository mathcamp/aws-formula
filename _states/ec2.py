"""
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

  .my-keypair:
    ec2.keypair:
      - name: mykey
      - region: us-west-1
      - content: ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDMiEGksJCy8vo6s16VYVIg/emb3QHvno9Fh0irFjgKMe9Esn73CwQm96AGEMpVzeugMQg2YjpjIk5exdk6aJct66IYiRt+rq05C/IWsFzYvXr5+DBNkepOj9pVxtImTy7boZb9AGXBiMg5YviugbRD0XZSyoA5OZ9UHlqjg1tH5Cdm1Q8RfFi3GOzMtDhHIRojLW0Quf1JfiUGXFqJTdTbWlP+ANe560LvaOhsoxMaAs6xENzOjKqTDf9oXH00oHBUqlSwuJJfrsVpEdcp2BQQstPtG5sReW3UpJT8zl/Y/I0B3+vCt5plsyV77fa0Up8HRrOy00sZ9pzizLyBHip7 stevearc@ubuntu

  .old-keypair:
    ec2.keypair_absent:
      - name: oldkey
      - region: us-west-1

"""

# This prevents pylint from yelling at me
__opts__ = {}
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
    return __salt__['aws_util.run_aws_module'](
        'ec2.manage', 'Server', name, region, name, region, key_name, ami,
        security_groups, instance_type, kernel, user_data,
        termination_protection, addressing_type, placement, ramdisk_id,
        monitoring_enabled, subnet_id, block_device_map,
        instance_initiated_shutdown_behavior, private_ip_address,
        placement_group, additional_info, instance_profile_name,
        instance_profile_arn, tenancy, ebs_optimized, network_interfaces,
        __opts__['test'])


def absent(
    name,
    region,
        force_termination=False):
    """
    Ensure a server does not exist

    Most parameters are described in ``ec2.manage`` module

    """
    return __salt__['aws_util.run_aws_module'](
        'ec2.terminate', 'Server', name, region, name, region,
        force_termination, __opts__['test'])


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
    return __salt__['aws_util.run_aws_module'](
        'ec2.manage_security_group', 'Security group', name, region, name,
        region, description, vpc_id, rules, rules_egress, __opts__['test'])


def security_group_present(
    name,
    region,
    description,
    vpc_id=None):
    """
    Ensure a security group with the given name exists

    Unlike ``security_group``, this only ensures that the group exists. It will
    not manage the rules of the security group.

    Most parameters are described in ``ec2.create_bare_security_group`` module

    """
    return __salt__['aws_util.run_aws_module'](
        'ec2.create_bare_security_group', 'Security group', name, region, name,
        region, description, vpc_id, __opts__['test'])


def security_group_absent(
    name,
    region,
        group_id=None):
    """
    Ensure a Security Group does not exist

    Most parameters are described in ``ec2.manage_security_group`` module

    """
    return __salt__['aws_util.run_aws_module'](
        'ec2.delete_security_group', 'Security group', name, region, name,
        region, group_id, __opts__['test'])


def keypair(
    name,
    region,
        content):
    """
    Ensure a keypair exists

    """
    return __salt__['aws_util.run_aws_module'](
        'ec2.create_keypair', 'Keypair', name, region, name, region, content,
        __opts__['test'])


def keypair_absent(
    name,
        region):
    """
    Ensure a keypair does not exist

    """
    return __salt__['aws_util.run_aws_module'](
        'ec2.delete_keypair', 'Keypair', name, region, name, region, __opts__['test'])
