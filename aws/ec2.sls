#!pydsl

__pydsl__.set(ordered=True)

for group in __pillar__.get('aws', {}).get('security_groups', []):
    state('security-group-' + group['name']).ec2.security_group(
        name=group['name'],
        region=group['region'],
        description=group['description'],
        vpc_id=group.get('vpc_id'),
        rules=group.get('rules'),
        rules_egress=group.get('rules_egress'))

for server in __pillar__.get('aws', {}).get('servers', []):
    state('server-' + server['name']).ec2.present(
    name=server['name'],
    region=server['region'],
    key_name=server['key_name'],
    ami=server['ami'],
    security_groups=server.get('security_groups'),
    instance_type=server.get('instance_type'),
    kernel=server.get('kernel'),
    user_data=server.get('user_data'),
    termination_protection=server.get('termination_protection'),
    addressing_type=server.get('addressing_type'),
    placement=server.get('placement'),
    ramdisk_id=server.get('ramdisk_id'),
    monitoring_enabled=server.get('monitoring_enabled'),
    subnet_id=server.get('subnet_id'),
    block_device_map=server.get('block_device_map'),
    instance_initiated_shutdown_behavior=server.get('instance_initiated_shutdown_behavior'),
    private_ip_address=server.get('private_ip_address'),
    placement_group=server.get('placement_group'),
    additional_info=server.get('additional_info'),
    instance_profile_name=server.get('instance_profile_name'),
    instance_profile_arn=server.get('instance_profile_arn'),
    tenancy=server.get('tenancy'),
    ebs_optimized=server.get('ebs_optimized'),
    network_interfaces=server.get('network_interfaces'))

for server in __pillar__.get('aws', {}).get('servers_absent', []):
    state('server-' + server['name']).ec2.absent(
    name=server['name'],
    region=server['region'],
    force_termination=server.get('force_termination', False))

for group in __pillar__.get('aws', {}).get('security_groups_absent', []):
    state('security-group-' + group['name']).ec2.security_group_absent(
        name=group['name'],
        region=group['region'])
