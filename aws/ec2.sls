#!pydsl

__pydsl__.set(ordered=True)

for keypair in __pillar__.get('aws', {}).get('keypairs', []):
    state('keypair-' + keypair['name']).ec2.keypair(**keypair)

# First make sure all security groups exist before managing them.
# This prevents bugs from dependency cycles
for group in __pillar__.get('aws', {}).get('security_groups', []):
    state('bare-security-group-' + group['name']).ec2.security_group_present(
        name=group['name'],
        region=group['region'],
        description=group['description'],
        vpc_id=group.get('vpc_id'))

for group in __pillar__.get('aws', {}).get('security_groups', []):
    state('security-group-' + group['name']).ec2.security_group(**group)

for server in __pillar__.get('aws', {}).get('servers', []):
    state('server-' + server['name']).ec2.present(**server)

for server in __pillar__.get('aws', {}).get('servers_absent', []):
    state('server-' + server['name']).ec2.absent(**server)

for group in __pillar__.get('aws', {}).get('security_groups_absent', []):
    state('security-group-' + group['name']).ec2.security_group_absent(**group)

for keypair in __pillar__.get('aws', {}).get('keypairs_absent', []):
    state('keypair-' + keypair['name']).ec2.keypair_absent(**keypair)
