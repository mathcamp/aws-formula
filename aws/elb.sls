#!pydsl

for elb in __pillar__.get('aws', {}).get('elbs', []):
    state('elb-' + elb['name']).elb.managed(
        name=elb['name'],
        region=elb['region'],
        zones=elb['zones'],
        listeners=elb.get('listeners'),
        subnets=elb.get('subnets'),
        security_groups=elb.get('security_groups'),
        scheme=elb.get('scheme'),
        health_check=elb.get('health_check'),
        policies=elb.get('policies'),
        instances=elb.get('instances')
    )

for elb in __pillar__.get('aws', {}).get('absent_elbs', []):
    state('elb-' + elb['name']).elb.absent(
        name=elb['name'],
        region=elb['region']
    )
