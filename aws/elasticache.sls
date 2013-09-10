#!pydsl

__pydsl__.set(ordered=True)

for group in __pillar__.get('aws', {}).get('elasticache_parameter_groups', []):
    state('parameter-group-' + group['name']).elasticache.parameter_group(**group)

for group in __pillar__.get('aws', {}).get('elasticache_security_groups', []):
    state('security-group-' + group['name']).elasticache.security_group(**group)

for cache in __pillar__.get('aws', {}).get('elasticaches', []):
    state('elasticache-' + cache['name']).elasticache.managed(**cache)

for cache in __pillar__.get('aws', {}).get('absent_elasticaches', []):
    state('elasticache-' + cache['name']).elasticache.absent(**cache)

for group in __pillar__.get('aws', {}).get('absent_elasticache_parameter_groups', []):
    state('parameter-group-' + group['name']).elasticache.parameter_group_absent(**group)

for group in __pillar__.get('aws', {}).get('absent_elasticache_security_groups', []):
    state('security-group-' + group['name']).elasticache.security_group_absent(**group)
