#!pydsl

__pydsl__.set(ordered=True)

for group in __pillar__.get('aws', {}).get('elasticache_parameter_groups', []):
    state('parameter-group-' + group['name']).elasticache.parameter_group_managed(**group)

for cache in __pillar__.get('aws', {}).get('elasticaches', []):
    state('elasticache-' + cache['name']).elasticache.managed(**cache)

for cache in __pillar__.get('aws', {}).get('absent_elasticaches', []):
    state('elasticache-' + cache['name']).elasticache.absent(**cache)

for group in __pillar__.get('aws', {}).get('absent_elasticache_parameter_groups', []):
    state('parameter-group-' + group['name']).elasticache.parameter_group_absent(**group)
