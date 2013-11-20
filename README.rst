AWS States
==========
This is a set of custom states that can idempotently manage AWS
configurations, and a state file that allows you to easily manage the configs
with pillar data.

Since all of the states are just making AWS api calls through boto, you should
only really run this state on a single machine.

Requires boto>=2.12.0 to be installed.

Services
========
Currently supported AWS services are

* EC2 (launching, security groups, keypairs)
* ELB (launching, adding/removing servers)
* ElastiCache (clusters, parameter groups, security groups, replication groups)

Oddities
========
Some actions may complete, yet not be completely finished on the AWS side (for
example, launching an ElastiCache cluster does not mean it is available). This
means that if there are any dependencies, they may fail if the AWS action has
not yet completed. This is fine, because everything is idempotent. Just keep
running the state until it completes with no errors.

TODO
====
DyanamoDB
