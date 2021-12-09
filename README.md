Role Name
=========

Install and configure lustre clients and servers.

Requirements
------------

- By default this targets CentOS 7.9 (2009).
- For servers, either:
  - Appropriate (patched) kernel packages should be installed e.g. using [ansible-role-linux-kernel](https://github.com/mjrasobarnett/ansible-role-linux-kernel), or
  - Install unpatched kernel-* packages matching the current kernel (possibly updating the kernel first) and use `lustre_install_type: patchless-ldiskfs-server`.

Role Variables
--------------

See `defaults/main.yml`.

Dependencies
------------

None.

Example Playbook
----------------

TODO

License
-------

TODO

Author Information
------------------

TODO
