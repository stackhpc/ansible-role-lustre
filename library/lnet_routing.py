#!/usr/bin/python

DOCUMENTATION = """
---
module: lnet_routing.py
short_description: Configure lnet routing dynamically via lnetctl
description:
  - Uses lnetctl to dynamically update lnet routing configuration on-the-fly
options:
  enable:
    description:
      - Enable/disable lnet routing
    type: bool
  buffers:
    description:
      - set routing buffers
    type: dict
requirements:
  - Uses (C(lnetctl)).
"""
EXAMPLES = r'''
- name: "Configure lnet"
  lnet_routing:
    enable: true
    buffers:
      tiny: 2048
      small: 16384
      large: 1024
'''

RETURN = r''' # '''

import re
import json
from ansible.module_utils.basic import AnsibleModule

import yaml
try:
    from yaml import CLoader as Loader, CDumper as Dumper
except ImportError:
    from yaml import Loader, Dumper

def main():
    module_args = dict(
        enable=dict(type='bool'),
        buffers=dict(type='dict', default={}),
    )

    module = AnsibleModule(
        argument_spec=module_args,
        supports_check_mode=True
    )

    result = dict(
        changed=False
    )

    current = {}
    wanted = {}

    enable_routing=module.params.get('enable')
    routing_buffers=module.params.get('buffers')

    wanted['enable_routing'] = enable_routing

    # Populate both `got` and `wanted`.
    lnetctl_cmd = module.get_bin_path('lnetctl')
    if not lnetctl_cmd:
      if module.check_mode:
        module.warn("'lnetctl' executable not found. Cannot configure routing")
        module.exit_json(**result)
      else:
        module.fail_json(changed=False, msg="'lnetctl' executable not found.")

    # Run lnetctl to get current routing params
    rc, raw_routing_config, err = module.run_command("{cmd} routing show".format(cmd=lnetctl_cmd))

    if rc != 0:
      module.fail_json(changed=False, msg="Failed to get current parameters from lnetctl. rc: {}. Error: {}".format(rc, err))

    # Parse output from lnetctl command from yaml into dictionary of configuration
    try:
      current_routing_config = yaml.load(raw_routing_config)
    except yaml.YAMLError as exc:
      module.fail_json(changed=False, msg="Failed to parse valid yaml from lnetctl routing show. Exception: {}".format(exc))

    if enable_routing is not None:
      # Set desired state
      wanted['enable_routing'] = enable_routing

      if enable_routing:
        if 'tiny' in routing_buffers:
          wanted['tiny_buffers'] = int(routing_buffers.get('tiny'))
        if 'small' in routing_buffers:
          wanted['small_buffers'] = int(routing_buffers.get('small'))
        if 'large' in routing_buffers:
          wanted['large_buffers'] = int(routing_buffers.get('large'))
      else:
        wanted['tiny_buffers'] = 0
        wanted['small_buffers'] = 0
        wanted['large_buffers'] = 0

      # Determine current state
      if current_routing_config is None:
        # No values, routing is not enabled
        current['enable_routing'] = False
        current['tiny_buffers'] = 0
        current['small_buffers'] = 0
        current['large_buffers'] = 0

      elif 'routing' in current_routing_config:
        # 'routing' is structured as a list of dictionaries, where one dictionary should contain the key 'enable'
        for entry in current_routing_config['routing']:
          if 'enable' in entry:
            current['enable_routing'] = bool(entry['enable'])

        # 'buffers' is a simple dictionary and will only exist if routing is enabled
        if 'buffers' in current_routing_config:
          current['tiny_buffers'] = int(current_routing_config['buffers']['tiny'])
          current['small_buffers'] = int(current_routing_config['buffers']['small'])
          current['large_buffers'] = int(current_routing_config['buffers']['large'])

      else:
      	module.fail_json(changed=False, msg="Unexpected format of output from lnetctl routing show. Output: {}".format(current_routing_config))


    if current != wanted:
        result['changed'] = True
        result['diff'] = dict(
            before=current,
            after=wanted,
        )

    if module.check_mode or not result['changed']:
        module.exit_json(**result)

    ##############
    # Making changes
    #

    # Calculate difference between current & wanted settings, where we keep the 'wanted' when values differ
    set_current = set(current.items())
    set_wanted = set(wanted.items())
    difference = dict(set_wanted - set_current)
    module.debug("Current settings: {}".format(set_current))
    module.debug("Wanted settings: {}".format(set_wanted))
    module.debug("Difference: {}".format(difference))

    # Use 'results' to store output of commands run as feedback to user
    result['results'] = []

    if 'enable_routing' in difference:
        command = "{cmd} set routing {value}".format(cmd=lnetctl_cmd, value=int(difference['enable_routing']))
        rc, output, err = module.run_command(command)
        if rc != 0:
            module.fail_json(changed=False, msg="lnetctl command exited with error: {}. rc: {}. err: {}".format(command, rc, err))
        result['results'].extend([command])

    for setting in ['tiny_buffers', 'small_buffers', 'large_buffers']:
    	if setting in difference:
    	    command = "{cmd} set {setting} {value}".format(cmd=lnetctl_cmd, setting=setting, value=int(difference[setting]))
    	    rc, output, err = module.run_command(command)
    	    if rc != 0:
    	        module.fail_json(changed=False, msg="lnetctl command exited with error: {}. rc: {}. err: {}".format(command, rc, err))
    	    result['results'].extend([command])

    module.exit_json(**result)

if __name__ == '__main__':
    main()

