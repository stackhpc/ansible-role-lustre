#!/usr/bin/python

from __future__ import print_function

DOCUMENTATION = """
---
module: lnet_routes.py
short_description: Configure lnet routes dynamically via lnetctl
description:
  - Uses lnetctl to dynamically update lnet routes on-the-fly
options:
  routes:
    description:
      - Dictionary/Hash containing desired LNET routes
    type: dict
requirements:
  - Uses (C(lnetctl)).
  - Requires PyYAML to be installed on the hosts being operated on
"""

EXAMPLES = r'''
- name: "Configure lnet"
  lnet_routes:
    routes:
      'o2ib0':
        - gateway: '192.168.0.1@o2ib2'
        - gateway: '192.168.0.2@o2ib2'
      'o2ib1':
        - gateway: '192.168.0.3@o2ib2'
        - gateway: '192.168.0.4@o2ib2'
'''

RETURN = r''' # '''

from pprint import pprint
import re
import json
from ansible.module_utils.basic import AnsibleModule

try:
    # Python3
    from itertools import filterfalse as filterfalse
except ImportError:
    # Python2
    from itertools import ifilterfalse as filterfalse

from ansible.module_utils.basic import missing_required_lib

YAML_IMPORT_ERR = None
try:
    import yaml
    HAS_YAML = True
except:
    HAS_YAML = False
    YAML_IMP_ERR = traceback.format_exc()

try:
    from yaml import CLoader as Loader, CDumper as Dumper
except ImportError:
    from yaml import Loader, Dumper

class LNETRoute:

  def __init__(self,
               net,
               gateway,
               hop=None,
               priority=None,
              ):

    self.net = net
    self.gateway = gateway
    self.hop = hop
    self.priority = priority

  def __eq__(self, other):
    if isinstance(other, self.__class__):
      return self.__dict__ == other.__dict__
    else:
      return False

  def __ne__(self, other):
    return not self.__eq__(other)

  def __repr__(self):
    return str(self.__dict__)

def main():

    module_args = dict(
        routes=dict(type='dict', default={}),
    )

    module = AnsibleModule(
        argument_spec=module_args,
        supports_check_mode=True
    )

    result = dict(
        changed=False
    )

    # Check for whether we could import yaml library or not
    if not HAS_YAML:
      module.fail_json(msg=missing_required_lib("yaml"),
                       exception=YAML_IMP_ERR)

    # Store path to lnetctl binary
    lnetctl_cmd = module.get_bin_path('lnetctl')
    if not lnetctl_cmd:
      if module.check_mode:
        module.warn("'lnetctl' executable not found. Cannot configure routes")
        module.exit_json(**result)
      else:
        module.fail_json(changed=False, msg="'lnetctl' executable not found.")


    # 'current' and 'wanted' are dictionaries containing the current set
    # of routes, and the wanted set of routes respectively.
    # Each dict is using a key which is composed of the LNET network id,
    # and the gateway for the route, which together form a unique identifier
    # for an LNET route.
    current = {}
    wanted = {}

    # 'wanted_routes' is the argument passed into the module by the user
    # and is structured a bit differently to the yaml representation of
    # routes outputted by 'lnetctl route show'
    wanted_routes = module.params.get('routes')
    # Here we iterate over the wanted_routes and convert them into the
    # format of our 'wanted' dictionary
    for network, routes in wanted_routes.items():
      for route in routes:
        try:
          lnet_route = LNETRoute(network,
                                 route['gateway'],
                                 route.get('hop',-1),
                                 route.get('priority',0),)
        except KeyError as exc:
          module.fail_json(changed=False, msg="Failed to extract expected keys from lnetctl route. Route: {}. Exception: {}".format(route, exc))

        # Construct a key that uniquely defines the route, which is the combination
        # of the network and the gateway
        wanted['route:{} via {}'.format(network, route['gateway'])] = lnet_route


    # Now we determine the state of current routes by querying lnetctl
    # Run lnetctl to get current routing params
    rc, raw_routes_config, err = module.run_command("{cmd} route show --verbose".format(cmd=lnetctl_cmd))
    if rc != 0:
      module.fail_json(changed=False, msg="Failed to get current parameters from lnetctl. rc: {}. Error: {}".format(rc, err))

    # Parse output from lnetctl command from yaml into dictionary of configuration
    try:
      current_routes_config = yaml.load(raw_routes_config)
    except yaml.YAMLError as exc:
      module.fail_json(changed=False, msg="Failed to parse valid yaml from lnetctl route show. Exception: {}".format(exc))

    # Handle when there are no existing routes
    if current_routes_config:
      if 'route' in current_routes_config:
        # 'route' is structured as a list of dictionaries, where each dictionary contain a single route
        for route in current_routes_config['route']:
          # Normalise representation of LNET net suffix. LNET annoyingly represents
          # networks ending in the suffix '0' as equivalent to network names without
          # any numerical suffix, i.e:
          #   tcp0 == tcp
          #   o2ib0 == o2ib
          # To handle this, we normalise all networks without a numerical suffix to add a '0'
          match = re.search(r'^(tcp|o2ib|Elan|ra)\d+$', route['net'])
          if not match:
            normalised_net = route['net'] + '0'
          else:
            normalised_net = route['net']

          try:
            lnet_route = LNETRoute(normalised_net,
                                   route['gateway'],
                                   route['hop'],
                                   route['priority'],)
          except KeyError as exc:
            module.fail_json(changed=False, msg="Failed to extract expected keys from lnetctl route. Route: {}. Exception: {}".format(route, exc))

          # Construct a key using the same scheme as for wanted, above
          current['route:{} via {}'.format(normalised_net, route['gateway'])] = lnet_route

      else:
      	module.fail_json(changed=False, msg="Unexpected format of output from lnetctl routing show. Output: {}".format(current_routes_config))

    # Check whether current state is different from desired state
    if current != wanted:
        result['changed'] = True
        result['diff'] = dict(
            # Note here, to convert to yaml, we simply convert 'current' and 'wanted'
            # into lists of the class attribute dictionaries, so we don't have to
            # figure out how to make PyYAML serialise out object
            before=yaml.safe_dump([x.__dict__ for x in current.values()]),
            after=yaml.safe_dump([x.__dict__ for x in wanted.values()])
        )

    if module.check_mode or not result['changed']:
        module.exit_json(**result)

    ##############
    # Determing what changes are to be made
    #

    # Calculate routes that exist in both current and wanted, using the filter function
    # *only* store routes that exist in both current and wanted
    # These will be routes that we leave alone
    routes_keep = {}
    routes_add = {}
    routes_update = {}
    for key, wanted_route in wanted.items():
      # If there are no current routes, then route must be for adding
      if not current:
        routes_add[key] = wanted_route
        continue

      # If there are current routes, but wanted route doesn't exist yet, then
      # route must be for adding
      if key not in current:
        routes_add[key] = wanted_route
        continue

      for current_key, current_route in current.items():
        # If keys match, then routes are equivalent. Either it's a route to
        # be updated (differing params), or it's a route to keep unmodified
        if key == current_key:
          if wanted_route == current_route:
            routes_keep[key] = wanted_route
            continue
          else:
            routes_update[key] = wanted_route
            continue

    # Now calculate any remaining routes in current, that aren't in wanted
    # These will be routes that we *delete*
    routes_delete = {}
    # We can simply find any keys that exist in current, but not in wanted,
    # since the key uniquely identifies the route
    for key, route in current.items():
      if key not in wanted:
        routes_delete[key] = route

    module.debug("Wanted: \n{}".format(json.dumps([x.__dict__ for x in wanted.values()], indent=4)))
    module.debug("Current: \n{}".format(json.dumps([x.__dict__ for x in current.values()], indent=4)))
    module.debug("Routes to add: \n{}".format(json.dumps([x.__dict__ for x in routes_add.values()], indent=4)))
    module.debug("Routes to delete: \n{}".format(json.dumps([x.__dict__ for x in routes_delete.values()], indent=4)))
    module.debug("Routes to update: \n{}".format(json.dumps([x.__dict__ for x in routes_update.values()], indent=4)))
    module.debug("Routes to keep: \n{}".format(json.dumps([x.__dict__ for x in routes_keep.values()], indent=4)))

    module.log("Total Wanted: {}".format(len(wanted)))
    module.log("Total Current: {}".format(len(current)))
    module.log("Total Routes Adding: {}".format(len(routes_add)))
    module.log("Total Routes Deleting: {}".format(len(routes_delete)))
    module.log("Total Routes Updating: {}".format(len(routes_update)))
    module.log("Total Routes Keeping: {}".format(len(routes_keep)))
    module.log("Total Routes: {}".format(len(routes_keep)+len(routes_add)+len(routes_update)))

    ##############
    # Making changes
    #
    # Use 'results' to store output of commands run as feedback to user
    result['results'] = []
    failed_commands = []

    # Add new routes
    for route in routes_add.values():
      command = "{cmd} route add --net {net} --gateway {gateway} --hop {hop} --priority {priority}".format(
          cmd=lnetctl_cmd,
          net=route.net,
          gateway=route.gateway,
          hop=route.hop,
          priority=route.priority)
      rc, output, err = module.run_command(command)
      if rc != 0:
        failed_commands.append({'command': command, 'rc': rc, 'err': err})
      result['results'].extend([command])

    # Update existing routes
    for route in routes_update.values():
      # First delete route, then add it back again with new parameters
      # lnetctl doesn't support in-place update of route
      command = "{cmd} route del --net {net} --gateway {gateway}".format(
          cmd=lnetctl_cmd,
          net=route.net,
          gateway=route.gateway)
      rc, output, err = module.run_command(command)
      if rc != 0:
        failed_commands.append({'command': command, 'rc': rc, 'err': err})
      result['results'].extend([command])

      command = "{cmd} route add --net {net} --gateway {gateway} --hop {hop} --priority {priority}".format(
          cmd=lnetctl_cmd,
          net=route.net,
          gateway=route.gateway,
          hop=route.hop,
          priority=route.priority)
      rc, output, err = module.run_command(command)
      if rc != 0:
        failed_commands.append({'command': command, 'rc': rc, 'err': err})
      result['results'].extend([command])

    # Delete extraneous routes
    for route in routes_delete.values():
      command = "{cmd} route del --net {net} --gateway {gateway}".format(
          cmd=lnetctl_cmd,
          net=route.net,
          gateway=route.gateway)
      rc, output, err = module.run_command(command)
      if rc != 0:
        failed_commands.append({'command': command, 'rc': rc, 'err': err})
      result['results'].extend([command])

    # If any commands failed to run, exit with error and add this to result output
    if failed_commands:
      result['failed_commands'] = failed_commands
      module.fail_json(msg="{} lnetctl commands failed to execute successfully.".format(len(failed_commands)), **result)

    # Success
    module.exit_json(**result)

if __name__ == '__main__':
    main()
