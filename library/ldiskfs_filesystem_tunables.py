#!/usr/bin/python

DOCUMENTATION = """
---
module: ldiskfs_filesystem_tunables.py
short_description: Configure dynamic filesystem parameters
description:
  - Uses tune2fs to alter filesystem features
options:
  device:
    description:
      - Block device containing filesystem
    type: string
    required: True
  enable_project_quota:
    description:
      - Enable/disable 'project' filesystem feature
    type: bool
  enable_wide_striping:
    description:
      - Enable/disable 'ea_inode' filesystem feature
    type: bool
  reserved_blocks_percentage:
    description:
      - Set the percentage of the filesystem which may only be allocated by privileged processes. Defaults to 5%
    type: int
requirements:
  - Uses (C(tune2fs)) and C(findmnt) commands.
"""
EXAMPLES = r'''
- name: "Configure MDT ldiskfs features"
  ldiskfs_filesystem_tunables:
    device: '/dev/sda'
    enable_project_quota: true
'''

RETURN = r''' # '''

import re
import json
from ansible.module_utils.basic import AnsibleModule


def main():
    module_args = dict(
        device=dict(required=True, aliases=['dev']),
        enable_project_quota=dict(type='bool'),
        enable_wide_striping=dict(type='bool'),
        reserved_blocks_percentage=dict(type='int'),
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

    enable_project_quota=module.params.get('enable_project_quota')
    enable_wide_striping=module.params.get('enable_wide_striping')
    reserved_blocks_percentage=module.params.get('reserved_blocks_percentage')

    # Populate both `got` and `wanted`.
    blkdev=module.params.get('device')
    tune2fs_cmd = module.get_bin_path('tune2fs', required=True)
    findmnt_cmd = module.get_bin_path('findmnt', required=True)
    # Run tune2fs to get current filesystem params
    rc, raw_tunefs_params, err = module.run_command("{cmd} -l {dev}".format(cmd=tune2fs_cmd, dev=blkdev))

    if rc != 0:
        module.fail_json(changed=False, msg="Failed to get current parameters from device: {}. Output: {}".format(blkdev, err))

    match = re.search(r"^Filesystem features:\s+(?P<features>.*)$", raw_tunefs_params, re.MULTILINE)
    if not match:
        module.fail_json(changed=False, msg="Failed to get filesystem features from tune2fs for device: {}. Output: {}".format(blkdev, raw_tunefs_params))
    features = match.group('features').split()

    if enable_project_quota is not None:
        # Determine current and desired state of project_quota feature
        if 'project' in features:
            current['project_quota'] = True
        else:
            current['project_quota'] = False

        wanted['project_quota'] = enable_project_quota

    if enable_wide_striping is not None:
        # Determine current and desired state of project_quota feature
        if 'ea_inode' in features:
            current['wide_striping'] = True
        else:
            current['wide_striping'] = False

        wanted['wide_striping'] = enable_wide_striping

    if reserved_blocks_percentage is not None:
        match = re.search(r"^Reserved block count:\s+(?P<reserved_block_count>\d+)$", raw_tunefs_params, re.MULTILINE)
        if not match:
            module.fail_json(changed=False, msg="Failed to get 'reserved block count' from tune2fs for device: {}. Output: {}".format(blkdev, raw_tunefs_params.splitlines()))
        reserved_block_count = int(match.group('reserved_block_count'))

        match = re.search(r"^Block count:\s+(?P<block_count>\d+)$", raw_tunefs_params, re.MULTILINE)
        if not match:
            module.fail_json(changed=False, msg="Failed to get 'block count' from tune2fs for device: {}. Output: {}".format(blkdev, raw_tunefs_params))
        block_count = int(match.group('block_count'))
        # Calculate percentage rounded to nearest integer
        current['reserved_blocks_percentage'] = int(round((100.0*reserved_block_count) / block_count))

        wanted['reserved_blocks_percentage'] = reserved_blocks_percentage

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

    # Before doing any changes, check if the device is mounted. If so, fail
    command = "{cmd} --source {dev}".format(cmd=findmnt_cmd, dev=blkdev)
    rc, findmnt_output, err = module.run_command(command)
    if rc == 0:
        module.fail_json(changed=False, msg="findmnt shows device: {} is still mounted. Cannot modify filesystem "
                                            "tunables while device is mounted. Unmount device and try again.".format(blkdev))

    # Calculate difference between current & wanted settings, where we keep the 'wanted' when values differ
    set_current = set(current.items())
    set_wanted = set(wanted.items())
    difference = dict(set_wanted - set_current)
    # Use 'results' to store output of commands run as feedback to user
    result['results'] = []

    if 'project_quota' in difference:
        if difference['project_quota']:
            # Add project feature to filesystem
            command = "{cmd} -O project {dev}".format(cmd=tune2fs_cmd, dev=blkdev)
            rc, output, err = module.run_command(command)
            if rc != 0:
                module.fail_json(changed=False, msg="tune2fs command exited with error: {}".format(command))
            result['results'].extend([command, output])
        else:
            # Remove project feature to filesystem
            command = "{cmd} -O ^project {dev}".format(cmd=tune2fs_cmd, dev=blkdev)
            rc, output, err = module.run_command(command)
            if rc != 0:
                module.fail_json(changed=False, msg="tune2fs command exited with error: {}".format(command))
            result['results'].extend([command, output])

    if 'wide_striping' in difference:
        if difference['wide_striping']:
            # Add ea_inode feature to filesystem
            command = "{cmd} -O ea_inode {dev}".format(cmd=tune2fs_cmd, dev=blkdev)
            rc, output, err = module.run_command(command)
            if rc != 0:
                module.fail_json(changed=False, msg="tune2fs command exited with error: {}".format(command))
            result['results'].extend([command, output])
        else:
            # Cannot remove ea_inode feature - not support
            module.fail_json(changed=False, msg="Cannot remove ea_inode feature from filesystem. Not supported by tune2fs")

    if 'reserved_blocks_percentage' in difference:
        command = "{cmd} -m {percent} {dev}".format(cmd=tune2fs_cmd, percent=difference['reserved_blocks_percentage'], dev=blkdev)
        rc, output, err = module.run_command(command)
        if rc != 0:
            module.fail_json(changed=False, msg="tune2fs command exited with error: {}".format(command))
        result['results'].extend([command, output])

    module.exit_json(**result)

if __name__ == '__main__':
    main()
