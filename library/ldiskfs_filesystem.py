#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2013, Alexander Bulimov <lazywolf0@gmail.com>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
import re
__metaclass__ = type

DOCUMENTATION = '''
---
author:
- Alexander Bulimov (@abulimov)
- Matt Rásó-Barnett (matt@rasobarnett.com)
module: ldiskfs_filesystem
short_description: Makes a filesystem
description:
  - This module creates a filesystem.
options:
  target_type:
    description:
    - Lustre target type, choice of 'ost', 'mdt', 'mgs'.
    required: yes
    aliases: [target]
  fsname:
    description:
    - Lustre fsname.
    required: yes
  index:
    description:
    - Particular OST or MDT index. Required for all targets other than MGS.
  dev:
    description:
    - Target path to device or image file.
    required: yes
    aliases: [device]
  dryrun:
    description:
    - If C(yes), only print what would be done, does not affect the disk
    type: bool
    default: 'no'
  replace:
    description:
    - If C(yes), allows device to be replaced
    type: bool
    default: 'no'
  force:
    description:
    - If C(yes), allows to create new filesystem on devices that already has filesystem.
    type: bool
    default: 'no'
  mkfsoptions:
    description:
    - List of format options for the backing fs. to be passed to mkfs command.
    aliases: [mkfsopts]
  service_nodes:
    description:
    - List of NID(s) of all service partners.
    aliases: [servicenodes]
  mgs_nodes:
    description:
    - List of NID(s) of the MGS node, required for all targets other than the MGS.
    aliases: [mgsnodes]
  resizefs:
    description:
    - If C(yes), if the block device and filesystem size differ, grow the filesystem into the space.
    type: bool
    default: 'no'
requirements:
  - Uses tools related to the I(fstype) (C(mkfs)) and C(blkid) command. When I(resizefs) is enabled, C(blockdev) command is required too.
notes:
  - Potential filesystem on I(dev) are checked using C(blkid), in case C(blkid) isn't able to detect an existing filesystem,
    this filesystem is overwritten even if I(force) is C(no).
'''

EXAMPLES = '''
- name: Create a ldiskfs filesystem on /dev/sdb1
  ldiskfs_filesystem:
    dev: /dev/sdb1
'''

from distutils.version import LooseVersion
import os
import platform
import re
import stat

from ansible.module_utils.basic import AnsibleModule


class Device(object):
    def __init__(self, module, path):
        self.module = module
        self.path = path

    def size(self):
        """ Return size in bytes of device. Returns int """
        statinfo = os.stat(self.path)
        if stat.S_ISBLK(statinfo.st_mode):
            blockdev_cmd = self.module.get_bin_path("blockdev", required=True)
            _, devsize_in_bytes, _ = self.module.run_command([blockdev_cmd, "--getsize64", self.path], check_rc=True)
            return int(devsize_in_bytes)
        elif os.path.isfile(self.path):
            return os.path.getsize(self.path)
        else:
            self.module.fail_json(changed=False, msg="Target device not supported: %s" % self)

    def get_mountpoint(self):
        """Return (first) mountpoint of device. Returns None when not mounted."""
        cmd_findmnt = self.module.get_bin_path("findmnt", required=True)

        # find mountpoint
        rc, mountpoint, _ = self.module.run_command([cmd_findmnt, "--mtab", "--noheadings", "--output",
                                                    "TARGET", "--source", self.path], check_rc=False)
        if rc != 0:
            mountpoint = None
        else:
            mountpoint = mountpoint.split('\n')[0]

        return mountpoint

    def __str__(self):
        return self.path


class LDISKFS(object):

    GROW = None
    MKFS = 'mkfs.lustre'
    MKFS_FORCE_FLAGS = '--reformat'

    LANG_ENV = {'LANG': 'C', 'LC_ALL': 'C', 'LC_MESSAGES': 'C'}

    def __init__(self, module):
        self.module = module

    @property
    def fstype(self):
        return type(self).__name__

    def get_fs_size(self, dev):
        """ Return size in bytes of filesystem on device. Returns int """
        raise NotImplementedError()

    def create_mgs(self):
        mkfsopts = self.module.params.get('mkfsoptions')
        dev = self.module.params.get('dev')
        dryrun = self.module.params.get('dryrun')
        force = self.module.params.get('force')
        servicenodes = self.module.params.get('service_nodes')

        if self.module.check_mode:
            return

        mkfs = self.module.get_bin_path(self.MKFS, required=True)
        cmd = [mkfs, '--mgs']

        if dryrun:
            cmd.append("--dryrun")
        if force:
            cmd.append(self.MKFS_FORCE_FLAGS)
        if servicenodes:
            cmd.append(" ".join("--servicenode=\'{}\'".format(nid) for nid in servicenodes))
        if mkfsopts is not None:
            cmd.append("--mkfsoptions \'{}\'".format(mkfsopts))
        if dev is not None:
            cmd.append("\'{}\'".format(dev))

        self.module.log("Executing command: {}".format(" ".join(cmd)))
        self.module.run_command(" ".join(cmd), check_rc=True)

    def create(self):
        target_type = self.module.params.get('target_type')
        index = self.module.params.get('index')
        fsname = self.module.params.get('fsname')
        mkfsopts = self.module.params.get('mkfsoptions')
        dev = self.module.params.get('dev')
        dryrun = self.module.params.get('dryrun')
        force = self.module.params.get('force')
        replace = self.module.params.get('replace')
        mgsnodes = self.module.params.get('mgs_nodes')
        servicenodes = self.module.params.get('service_nodes')

        if self.module.check_mode:
            return

        mkfs = self.module.get_bin_path(self.MKFS, required=True)
        cmd = [mkfs, '--{}'.format(target_type)]

        if dryrun:
            cmd.append("--dryrun")
        if force:
            cmd.append(self.MKFS_FORCE_FLAGS)
        if replace:
            cmd.append("--replace")

        if fsname is not None:
            cmd.append("--fsname {}".format(fsname))

        if index is not None:
            cmd.append("--index {}".format(index))
        else:
            self.module.exit_json(changed=False, msg="Lustre target of type: {} requires setting a value for the 'index' option".format(target_type))

        if mgsnodes:
            cmd.append(" ".join("--mgsnode=\'{}\'".format(nid) for nid in mgsnodes))
        else:
            self.module.exit_json(changed=False, msg="Lustre target of type: {} requires setting a value for the 'mgsnodes' option".format(target_type))

        if servicenodes:
            cmd.append(" ".join("--servicenode=\'{}\'".format(nid) for nid in servicenodes))

        if mkfsopts is not None:
            cmd.append("--mkfsoptions \'{}\'".format(mkfsopts))

        if dev is not None:
            cmd.append("\'{}\'".format(dev))

        self.module.log("Executing command: {}".format(" ".join(cmd)))
        self.module.run_command(" ".join(cmd), check_rc=True)

    def grow_cmd(self, dev):
        cmd = self.module.get_bin_path(self.GROW, required=True)
        return [cmd, str(dev)]

    def grow(self, dev):
        """Get dev and fs size and compare. Returns stdout of used command."""
        devsize_in_bytes = dev.size()

        try:
            fssize_in_bytes = self.get_fs_size(dev)
        except NotImplementedError:
            self.module.fail_json(changed=False, msg="module does not support resizing %s filesystem yet." % self.fstype)

        if not fssize_in_bytes < devsize_in_bytes:
            self.module.exit_json(changed=False, msg="%s filesystem is using the whole device %s" % (self.fstype, dev))
        elif self.module.check_mode:
            self.module.exit_json(changed=True, msg="Resizing filesystem %s on device %s" % (self.fstype, dev))
        else:
            _, out, _ = self.module.run_command(self.grow_cmd(dev), check_rc=True)
            return out

def main():

    # There is no "single command" to manipulate filesystems, so we map them all out and their options
    module = AnsibleModule(
        argument_spec=dict(
            target_type=dict(required=True, aliases=['target'], choices=['ost','mdt','mgs']),
            dev=dict(required=True, aliases=['device']),
            fsname=dict(required=True),
            index=dict(type='int'),
            mkfsoptions=dict(aliases=['mkfsopts']),
            service_nodes=dict(type='list', aliases=['servicenodes']),
            mgs_nodes=dict(type='list', aliases=['mgsnodes']),
            dryrun=dict(type='bool', default=False),
            force=dict(type='bool', default=False),
            replace=dict(type='bool', default=False),
            resizefs=dict(type='bool', default=False),
        ),
        supports_check_mode=True,
    )

    target_type = module.params.get('target_type')
    fsname = module.params.get('fsname')
    index = module.params.get('index')
    dev = module.params.get('dev')
    force = module.params.get('force')
    replace = module.params.get('replace')
    resizefs = module.params.get('resizefs')

    changed = False

    if not os.path.exists(dev):
        module.fail_json(msg="Device %s not found." % dev)
    dev = Device(module, dev)

    cmd = module.get_bin_path('blkid', required=True)
    rc, raw_fs, err = module.run_command("%s -c /dev/null -o value -s TYPE %s" % (cmd, dev))
    # In case blkid isn't able to identify an existing filesystem, device is considered as empty,
    # then this existing filesystem would be overwritten even if force isn't enabled.
    fs = raw_fs.strip()

    filesystem = LDISKFS(module)

    # LDISKFS filesystems appear to blkid as 'ext4' filesystems
    same_fs = (fs  == 'ext4')
    if same_fs and not force:
        # Existing filesystem found. Check what LABEL is set (if any)
        rc, raw_fs_label, err = module.run_command("%s -c /dev/null -o value -s LABEL %s" % (cmd, dev))
        fs_label = raw_fs_label.strip()

        # Check if label matches the MGS format, which is simply 'MGS'
        if fs_label == 'MGS':
          # If device is expected to be an MGS, then do-nothing. Assume device already formatted successfully
          if target_type == 'mgs':
            module.exit_json(changed=False)
          # If not expected to be an MGS, abort
          else:
            module.fail_json(msg="'{}' is already used, with label: {}, "
                                 "use force=yes to overwrite".format(dev, fs_label), rc=rc, err=err)

        # Check if label matches common format for OST or MDT devices
        label_regex = re.compile(
          r"^(?P<fs_name>[\w\-_]+)"    # Match filesystem name
          r"[-:]"                      # Match delimeter between fsname and target name. Either '-' or ':'
          r"(?P<target_type>[A-Z]+)"   # Match target type, either MDT or OST
          r"(?P<index>[a-z0-9]{4})$")  # Match target index

        match = re.search(label_regex, fs_label)

        # If label doesn't match regex, it must be some other filesystem. Abort
        if not match:
          module.fail_json(msg="'{}' is already used, with label: {}, "
                               "use force=yes to overwrite".format(dev, fs_label), rc=rc, err=err)
        # Otherwise, decompose label, and check if the current device matches
        # the type of device that we are attempting to create
        else:
          existing_fs_name = match.group('fs_name')
          existing_target_type = match.group('target_type')
          existing_index = match.group('index')
          new_index = format(index, '04x') if index is not None else index # MGS has index=None

          if (existing_fs_name != fsname):
            module.fail_json(msg="Device '{}' is already used in a different filesystem {}, "
                                 "full label: {}. Use force=yes to "
                                 "overwrite".format(dev, existing_fs_name, fs_label), rc=rc, err=err)
          elif (existing_target_type.lower() != target_type):
            module.fail_json(msg="Device '{}' is already used as a different target type {}, "
                                 "full label: {}. Use force=yes to "
                                 "overwrite".format(dev, existing_target_type, fs_label), rc=rc, err=err)
          elif (existing_index != new_index):
            module.fail_json(msg="Device '{}' is already used with a different index {}, instead of {}, "
                                 "full label: {}. Use force=yes to "
                                 "overwrite".format(dev, existing_index, new_index, fs_label), rc=rc, err=err)
          # If everything matches, then current target is already configured
          # as expected. No further change needed
          else:
            module.exit_json(changed=False)

    # If existing filesystem is not of type ext4, abort
    elif fs and not force:
        module.fail_json(msg="'%s' is already used as %s, use force=yes to overwrite" % (dev, fs), rc=rc, err=err)

    # Create filesystem, depending on target type
    if target_type == 'mgs':
        filesystem.create_mgs()
    elif (target_type == 'mdt') or (target_type == 'ost'):
        filesystem.create()
    else:
        module.fail_json(msg="'%s' is not a supported target_type, choices are 'mgs', 'mdt', 'ost'" % (target_type), rc=rc, err=err)

    changed = True

    module.exit_json(changed=changed)


if __name__ == '__main__':
    main()
