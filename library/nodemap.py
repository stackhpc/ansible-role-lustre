#!/usr/bin/python

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

DOCUMENTATION = r'''
---
module: nodemap

short_description: Configure Lustre nodemaps

description: Add, delete or modify existing Lustre nodemaps to match those defined in a yaml-format file. This should be run on the MGS and requires elevated privileges. It supports all nodemap parameters which can be set using the lustre command-line tools, except for `sepol` and `audit_mode`.

options:
    src:
        description: Path to yaml-format file containing nodemaps. See `templates/nodemaps.j2` for an example.
        required: true
        type: str

'''

EXAMPLES = r'''
- name: Apply nodemap config
  nodemap:
    src: /etc/lustre/nodemaps.yml
  register: nodemap_import
- name: Show nodemap changes made
  debug:
    msg: "{{ nodemap_import.diff }}"
'''

RETURN = r'''
diff:
    description: The changes made to apply the nodemaps specified by `src`. Format is similar to `src` but with lines prefixed with "<" for deletion and ">" for addition. Lists and mappings are sorted for predicability. NB Use ANSIBLE_STDOUT_CALLBACK=debug to get more readable formatting.
    type: dict
    returned: always
'''

from ansible.module_utils.basic import AnsibleModule
import subprocess, pprint, sys, re, ast, difflib, datetime, os,  socket, struct

# internal canonical form for nodemap config is:
# - keys in sorted order, where consistency is required (note pyyaml outputs sorted keys anyway)
# - lists are sorted (lusstre treats them as unordered)
# - simple values (i.e. not dicts or lists) are either str or int - latter needs to be explicitly converted


# pyyaml:
from yaml import load, dump # TODO: use safe_load
try:
    from yaml import CLoader as Loader, CDumper as Dumper
except ImportError:
    from yaml import Loader, Dumper

# lctl commands:
NODEMAP_ACTIVATE = "lctl nodemap_activate {new}" # can just overwrite old value
NODEMAP_EXISTS = "lctl nodemap_{mode} {name}"
NODEMAP_SET_FILESET = "lctl nodemap_set_fileset --name {nodemap} --fileset {new!r}" # quote path to ensure "no" fileset ('') is ok
NODEMAP_MODIFY = "lctl nodemap_modify --name {nodemap} --property {property} --value {new}"
NODEMAP_CHANGE_IDMAP = "lctl nodemap_{mode}_idmap --name {nodemap} --idtype {idtype} --idmap {client_id}:{fs_id}"
NODEMAP_CHANGE_RANGE = "lctl nodemap_{mode}_range --name {nodemap} --range {nid}"
NODEMAP_MODIFY_PARAMS = 'squash_gid squash_uid deny_unknown'.split()
# NB for the next two commands the exported yaml (from `lctl get_param nodemap.<nodemap_name>.*`) has e.g. "admin_nodemap" whereas `lctl nodemap_modify --property` just has "admin", unhelpfully!
NODEMAP_SET_ADMIN = "lctl nodemap_modify --name {nodemap} --property admin --value {new}"
NODEMAP_SET_TRUSTED = "lctl nodemap_modify --name {nodemap} --property trusted --value {new}"
NODEMAP_IGNORE_PARAMS = 'audit_mode exports id map_mode sepol'.split()

def cmd(module, cmdline):
    """ Run a space-separated command and return its stdout/stderr.

        Uses shell, blocks until subprocess returns.
    """
    rc, stdout, stderr = module.run_command(cmdline, use_unsafe_shell=True) # need shell else lctl not found TODO: FIXME
    return stdout, stderr

def call(module, cmdline):
    rc, stdout, stderr = module.run_command(cmdline, use_unsafe_shell=True, check_rc=True) # need shell else lctl not found TODO: FIXME
    
def lctl_get_param(module, item, output):
    """ Get a lustre parameter.

        A wrapper for `lctl get_param`.
    
        Args:
            item: str, path to parameter to query - see `lctl get_param --help`
            output: dict which will be modified with results, may be empty.
        
        The output dict is a nested datastructure containing dicts, lists (either of which may be empty), strs or ints.
        Dict keys are always strs. The structure of this (i.e. the nested keys) follows the path-line structure of lctl
        parameters. The same dict may be passed to this function multiple times to build up results from several parameters.
    """
    s, e = cmd(module, "lctl get_param '{item}'".format(item=item)) # need quoting around `item` to avoid shell expansion of ".*" !
    lines = s.strip().split('\n')
    accumulate = []
    for line in lines:
        #print(line)
        if line: # skip empty lines
            #print('line:', line)
            if '=' in line:
                
                # handle accumulated value lines from *previous* object:
                if accumulate:
                    prev_value = r[param] + ''.join(accumulate) # sometimes previous key=value ended"=[" so always prefix that
                    quoted_prev_value = re.sub(r'\s?([^\s:]+):\s?([^\s,]+)', r"'\1':'\2'", prev_value) # add quoting around dict values and keys
                    # turn it into python:
                    try:
                        py_prev_value = ast.literal_eval(quoted_prev_value)
                    except:
                        print('ERROR: failed when parsing', quoted_prev_value)
                        raise
                    
                    # store and reset:
                    r[param] = py_prev_value
                    accumulate = []

                # handle normal lines:
                dotted_param, _ , value = line.partition('=')
                parts = dotted_param.split('.')
                parents = parts[:-1]
                param = parts[-1]
                r = output
                for p in parents:
                    r = r.setdefault(p, {})
                r[param] = value

            else:
                accumulate.append(line)
    return output
    
def load_live(module):
    """ Load live nodemap information.
    
        Returns a nested datastructure in normalised form.
    """
    output = {}
    lctl_get_param(module, "nodemap.*", output)
    s, e = cmd(module, "lctl nodemap_info",) # need quoting to avoid shell expansion!
    nodemaps = [n.split('.')[-1] for n in s.strip().split('\n')]
    #print(nodemaps)
    for nmap in nodemaps:
        lctl_get_param(module, "nodemap.{nmap}.*".format(nmap=nmap), output)
    to_int(output)
    deep_sort(output)

    return output

def load_from_file(path):
    """ Load nodemap info from a file.
    
        Returns a nested datastructure in normalised form.
    """
    with open(path) as f:
        nodemap = load(f.read(), Loader=Loader)
        deep_sort(nodemap)
        # to_int() not needed as file will have been saved with ints
    return nodemap

def deep_sort(data):
    """ In-place sort of any lists in a nested dict/list datastructure. """
    if isinstance(data, list):
        data.sort()
        for item in data:
            deep_sort(item)
    elif isinstance(data, dict):
        for item in data.values():
            deep_sort(item)
    return None

def to_int(data, key_or_idx=None):
    """ Change ints-as-strs in nested python lists/dicts to ints
    
        NB: modifies data in place and returns None
    """
    if key_or_idx is None:
        value = data
    else:
        value = data[key_or_idx]
    if isinstance(value, list):
        for idx, v in enumerate(value):
            to_int(value, idx)
    elif isinstance(value, dict):
        for k, v in value.items():
            to_int(value, k)
    elif isinstance(value, str):
        if value.isdigit():
            data[key_or_idx] = int(value)
        return

def flatten(data):
    """ Flatten a nested dict into a sequence of (keypath, value).

        - `keypath` is a list giving the keys to get to the corresponding value
        - `value` is the value at this keypath - if this is a nested dict then it is shown as an empty dict {}
           with the nested values shown at their corresponding keypaths.
    """
    stack = [([], data)]
    results = []
    while stack:
        keyparts, data = stack.pop(0)
        if isinstance(data, dict):
            if keyparts != []:
                results.append((tuple(keyparts), {}))
            for k in sorted(data.keys()):
                stack.append((keyparts + [k], data[k]))
        else:
            results.append((tuple(keyparts), data))
    return results

def strip_range_id(ranges):
    """ Remove `id` field from ranges in nodemap range list
    
        Works in place, returns None.
    """
    for r in ranges:
        if 'id' in r:
            del r['id']

def diff(left, right):
    """ Diff nested dicts.

        Returns a sequence of (keypath, action, value).

        Where:
        - `keypath` is a list giving the keys to get to the corresponding value
        - `action` is DEL or ADD, with keys with changed values being given as a DEL followed by an ADD
        - `value` is the value added or deleted - if this is a nested dict it is given as {} with the dict contents
           shown as DEL/ADD at the corresponding (longer) keypath.

        The returned sequence is in sorted `keypath` order.
    """

    # convert flattened dicts into dicts with key:=keypath, value:=value for efficent searching for keys
    dleft = dict((k, v) for (k, v) in flatten(left))
    dright = dict((k, v) for (k, v) in flatten(right))

    # remove 'id' key from range: # TODO: find some way to generalise this as key=func, with key maybe wildcarded, e.g. (*, "ranges")
    for d in (dleft, dright):
        for k in d:
            if k[-1] == 'ranges':
                strip_range_id(d[k])

    leftkeys = set(dleft.keys())
    rightkeys = set(dright.keys())
    
    output = []
    for k in sorted(leftkeys | rightkeys):
        if k[-1] in NODEMAP_IGNORE_PARAMS:
            pass # TODO: add verbose output and control?
        elif k in leftkeys and k not in rightkeys:
            output.append((k, 'DEL', dleft[k]))
        elif k in rightkeys and k not in leftkeys:
            output.append((k, 'ADD', dright[k]))
        elif dleft[k] != dright[k]:
            output.append((k, 'DEL', dleft[k]))
            output.append((k, 'ADD', dright[k]))
    return output
    
def range_to_pattern(start_nid, end_nid):
    """ Take nids as provided in range info from lustre and return the patten needed for add_range

        e.g. 192.168.2.0@tp4, 192.168.3.255@tcp4 => 192.168.[2-3].[0-255]@tcp4

        Note the start and end nids MUST produce a continous range considering each segment, e.g. this is not OK:
            192.168.2.253@tp4, 192.168.3.9@tcp4 => 192.168.[2-3].[253-9]@tcp4
        This is a lustre limitation, hence we don't try to handle this case here, as the range info returned from
        lustre is guaranteed to be in this form.
    """
    start, _, netname1 = start_nid.partition('@')
    end, _, netname2 = end_nid.partition('@')
    if netname1 != netname2:
        raise ValueError('invalid range from %s-%s: different netnames' % (start_nid, end_nid))
    output = []
    for s, e in zip(start.split('.'), end.split('.')):
        s, e = int(s), int(e)
        if s < e:
            output.append('[%i-%i]' % (s, e))
        elif s == e:
            output.append(str(s))
        else:
            raise ValueError('invalid range from %s-%s: part has start > end' % (start_nid, end_nid))
        # NB stil don't catch case described in docstring!
    return '.'.join(output) + '@%s' % netname1

def make_changes(module, changes):
    """ Make changes to the live nodemap config as output from diff(). """

    # This is nodemap-specific, e.g. knows that when a nodemap is empty it doesn't need to recurse into parameters, can just delete the entire nodemap.

    deleted_nodemaps = []
    for (keypath, action, value) in changes:
        #print('#', keypath, action, repr(value))
        if keypath[0] != 'nodemap':
            raise ValueError("'nodemap' not at start of key path %s: is this a nodemap diff?" % keypath)
        
        nodemap = keypath[1]
        
        if len(keypath) == 2:
            if nodemap == 'active': # not really a nodemap
                if action == 'ADD': # don't care about what it was
                    call(module, NODEMAP_ACTIVATE.format(new=value))
            else: # nodemap add/delete
                call(module, NODEMAP_EXISTS.format(name=nodemap, mode=action.lower()))
                if action == 'DEL':
                    deleted_nodemaps.append(nodemap)
        else:
            if nodemap not in deleted_nodemaps: # can't changed properties if we've deleted it!
                param = keypath[2]
                if param == 'fileset' and action == 'ADD': # can ignore delete on these, just overwrite
                    call(module, NODEMAP_SET_FILESET.format(nodemap=nodemap, new=value))
                elif param in NODEMAP_MODIFY_PARAMS and action == 'ADD':
                    call(module, NODEMAP_MODIFY.format(nodemap=nodemap, property=param, new=value))
                elif param == 'admin_nodemap' and action == 'ADD':
                    call(module, NODEMAP_SET_ADMIN.format(nodemap=nodemap, new=value))
                elif param == 'trusted_nodemap' and action == 'ADD':
                    call(module, NODEMAP_SET_TRUSTED.format(nodemap=nodemap, new=value))
                elif param == 'idmap': # don't ignore delete as need to get rid of old ones
                    for idmap in value:
                        call(module, NODEMAP_CHANGE_IDMAP.format(mode=action.lower(), nodemap=nodemap, **idmap))
                elif param == 'ranges': # again need to delete old ones
                    for rng in value:
                        pattern = range_to_pattern(rng['start_nid'], rng['end_nid'])
                        call(module, NODEMAP_CHANGE_RANGE.format(mode=action.lower(), nodemap=nodemap, nid='{pattern}'.format(pattern=pattern)))

def changes_to_yaml(changes):
    """ Return a multi-line string of pseudo-yaml from a nested dict produced by `diff()`.
    
        Output is like a yaml version of the original dicts, except that deletions are prefixed with '<'
        and additions with '>'. Note that:
            - Modified values are shown as a deletion and addition.
            - Keys present in both "left" and "right" sides (i.e. needed for changes at deeper nesting levels) are not prefixed with anything.
    """

    lines = []
    nindent = 4
    curr_keypath = []
    for (keypath, action, value) in changes:
        # calculate position in keys wrt previous output:
        common = [a for a, b in zip(curr_keypath, keypath) if a == b]
        new = keypath[len(common):]
        level = len(keypath) - 2
        # output intermediate keys (no action on these):
        for i, k in enumerate(new[:-1]):
            lines.append('%s%s:' % ((' ' * nindent * level), k))
        # output actual change:
        symbol = '<' if action == 'DEL' else '>'
        lines.append(symbol + (' ' * (nindent * (level+1) - 1)) + keypath[-1] + ': ' + (str(value) or repr(value)))
        
        curr_keypath = keypath
    return '\n'.join(lines)
            

def run_module():
    module_args = dict(
        src = dict(type='str', required=True)
    )

    result = dict(
        changed=False,
        diff='',
    )

    module = AnsibleModule(
        argument_spec=module_args,
        supports_check_mode=True,
    )
    
    nodemap_a = load_live(module)
    nodemap_b = load_from_file(module.params['src'])
    changes = diff(nodemap_a, nodemap_b)
    result['diff'] = changes_to_yaml(changes)
    result['changed'] = bool(changes)
    if changes and not module.check_mode:
        make_changes(module, changes)
    module.exit_json(**result)

# def cli():

#     if len(sys.argv) < 2:
#         exit_bad_cli()
#     elif sys.argv[1] == 'export' and len(sys.argv) == 2:
#         live_nodemap = load_live()
#         live_yaml = dump(live_nodemap, Dumper=Dumper, default_flow_style=False)
#         print(live_yaml)
#     elif sys.argv[1] == 'diff' and len(sys.argv) in (3, 4):
#         nodemap_a = load_live() if len(sys.argv) == 3 else load_from_file(sys.argv[2])
#         nodemap_b = load_from_file(sys.argv[-1])
#         changes = diff(nodemap_a, nodemap_b)
#         print(changes_to_yaml(changes))
#     elif sys.argv[1] == 'import' and len(sys.argv) in (3, 4): # NB 4-arg form only for testing!!
#         nodemap_a = load_live() if len(sys.argv) == 3 else load_from_file(sys.argv[2])
#         nodemap_b = load_from_file(sys.argv[-1])
#         changes = diff(nodemap_a, nodemap_b)
#         print(changes_to_yaml(changes))
#         if len(sys.argv) == 4:
#             print('----')
#             make_changes(changes, print)
#         else:
#             make_changes(changes)
    
    # elif sys.argv[1] == '--version' and len(sys.argv) == 2:
    #     print(__version__)
    # elif sys.argv[1] == '--help' and len(sys.argv) == 2:
    #     print(__doc__)
    # else:
    #     exit_bad_cli()
    
if __name__ == '__main__':
    run_module()