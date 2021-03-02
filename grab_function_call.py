import r2pipe
import argparse
import json
import sys
from pathlib import Path
from asciitree import LeftAligned
from collections import OrderedDict as OD

# find path from:
#   nmap port mapping service
# trigger point:
#   bug track id
#   CVE vuln function
# scenario:
#   has a vuln/bug lib, from service to vuln lib
#   have multi-vuln/bug functions in a binary, find a way to trigger all
# maybe:
#   speed limit?
#   path explotion?
# RCE gadget:
#   information leak + memory corruption
#   out of bound RW to arbitrary RW

class VulnBin:
    def __init__(self, elf_path, addr_list):
        self.vuln_path = {}
        self.path = elf_path
        self.name = str(Path(elf_path).name)
        self.addr_list = addr_list
        self.r2 = r2pipe.open(self.path)
        self.r2.cmd('aa')
        self.r2.cmd('aac')
        self.set_vuln_path(self.addr_list)

    def filter_vuln_by_symbol(self, vuln_func):
        # find vuln function address
        result = []
        for func in vuln_func:
            func_info = json.loads(self.r2.cmd('afij sym.imp.{}'.format(func)))
            if func_info:
                if func_info[0]['offset'] != 0:
                    result.append(func_info[0]['offset'])
        return result

    def set_vuln_path(self, addr_list):
        self.addr_list = addr_list
        self.vuln_path = {}
        for addr in self.addr_list:
            self.vuln_path[addr] = VulnPath(self.r2, addr)

    def print_block_path(self):
        for addr, vuln_path in self.vuln_path.items():
            print(vuln_path.block_path())

    def print_call_stack(self):
        for addr, vuln_path in self.vuln_path.items():
            tree, symbols = vuln_path.call_stack()
            print(tree)

    def print_vuln_func(self):
        for addr, vuln_path in self.vuln_path.items():
            tree, symbols = vuln_path.call_stack()
            print(symbols)

    def vuln_func(self):
        result = set()
        for addr, vuln_path in self.vuln_path.items():
            tree, symbols = vuln_path.call_stack()
            result |= set(symbols.split())
        return result

    def __del__(self):
        self.r2.quit()

class VulnPath:
    def __init__(self, elf, addr):
        self.r2 = elf
        self.addr = addr
        self.r2.cmd(hex(addr))
        self.block_base = int(self.r2.cmd('ab | grep ^addr').split(' ')[1], 16)
        func_info = json.loads(self.r2.cmd('afij'))[0]
        self.func_base = func_info['offset']
        self.func_name = func_info['name']

    def _find_callers(self, addr, callers, history):
        xrefs = json.loads(self.r2.cmd('axtj {}'.format(addr)))
        if not xrefs:
            return OD([])
        if addr in history:
            return OD([('LOOP', {})])
        childs = []
        for caller in xrefs:
            if 'fcn_name' not in caller:
                continue
            desc = '{}: 0x{:x}'.format(caller['fcn_name'], caller['from'])
            child = self._find_callers(caller['fcn_addr'],
                    callers, history + [addr])
            childs.append((desc, child))
            callers.add(caller['fcn_addr'])
        return OD(childs)

    # TODO: cache
    def call_stack(self):
        callers = {self.func_base}
        tree = {self.func_name: self._find_callers(self.func_base, callers, [])}
        tr = LeftAligned()
        # TODO: quickly
        symbols = []
        for func in callers:
            symbol_list = self.r2.cmd('iEq | grep {:x} | awk \'{{print $3}}\''.format(func))
            symbols += symbol_list.split('\n')[:-1]
        return tr(tree), ' '.join(symbols)

    # TODO: cache
    def block_path(self):
        # parse function block
        self.r2.cmd(hex(self.addr))
        func_blocks = json.loads(self.r2.cmd('abj'))
        call_maps = {}
        for block in func_blocks:
            if 'jump' in block:
                call_maps.setdefault(block['jump'], []).append(('j', block['addr']))
            if 'fail' in block:
                call_maps.setdefault(block['fail'], []).append(('f', block['addr']))
        tree = {hex(self.block_base): self._build_tree(call_maps, self.block_base, [])}
        tr = LeftAligned()
        return tr(tree)

    def _build_tree(self, call_maps, target, history):
        if target in history:
            return OD([('LOOP', {})])
        if target not in call_maps:
            return OD([])
        childs = []
        for cond, caller in call_maps[target]:
            desc = '{} 0x{:x}'.format(cond, caller)
            child = self._build_tree(call_maps, caller, history + [target])
            childs.append((desc, child))
        return OD(childs)


class ExploitPath:
    def __init__(self, rootfs, targets, vuln_bin):
        self.rootfs = rootfs
        self.targets = targets
        self.vuln_bin = vuln_bin
        self.binaries = {}
        self.binaries[vuln_bin.name] = vuln_bin

    # Return vulnerable export symbol in elf
    # And asciitree
    def _find_affected(self, elf, vuln_bin):
        elf_libs = json.loads(elf.r2.cmd('ilj'))
        tree = []
        vuln_addr = []
        for lib_name in elf_libs:
            if lib_name == vuln_bin.name:
                elf_vuln_addr = elf.filter_vuln_by_symbol(vuln_bin.vuln_func())
                vuln_addr += elf_vuln_addr
                # prepare tree
                func_set = set(map(lambda x: hex(x), elf_vuln_addr))
                if func_set:
                    func_set = vuln_bin.vuln_func()
                    tree.append(('{}: {}'.format(lib_name, func_set), {}))
            else:
                if lib_name not in self.binaries:
                    # new VulnBin and check vulnerable
                    lib_path = get_path_or_exit(self.rootfs, lib_name)
                    lib = VulnBin(lib_path, [])
                else:
                    lib = self.binaries[lib_name]
                vuln_func, subtree = self._find_affected(lib, vuln_bin)
                elf_vuln_addr = elf.filter_vuln_by_symbol(vuln_func)
                vuln_addr += elf_vuln_addr
                # prepare tree
                func_set = set(map(lambda x: hex(x), elf_vuln_addr))
                if func_set:
                    func_set = vuln_func
                    tree.append(('{}: {}'.format(lib_name, func_set), subtree))
        vuln_exp_sym = []
        # set vuln path if exist
        if vuln_addr:
            elf.set_vuln_path(vuln_addr)
            vuln_exp_sym = elf.vuln_func()
        # record to binaries if vulnerable
        if vuln_exp_sym:
            self.binaries[elf.name] = elf
        return vuln_exp_sym, OD(tree)

    def find(self):
        for elf_name in self.targets:
            elf_path = get_path_or_exit(self.rootfs, elf_name)
            elf = VulnBin(elf_path, [])
            symbol, tree = self._find_affected(elf, self.vuln_bin)
            tr = LeftAligned()
            tree = tr({elf_name: tree})
            print(tree)


def get_path_or_exit(rootfs, vuln_elf):
    vuln_lib = list(Path(rootfs).rglob(vuln_elf))
    if not vuln_lib:
        sys.exit('{}: no such file'.format(vuln_elf))
    return str(vuln_lib[0].absolute())


def main():
    parser = argparse.ArgumentParser(description='find possible exploit path')
    parser.add_argument('vuln_elf', type=str)
    parser.add_argument('vuln_addr', nargs='*', type=str)
    parser.add_argument('-c', '--call-stack', help='show call stack', action='store_true')
    parser.add_argument('-b', '--block-path', help='show block path', action='store_true')
    parser.add_argument('-f', '--vuln-functions', help='list vulnerable functions', action='store_true')
    parser.add_argument('-r', '--rootfs', default='./', help='find other vulnerable binaries', type=str)
    parser.add_argument('-t', '--targets', default=[], nargs='*', type=str, help='interested binaries for exploit entry')
    parser.add_argument('-e', '--exploit-path', help='show exploit path from targets', action='store_true')
    
    args = parser.parse_args()
    vuln_lib_path = get_path_or_exit(args.rootfs, args.vuln_elf)
    vuln_bin = VulnBin(vuln_lib_path, list(map(lambda x: int(x, 16), args.vuln_addr)))
    if args.block_path:
        vuln_bin.print_block_path()
    if args.call_stack:
        vuln_bin.print_call_stack()
    if args.vuln_functions:
        vuln_bin.print_vuln_func()
    if args.exploit_path:
        exp_path = ExploitPath(args.rootfs, args.targets, vuln_bin)
        exp_path.find()

if __name__ == '__main__':
    main()
