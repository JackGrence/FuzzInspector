import r2pipe
import argparse
import json
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
    def __init__(self, elf, addr_list):
        self.r2 = r2pipe.open(elf)
        self.r2.cmd('aa')
        self.r2.cmd('aac')
        self.vuln_path = {}
        for addr in addr_list:
            self.vuln_path[addr] = VulnPath(self.r2, int(addr, 16))

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
            symbol_list = self.r2.cmd('isq | grep {:x} | awk \'{{print $3}}\''.format(func))
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
    vuln_lib = list(Path(args.rootfs).rglob(args.vuln_elf))[0].absolute()
    vuln_lib = str(vuln_lib)
    binaries = {}
    binaries[vuln_lib] = VulnBin(vuln_lib, args.vuln_addr)
    if args.block_path:
        binaries[vuln_lib].print_block_path()
    if args.call_stack:
        binaries[vuln_lib].print_call_stack()
    if args.vuln_functions:
        binaries[vuln_lib].print_vuln_func()

if __name__ == '__main__':
    main()
