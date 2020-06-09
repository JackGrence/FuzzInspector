import r2pipe
import argparse
import json
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

class VulnPath:
    def __init__(self, elf, addr):
        self.r2 = r2pipe.open(elf)
        self.r2.cmd('aa')
        self.r2.cmd('aac')
        self.r2.cmd(addr)
        self.addr = int(addr, 16)
        self.block_base = int(self.r2.cmd('ab | grep ^addr').split(' ')[1], 16)
        func_info = json.loads(self.r2.cmd('afij'))[0]
        self.func_base = func_info['offset']
        self.func_name = func_info['name']

    def __del__(self):
        self.r2.quit()

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
            callers.add(caller['fcn_name'])
        return OD(childs)

    def _draw_call_path(self):
        callers = {self.func_name}
        tree = {self.func_name: self._find_callers(self.func_base, callers, [])}
        tr = LeftAligned()
        # TODO: quickly
        symbols_str = ''
        for func in callers:
            if 'sym' in func:
                symbols_str += func.replace('sym.', ' ')
        return tr(tree), symbols_str

    def analyze(self, is_call_stack, is_block_path, is_vuln_func):
        # parse function block
        func_blocks = json.loads(self.r2.cmd('abj'))
        call_maps = {}
        for block in func_blocks:
            if 'jump' in block:
                call_maps.setdefault(block['jump'], []).append(('j', block['addr']))
            if 'fail' in block:
                call_maps.setdefault(block['fail'], []).append(('f', block['addr']))
        if is_block_path:
            self._draw_path(call_maps, self.block_base)
        if is_call_stack or is_vuln_func:
            tree, callers = self._draw_call_path()
            if is_call_stack:
                print(tree)
            if is_vuln_func:
                print(callers)

    def _draw_path(self, call_maps, target):
        tree = {hex(target): self._build_tree(call_maps, target, [])}
        tr = LeftAligned()
        print(tr(tree))

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
    parser.add_argument('vuln_addr', type=str)
    parser.add_argument('-c', '--call-stack', help='show call stack', action='store_true')
    parser.add_argument('-b', '--block-path', help='show block path', action='store_true')
    parser.add_argument('-f', '--vuln-functions', help='list vulnerable functions', action='store_true')
    
    args = parser.parse_args()
    vuln_path = VulnPath(args.vuln_elf, args.vuln_addr)
    vuln_path.analyze(args.call_stack, args.block_path, args.vuln_functions)

if __name__ == '__main__':
    main()
