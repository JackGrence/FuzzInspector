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
    def __init__(self, elf):
        self.r2 = r2pipe.open(elf)
        self.r2.cmd('aac')

    def __del__(self):
        self.r2.quit()

    def analyze(self, addr):
        self.r2.cmd(addr)
        addr = int(addr, 16)
        block_addr = int(self.r2.cmd('ab | grep ^addr').split(' ')[1], 16)
        func_base = json.loads(self.r2.cmd('afij'))[0]['offset']
        # parse function block
        func_blocks = json.loads(self.r2.cmd('abj'))
        call_maps = {}
        for block in func_blocks:
            if 'jump' in block:
                call_maps.setdefault(block['jump'], []).append(('j', block['addr']))
            if 'fail' in block:
                call_maps.setdefault(block['fail'], []).append(('f', block['addr']))
        self._draw_path(call_maps, block_addr)

    def _draw_path(self, call_maps, target):
        tree = {hex(target): self._build_tree(call_maps, target)}
        tr = LeftAligned()
        print(tr(tree))

    def _build_tree(self, call_maps, target):
        if target not in call_maps:
            return OD([])
        childs = []
        for cond, caller in call_maps[target]:
            desc = '{} 0x{:x}'.format(cond, caller)
            child = self._build_tree(call_maps, caller)
            childs.append((desc, child))
        return OD(childs)


def main():
    parser = argparse.ArgumentParser(description='find possible exploit path')
    parser.add_argument('vuln_elf', type=str)
    parser.add_argument('vuln_addr', type=str)
    
    args = parser.parse_args()
    vuln_path = VulnPath(args.vuln_elf)
    vuln_path.analyze(args.vuln_addr)

if __name__ == '__main__':
    main()
