import pika
import threading
import time
import os
import select
import subprocess
import struct
import r2pipe
import json
import queue


class BitmapReceiver (threading.Thread):

    def __init__(self):
        threading.Thread.__init__(self)
        self.queue = queue.Queue()
        self.data = {}

    def generate_data(self, filename, addr_list):
        '''
        self.data = {
          ADDR1: {
            'hit': N
            'seed': set()
          }
        }
        '''
        for addr in addr_list:
            addr = hex(addr)
            self.data[addr] = self.data.get(addr, {'hit': 0, 'seed': set()})
            self.data[addr]['hit'] += 1
            self.data[addr]['seed'].add(filename)

    def run(self):
        while True:
            filename = self.queue.get()
            # python ql.py inputfile debug_level trace
            result = subprocess.run(['python', 'ql.py', filename, '0', 'trace'], stdout=subprocess.PIPE)
            result = result.stdout.split(b'visualizer_afl:')
            result = filter(lambda x: b'END' in x, result)
            result = list(map(lambda x: int(x.split(b'END')[0], 0), result))
            self.generate_data(filename, result)
            self.queue.task_done()

    def print(self, addr):
        print('--------------------')
        addr = struct.unpack('<Q', addr)[0]
        print(hex(addr))


class BlockParser:
    def __init__(self, elf):
        self.elf = elf
        self.r2 = r2pipe.open(self.elf)
        print(f'start analyze {self.elf}...')
        self.r2.cmd('aaa')
        self.bits = json.loads(self.r2.cmd('iIj'))['bits']
        print(f'finish')

    def get_func_block(self, addr):
        # {'jump': 29153, 'fail': 28838, 'opaddr': 28688, 'addr': 28688,
        # 'size': 150, 'inputs': 0, 'outputs': 2, 'ninstr': 32, 'traced': True}

        blocks = {}
        afbj = json.loads(self.r2.cmd(f'afbj @{addr}'))
        for block in afbj:
            key = hex(block['addr'])
            blocks[key] = blocks.get(key, {'name': key, 'children': []})

        assigned = set()

        for b in afbj:
            key = hex(b['addr'])
            jump = hex(b.get('jump', 0))
            fail = hex(b.get('fail', 0))
            if jump in blocks:
                if jump not in assigned:
                    blocks[key]['children'].append(blocks[jump])
                    assigned.add(jump)
            if fail in blocks:
                if fail not in assigned:
                    blocks[key]['children'].append(blocks[fail])
                    assigned.add(fail)
        key = hex(afbj[0]['addr'])

        return blocks[key]

    def basicblock_disasm(self, addr):
        return self.r2.cmdj(f'pdbj @{addr}')

    def basicblock_cpustate(self, addr):
        pass


if __name__ == '__main__':
    block_info = BlockParser('/usr/bin/readelf')
    print(block_info.get_func_block('main'))
    bitmap = BitmapReceiver("/tmp/afl_visualizer.pipe")
    bitmap.start()
    bitmap.join()
