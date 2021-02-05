import threading
import time
import os
import select
import subprocess
import struct
import r2pipe
import json
import queue


class BinaryWorker:

    ACTION_BITMAP = 1
    ACTION_CPUSTATE = 2
    ACTION_RELATION = 3

    def __init__(self, action, address=0, basicblock=0, seeds=[], context=[]):
        self.action = action
        self.address = address
        self.basicblock = basicblock
        self.seeds = seeds
        self.context = context

    def run(self, data, cnt):
        if self.action == BinaryWorker.ACTION_BITMAP:
            # new or use old
            data['bitmap'] = self.bitmap(data.get('bitmap', {}))
        elif self.action == BinaryWorker.ACTION_CPUSTATE:
            # always new
            data['cpustate'] = self.cpustate()
            data['cpustate_cnt'] = cnt
        elif self.action == BinaryWorker.ACTION_RELATION:
            # always new
            data['relationship'] = self.relationship()
            data['relationship_cnt'] = cnt

    def bitmap(self, result):
        '''
        bitmap = {
          STR_ADDR1: {
            'hit': N
            'seed': []
          }
        }
        '''
        filename = self.seeds[0]
        # python ql.py inputfile debug_level trace
        addr_list = subprocess.run(['python', 'ql.py', filename, '0', 'trace'], stdout=subprocess.PIPE)
        addr_list = addr_list.stdout.split(b'visualizer_afl:')
        addr_list = filter(lambda x: b'END' in x, addr_list)
        addr_list = list(map(lambda x: int(x.split(b'END')[0], 0), addr_list))

        for addr in addr_list:
            addr = hex(addr)
            result[addr] = result.get(addr, {'hit': 0, 'seed': []})
            result[addr]['hit'] += 1
            if filename not in result[addr]['seed']:
                result[addr]['seed'].append(filename)

        return result


    def cpustate(self):
        if not self.seeds:
            return
        filename = self.seeds[0]
        result = subprocess.run(['python', 'ql.py', filename, '0', 'no',
                                 self.address, *self.context],
                                stdout=subprocess.PIPE)
        context = result.stdout.split(b'visualizer_afl:')
        if len(context) < 2:
            return
        context = context[1]
        context = context.split(b'VISEND')
        if len(context) < 2:
            return
        context = context[0]
        return context.decode()

    '''
    Return unmutable offsets
    '''
    def colorize(self, buf, l, r):
        old_buf = buf[:]
        buf = buf[:l] + os.urandom(r - l) + buf[r:]
        filename = '/tmp/vis.cur'
        with open(filename, 'wb') as f:
            f.write(buf)
        result = subprocess.run(['python', 'ql.py', filename, '0', 'no',
                                 self.address, *self.context],
                                stdout=subprocess.PIPE)
        if b'visualizer_afl:' in result.stdout:
            # still hit address, mutable
            return []
        else:
            # path change, find unmutable part
            if r - l <= 1:
                return [l]
            m = (l + r) // 2
            result = self.colorize(old_buf, l, m)
            result += self.colorize(old_buf, m, r)
            return result

    def relationship(self):
        filename = self.seeds[0]
        with open(filename, 'rb') as f:
            buf = f.read()
        # colorize
        unmutable = self.colorize(buf, 0, len(buf))
        return f'{self.address} + {unmutable}'


class BitmapReceiver (threading.Thread):

    def __init__(self):
        threading.Thread.__init__(self)
        self.queue = queue.Queue()
        self.data = {}

    def run(self):
        cnt = 0
        while True:
            worker = self.queue.get()
            worker.run(self.data, cnt)
            cnt += 1
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

    def get_block_addr(self, addr):
        return hex(self.r2.cmdj(f'pdbj @{addr}')[0]['offset'])


if __name__ == '__main__':
    block_info = BlockParser('/usr/bin/readelf')
    print(block_info.get_func_block('main'))
    bitmap = BitmapReceiver("/tmp/afl_visualizer.pipe")
    bitmap.start()
    bitmap.join()
