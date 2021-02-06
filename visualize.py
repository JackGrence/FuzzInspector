import threading
import time
import os
import select
import subprocess
import struct
import r2pipe
import json
import queue
import hexdump


class CPUStateHelper:

    # str_5_0x1234, byte_6_0x1234, u64_8_0x1234, u32_4_0x1234, u16_2_0x1234
    # TODO: bootstrap table
    @classmethod
    def html(cls, ql):
        result = ''
        for ctx in ql.viscontext:
            name = ctx.split('_')
            if len(name) == 3:
                name[1] = int(name[1], 0)
                name[2] = int(name[2], 0)
                if name[0] == 'str':
                    result += cls.str(ql, name[1], name[2])
                elif name[0] == 'byte':
                    result += cls.byte(ql, name[1], name[2])
                elif name[0][0] == 'u':
                    name[0] = int(name[0][1:])
                    result += cls.unpack(ql, name[0], name[1], name[2])
            elif 'stack' in ctx:
                result += cls.stack(ql)
            elif 'default' in ctx:
                result += cls.default(ql)
            else:
                result += cls.reg(ql, ctx)
        return result

    @classmethod
    def unpack(cls, ql, unpack, length, addr):
        unpack_helper = {64: ql.unpack64, 32: ql.unpack32, 16: ql.unpack16}
        # ex: value = ql.unpack32(ql.mem.read(addr, 4))
        result = ''
        item_size = unpack // 8
        for i in range(length):
            value = unpack_helper[unpack](ql.mem.read(addr, item_size))
            result += f'{hex(addr)} = {hex(value)}<br>'
            addr += item_size
        return result

    @classmethod
    def byte(cls, ql, length, addr):
        result = f'{hex(addr)}:<br>'
        result += hexdump.hexdump(ql.mem.read(addr, length), result='return')
        result += '<br>'
        result = result.replace('\n', '<br>')
        return result

    @classmethod
    def str(cls, ql, length, addr):
        result = ''
        for i in range(length):
            s = ql.mem.string(addr)
            result += f'{hex(addr)}: {s}<br>'
            addr += len(s) + 1
        return result
    
    @classmethod
    def reg(cls, ql, name):
        value = ql.reg.read(name)
        return f'{name} = {hex(value)}<br>'

    @classmethod
    def stack(cls, ql):
        result = ''
        num_bytes = ql.archbit // 8
        for i in range(10):
            name = ql.reg.sp + i * num_bytes
            value = ql.mem.read(name, num_bytes)
            value = ql.unpack(value)
            result += f'{hex(name)} = {hex(value)}<br>'
        return result

    @classmethod
    def default(cls, ql):
        result = ''
        for reg in ql.reg.register_mapping:
            result += cls.reg(ql, reg)
        result += cls.stack(ql)
        return result


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
        addr_list = self.parse_visresult(addr_list.stdout)

        for addr in addr_list:
            addr = hex(int(addr, 0))
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
        result = self.parse_visresult(result.stdout)
        return result if result else ''

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
        if self.parse_visresult(result.stdout):
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

    def parse_visresult(self, output):
        output = output.split(b'visualizer_afl:')
        output = filter(lambda x: b'VISEND' in x, output)
        output = list(map(lambda x: x.split(b'VISEND')[0].decode(), output))
        return output


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
