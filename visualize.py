import threading
import traceback
import sys
import time
import os
import select
import subprocess
import struct
import r2pipe
import json
import queue
import hexdump
import signal


class CPUStateHelper:

    # str_5_0x1234, byte_6_0x1234, u64_8_0x1234, u32_4_0x1234, u16_2_0x1234
    # TODO: bootstrap table
    @classmethod
    def html(cls, ql):
        result = ''
        try:
            for ctx in ql.viscontext:
                name = ctx.split('_')
                if len(name) == 3:
                    # parse length, reg/mem
                    name[1] = int(name[1], 0)
                    if name[2] in ql.reg.register_mapping:
                        name[2] = ql.reg.read(name[2])
                    else:
                        name[2] = int(name[2], 0)
                    # parse type
                    if name[0] == 'str':
                        result += cls.str(ql, name[1], name[2])
                    elif name[0] == 'byte':
                        result += cls.byte(ql, name[1], name[2])
                    elif name[0][0] == 'u':
                        name[0] = int(name[0][1:])
                        result += cls.unpack(ql, name[0], name[1], name[2])
                    elif name[0] == 'hex':
                        result += cls.hex(ql, name[1], name[2])
                    elif name[0] == 'map':
                        result += cls.map(ql, name[1], name[2])
                elif 'stack' in ctx:
                    result += cls.stack(ql)
                elif 'default' in ctx:
                    result += cls.default(ql)
                elif 'backtrace' in ctx:
                    result += cls.backtrace(ql)
                else:
                    result += cls.reg(ql, ctx)
        except:
            traceback.print_exc(limit=2, file=sys.stdout)
        return result

    @classmethod
    def backtrace(cls, ql):
        result = ''
        if 'r11' in ql.reg.register_mapping:
            byte_len = ql.archbit // 8
            cur_fp = ql.reg.r11
            info = cls.map_search(ql.reg.pc, ql.mem.map_info)[3]
            result += f'#0 {hex(ql.reg.pc)} {info}<br>\n'
            frame_num = 1
            while cur_fp != 0:
                prev_fp = ql.mem.read(cur_fp - byte_len, byte_len)
                prev_fp = ql.unpack(prev_fp)
                ret = ql.mem.read(cur_fp, byte_len)
                ret = ql.unpack(ret)
                info = cls.map_search(ret, ql.mem.map_info)[3]
                result += f'#{frame_num} {hex(ret)} {info}<br>\n'
                cur_fp = prev_fp
                frame_num += 1
        return result

    @classmethod
    def map_search(cls, addr, map_info):
        # [start, end, perm, info]
        if len(map_info) == 1:
            return map_info[0]
        if len(map_info) == 0:
            return []
        mid = len(map_info) // 2
        mid_info = map_info[mid]
        if addr >= mid_info[0] and addr < mid_info[1]:
            return mid_info
        elif addr >= mid_info[1]:
            return cls.map_search(addr, map_info[mid + 1:])
        elif addr < mid_info[0]:
            return cls.map_search(addr, map_info[:mid])

    @classmethod
    def map(cls, ql, length, addr):
        result = ''
        for start, end, perm, info in ql.mem.map_info:
            if addr in range(start, end):
                target = info
                for start, end, perm, info in ql.mem.map_info:
                    if target == info:
                        result += "[+] %08x - %08x - %s - %s    %s<br>\n" % (start, end, hex(addr - start), perm, info)
                break
        return result

    @classmethod
    def hex(cls, ql, length, addr):
        result = f'{hex(addr)}: '
        result += ql.mem.read(addr, length).hex()
        result += '<br>'
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
    ACTION_CONSTRAINT = 4

    def __init__(self, action, address=0, basicblock=0, seeds=[], context=[]):
        self.action = action
        self.address = address
        self.basicblock = basicblock
        self.seeds = seeds
        self.context = context

    def run(self, data, cnt, bin_info):
        if self.action == BinaryWorker.ACTION_BITMAP:
            # new or use old
            data['bitmap'] = self.bitmap(data.get('bitmap', {}), bin_info)
        elif self.action == BinaryWorker.ACTION_CPUSTATE:
            # always new
            data['cpustate'] = self.cpustate(bin_info)
            data['cpustate_cnt'] = cnt
        elif self.action == BinaryWorker.ACTION_RELATION:
            # always new
            data['relationship'] = self.relationship()
            data['relationship_cnt'] = cnt
        elif self.action == BinaryWorker.ACTION_CONSTRAINT:
            self.constraint(data)

    def parse_constraint(self, context):
        '''
        type_offset_data (hex_5_deadbeef)
        offset length data (5 4 0xde 0xad 0xbe 0xef)
        '''
        datatype, offset, data = context.split('_')
        offset = int(offset, 0)
        if datatype == 'hex':
            data = bytes.fromhex(data)
        elif datatype == 'str':
            data = data.encode() + b'\x00'
        else:
            data = b'unknown'

        result = f'{offset} {len(data)} '
        for d in data:
            result += f'{hex(d)} '
        return result

    def constraint(self, bitmapdata):
        '''
        total [constraint...] (2 [constraint1] [constraint2])
        '''
        # context to afl++
        result = f'{len(self.context)} '
        for ctx in self.context:
            data = self.parse_constraint(ctx)
            result += f'{data} '
        bitmapdata['constraint'] = result
        # SIGUSR2 inform afl++
        pids = subprocess.check_output(['pidof', 'afl-fuzz']).split(b' ')
        for pid in map(int, pids):
            os.kill(pid, signal.SIGUSR2)

    def bitmap(self, result, bin_info):
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

        # last one is mapinfo
        bin_info.init(addr_list[-1])
        for addr in addr_list[:-1]:
            addr = hex(int(addr, 0))
            if addr not in result:
                result[addr] = {'hit': 0, 'seed': []}
                bin_info.update(int(addr, 0))
            result[addr]['hit'] += 1
            if filename not in result[addr]['seed']:
                result[addr]['seed'].append(filename)

        return result


    def cpustate(self, bin_info):
        if not self.seeds:
            return

        # do cpustate
        filename = self.seeds[0]
        result = subprocess.run(['python', 'ql.py', filename, '0', 'no',
                                 str(self.address), *self.context],
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
                                 str(self.address), *self.context],
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

    def exec_context(self, buf):
        filename = '/tmp/vis.cur'
        with open(filename, 'wb') as f:
            f.write(buf)
        result = subprocess.run(['python', 'ql.py', filename, '0', 'no',
                                 str(self.address), *self.context],
                                stdout=subprocess.PIPE)
        return self.parse_visresult(result.stdout)

    def exec_context_rand(self, buf, l, r, unmutable=[]):
        old_buf = list(buf[:])
        buf = buf[:l] + os.urandom(r - l) + buf[r:]
        buf = list(buf)
        for i in unmutable:
            buf[i] = old_buf[i]
        buf = bytes(buf)
        return self.exec_context(buf)

    '''
    Return interesting(context changed) offsets
    '''
    def interesting(self, buf, l, r, expect, unmutable=[]):
        result = self.exec_context_rand(buf, l, r, unmutable=unmutable)
        while not result:
            result = self.exec_context_rand(buf, l, r, unmutable=unmutable)

        if ''.join(result) == ''.join(expect):
            # context still the same, return []
            return []
        else:
            # context changed, find interesting part
            if r - l <= 1:
                return [l]
            m = (l + r) // 2
            result = self.interesting(buf, l, m, expect, unmutable=unmutable)
            result += self.interesting(buf, m, r, expect, unmutable=unmutable)
            return result

    def relationship(self):
        filename = self.seeds[0]
        with open(filename, 'rb') as f:
            buf = f.read()
        # colorize
        unmutable = self.colorize(buf, 0, len(buf))
        # interesting bytes
        expect = self.exec_context(buf)
        offset = self.interesting(buf, 0, len(buf), expect, unmutable=unmutable)
        # output
        result = f'{hex(self.address)}<br>'
        result += f'{unmutable}<br>'
        result += f'{offset}<br>'
        result += f'{"".join(expect)}<br>'
        result += hexdump.hexdump(buf, result='return').replace('\n', '<br>')
        result += '<br>'
        return result

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
        self.bin_info = BinaryInfo()

    def run(self):
        cnt = 0
        while True:
            worker = self.queue.get()
            worker.run(self.data, cnt, self.bin_info)
            cnt += 1
            self.queue.task_done()

    def print(self, addr):
        print('--------------------')
        addr = struct.unpack('<Q', addr)[0]
        print(hex(addr))


class BinaryInfo:
    def __init__(self):
        self.binaries = {}

    def info2path(self, info):
        info = info.split('/', 1)
        return '/' + info[1] if len(info) >= 2 else ''

    def init(self, map_info):
        self.last_info = None
        self.map_info = eval(map_info)

    def addr2bin(self, addr):
        # [start, end, perm, info]
        if (self.last_info and
                addr >= self.last_info[0] and addr < self.last_info[1]):
            result_info = self.last_info
        else:
            result_info = CPUStateHelper.map_search(addr, self.map_info)

        self.last_info = result_info

        if not result_info:
            # not found :(
            return addr, None

        start, end, perm, info = result_info
        name = self.info2path(info)
        if not name:
            # not a exist binary :(
            return addr, None
        if name not in self.binaries:
            self.binaries[name] = BlockParser(name, start)
        addr = addr - start + self.binaries[name].r2.cmdj('ij')['bin']['baddr']
        return addr, self.binaries[name]

    def update(self, addr):
        # TODO: binary maybe None
        bin_addr, binary = self.addr2bin(addr)
        binary.update(bin_addr)

    def get_func_block(self, addr):
        bin_addr, binary = self.addr2bin(addr)
        return binary.get_func_block(bin_addr)

    def get_func_addr(self, addr):
        bin_addr, binary = self.addr2bin(addr)
        return binary.get_func_addr(bin_addr)

    def get_block_addr(self, addr):
        bin_addr, binary = self.addr2bin(addr)
        return binary.get_block_addr(bin_addr)

    def basicblock_disasm(self, addr):
        bin_addr, binary = self.addr2bin(addr)
        return binary.basicblock_disasm(bin_addr)


class BlockParser:
    def __init__(self, elf, base=0):
        self.base = base
        self.elf = elf
        self.r2 = r2pipe.open(self.elf)
        print(f'start analyze {self.elf}...')
        self.r2.cmd('aaa')
        self.bits = json.loads(self.r2.cmd('iIj'))['bits']

    def update(self, addr):
        result = self.r2.cmd(f'pdbj @{addr}')
        if not result:
            self.r2.cmd(f'af @{addr}')

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

    def get_func_addr(self, addr):
        return hex(self.r2.cmdj(f'pdbj @{addr}')[0]['fcn_addr'])


if __name__ == '__main__':
    block_info = BlockParser('/usr/bin/readelf')
    print(block_info.get_func_block('main'))
    bitmap = BitmapReceiver("/tmp/afl_visualizer.pipe")
    bitmap.start()
    bitmap.join()
