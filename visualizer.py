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
import glob
from datetime import datetime


class VisualizeHelper:

    STATUS_CHILD = 0
    STATUS_PARENT = 1

    @classmethod
    def init_from_afl_output(cls, bitmap_receiver):
        afl_output_dir = os.getenv('AFL_OUTPUT_DIR')
        for fn in glob.glob(f'{afl_output_dir}/visualizer/*'):
            worker = BinaryWorker(BinaryWorker.ACTION_BITMAP,
                                  seeds=[fn])
            bitmap_receiver.queue.put(worker)

    '''
    child return STATUS_CHILD, mutated data
    parent return STATUS_PARENT, child's stdout
    '''
    @classmethod
    def run_target(cls, data):
        # TODO: stdin or do it in ql.py
        # fork stuff...
        r, w = os.pipe()
        pid = os.fork()
        if pid == 0:
            os.dup2(w, 1)
            os.close(r)
            os.close(w)
            return cls.STATUS_CHILD, data
        else:
            os.close(w)
            result = b''
            buf = os.read(r, 1024)
            while len(buf) != 0:
                result += buf
                buf = os.read(r, 1024)
        return cls.STATUS_PARENT, result

    '''
    Find unmutable bytes by colorize
    '''
    @classmethod
    def find_unmutable(cls, inp):
        unmutable = []
        que = [[inp, 0, len(inp)]]
        while True:
            if not que:
                break
            data, l, r = que.pop()
            new_data = data[:l] + os.urandom(r - l) + data[r:]
            # log
            visoutput = 'visualizer_afl:'
            visoutput += f'Find unmutable from {l} to {r}, '
            visoutput += f'{new_data[:l][-5:]}, '
            visoutput += f'{new_data[l:r]}, '
            visoutput += f'{new_data[r:][:5]}'
            visoutput += 'VISEND'
            print(visoutput)
            sys.stdout.flush()
            # run target
            status, result = cls.run_target(new_data)
            if status == cls.STATUS_CHILD:
                # let child return to ql.py
                return status, result
            if not cls.parse_visresult(result):
                if r - l <= 1:
                    unmutable.append(l)
                    continue
                # miss, find the way
                m = (l + r) // 2
                que.append([data, l, m])
                que.append([data, m, r])
        return status, sorted(unmutable)

    '''
    Find mutable bytes
    '''
    @classmethod
    def find_mutable(cls, inp, expect, unmutable=[]):
        mutable = []
        que = [[inp, 0, len(inp)]]
        while True:
            if not que:
                break
            data, l, r = que.pop()
            new_data = data[:l] + os.urandom(r - l) + data[r:]
            new_data = list(new_data)
            for i in unmutable:
                new_data[i] = data[i]
            new_data = bytes(new_data)
            # log
            visoutput = 'visualizer_afl:'
            visoutput += f'Find mutable from {l} to {r}, '
            visoutput += f'{new_data[:l][-5:]}, '
            visoutput += f'{new_data[l:r]}, '
            visoutput += f'{new_data[r:][:5]}'
            visoutput += 'VISEND'
            print(visoutput)
            sys.stdout.flush()
            # run target
            status, result = cls.run_target(new_data)
            if status == cls.STATUS_CHILD:
                # let child return to ql.py
                return status, result
            result = ''.join(cls.parse_visresult(result))
            if result != expect:
                if r - l <= 1:
                    mutable.append(l)
                    continue
                # miss, find the way
                m = (l + r) // 2
                que.append([data, l, m])
                que.append([data, m, r])
        return status, sorted(mutable)

    @classmethod
    def relationship(cls, ql, inp):
        # colorize
        status, result = cls.find_unmutable(inp)
        if status == cls.STATUS_CHILD:
            # let child return to ql.py
            return result
        unmutable = result
        # interesting bytes
        status, result = cls.run_target(inp)
        if status == cls.STATUS_CHILD:
            return result
        expect = ''.join(cls.parse_visresult(result))
        status, result = cls.find_mutable(inp, expect, unmutable=unmutable)
        if status == cls.STATUS_CHILD:
            return result
        mutable = result

        inp_hexdump = hexdump.hexdump(inp, result='return')
        inp_hexdump = inp_hexdump.replace('\n', '<br>\n')
        result = f'visualizer_afl:\n'
        result += f'Address: {hex(ql.reg.pc)}<br>\n'
        result += f'Unmutable:<br>\n{unmutable}<br>\n'
        result += f'Mutable:<br>\n{mutable}<br>\n'
        result += f'Expect context:<br>\n{expect}<br>\n'
        result += f'Input hexdump:<br>\n{inp_hexdump}<br>\n'
        result += f'VISEND'
        print(result)
        sys.stdout.flush()
        sys.exit(0)
        # output
        return inp

    @classmethod
    def parse_visresult(self, output):
        output = output.split(b'visualizer_afl:')
        output = filter(lambda x: b'VISEND' in x, output)
        output = list(map(lambda x: x.split(b'VISEND')[0].decode(), output))
        return output

    # str_5_0x1234, byte_6_0x1234, u64_8_0x1234, u32_4_0x1234, u16_2_0x1234
    # TODO: bootstrap table
    @classmethod
    def cpustate(cls, ql):
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
        result += '<br>\n'
        return result

    @classmethod
    def unpack(cls, ql, unpack, length, addr):
        unpack_helper = {64: ql.unpack64, 32: ql.unpack32, 16: ql.unpack16}
        # ex: value = ql.unpack32(ql.mem.read(addr, 4))
        result = ''
        item_size = unpack // 8
        for i in range(length):
            value = unpack_helper[unpack](ql.mem.read(addr, item_size))
            result += f'{hex(addr)} = {hex(value)}<br>\n'
            addr += item_size
        return result

    @classmethod
    def byte(cls, ql, length, addr):
        result = f'{hex(addr)}:<br>\n'
        result += hexdump.hexdump(ql.mem.read(addr, length), result='return')
        result += '<br>\n'
        result = result.replace('\n', '<br>\n')
        return result

    @classmethod
    def str(cls, ql, length, addr):
        result = ''
        for i in range(length):
            s = ql.mem.string(addr)
            result += f'{hex(addr)}: {s}<br>\n'
            addr += len(s) + 1
        return result

    @classmethod
    def reg(cls, ql, name):
        value = ql.reg.read(name)
        return f'{name} = {hex(value)}<br>\n'

    @classmethod
    def stack(cls, ql):
        result = ''
        num_bytes = ql.archbit // 8
        for i in range(10):
            name = ql.reg.sp + i * num_bytes
            value = ql.mem.read(name, num_bytes)
            value = ql.unpack(value)
            result += f'{hex(name)} = {hex(value)}<br>\n'
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

    def __init__(self, action, address=0, basicblock=0, seeds=[], context=[], pid=0):
        self.action = action
        self.address = address
        self.basicblock = basicblock
        self.seeds = seeds
        self.context = context
        self.pid = pid

    def run(self, data, cnt, bin_info):
        if self.action == BinaryWorker.ACTION_BITMAP:
            # new or use old
            data['bitmap'] = self.bitmap(data.get('bitmap', {}), bin_info)
            data['bitmap_cnt'] = cnt
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
        ,type,endian,offset,overwrite_length,data
        ex: ,hex,<,0,3,deadbeef
        type endian offset overwirte_length data_cnt data_length data
        ex: array X 0 3 1 3 0xde 0xad 0xbe
        (0xef will ignore now)

        ,type,endian,offset,overwrite_length,data
        ex: ,range32,>,0,4,0x1,0x10000000
        type endian offset overwirte_length data_cnt data_length data
        ex: range big 0 4 2 4 0x01 0x00 0x00 0x00 4 0x00 0x00 0x00 0x10
        (forbid insert mode)
        '''
        # TODO: make string can be insert, support variant length
        delm = context[0]
        datatype, endian, offset, write_len, *data = context[1:].split(delm)
        offset = int(offset, 0)
        write_len = int(write_len, 0)
        bit2pack = {8: 'B', 16: 'H', 32: 'I', 64: 'Q'}
        # Note: we pack integer by network order between fuzzer and visualizer
        # the endian variable is for seed, will process in fuzzer
        if datatype[:5] == 'range':
            bit_len = int(datatype[5:])
            assert len(data) == 2, 'range length error'
            packstr = f'!{bit2pack[bit_len]}'
            data = map(lambda x: struct.pack(packstr, int(x, 0)), data)
        elif datatype[:3] == 'int':
            bit_len = int(datatype[3:])
            packstr = f'!{bit2pack[bit_len]}'
            data = map(lambda x: struct.pack(packstr, int(x, 0)), data)
        elif datatype[:3] == 'str':
            data = map(lambda x: x.encode() + b'\x00', data)
        elif datatype[:3] == 'hex':
            data = map(lambda x: bytes.fromhex(x), data)
        data = list(data)

        # type endian offset overwirte_length data_cnt data_length data
        # ex: range big 4 0 2 4 0x01 0x00 0x00 0x00 4 0x00 0x00 0x00 0x10
        # range -> 0, array -> 1
        # little endian -> 0, big endian -> 1
        result = '0' if datatype[:5] == 'range' else '1'
        result += ' 0' if endian == '<' else ' 1'
        result += f' {offset} {write_len} {len(data)}'
        for data_bytes in data:
            # TODO: variant data length, keep same and padding null now
            data_bytes = data_bytes.ljust(write_len, b'\x00')[:write_len]
            result += f' {len(data_bytes)}'
            for d in data_bytes:
                result += f' {hex(d)}'
        return result

    def constraint(self, bitmapdata):
        '''
        total [constraint...] (2 [constraint1] [constraint2])
        '''
        # context to afl++
        try:
            result = f'{len(self.context)} '
            for ctx in self.context:
                data = self.parse_constraint(ctx)
                result += f'{data} '
        except Exception as e:
            # invalid format, skip and log
            BitmapReceiver.log_error(f'Invalid constraint {self.context} {str(e)}')
            return
        bitmapdata['constraint'] = result
        BitmapReceiver.log_info(f'Parsed constraint {result}')
        # SIGUSR2 inform afl++
        # keep lookup afl-fuzz pid to prevent arbitrary kill
        pids = subprocess.check_output(['pidof', 'afl-fuzz']).split(b' ')
        for pid in map(int, pids):
            if pid == self.pid:
                msg = f'Inform fuzzer {pid} to set constraint'
                BitmapReceiver.log_info(msg)
                os.kill(pid, signal.SIGUSR2)

    def bitmap(self, result, bin_info):
        '''
        bitmap = {
          STR_ADDR1: {
            'hit': N
            'seeds': set()
            'fuzzers': {pid: name}
          }
        }
        '''
        filename = self.seeds[0]
        BitmapReceiver.log_info(f'Analysis seed {filename}')
        # python ql.py inputfile debug_level trace
        addr_list = subprocess.run(['python', 'ql.py', filename, '0', 'trace'], stdout=subprocess.PIPE)
        addr_list = VisualizeHelper.parse_visresult(addr_list.stdout)

        # last one is mapinfo
        bin_info.init(addr_list[-1])
        for addr in addr_list[:-1]:
            try:
                addr = hex(int(addr, 0))
            except ValueError:
                print(addr)
                continue
            if addr not in result:
                result[addr] = {'hit': 0, 'seeds': set(), 'fuzzers': {}}
                bin_info.update(int(addr, 0))
            result[addr]['hit'] += 1
            if filename not in result[addr]['seeds']:
                result[addr]['seeds'].add(filename)
            if self.pid not in result[addr]['fuzzers']:
                fuzzer_name = os.path.abspath(f'{filename}/../../../')
                fuzzer_name = os.path.basename(fuzzer_name)
                result[addr]['fuzzers'][self.pid] = fuzzer_name

        return result


    def cpustate(self, bin_info):
        if not self.seeds:
            return

        # do cpustate
        filename = self.seeds[0]
        BitmapReceiver.log_info(f'Get CPUState {self.context} by seed {filename}')
        result = subprocess.run(['python', 'ql.py', filename, '0', 'no',
                                 str(self.address), *self.context],
                                stdout=subprocess.PIPE)
        result = VisualizeHelper.parse_visresult(result.stdout)

        return result if result else ''

    def relationship(self):
        filename = self.seeds[0]
        BitmapReceiver.log_info(f'Get Relationship {self.context} by seed {filename}')
        result = subprocess.Popen(['python', 'ql.py', filename, '0', 'relation',
                                   str(self.address), *self.context],
                                  stdout=subprocess.PIPE)
        output = b''
        visresult = []
        while True:
            buf = result.stdout.read(32)
            if len(buf) == 0:
                break
            output += buf
            visresult += VisualizeHelper.parse_visresult(output)
            for i in visresult[:-1]:
                BitmapReceiver.log_info(i)
            visresult = visresult[-1:]
            output = output.split(b'VISEND')[-1]
        return visresult

    def parse_visresult(self, output):
        output = output.split(b'visualizer_afl:')
        output = filter(lambda x: b'VISEND' in x, output)
        output = list(map(lambda x: x.split(b'VISEND')[0].decode(), output))
        return output


'''
This is a non-thread safe class
'''
class BitmapReceiver (threading.Thread):

    log_list = []
    log_cnt = 0

    @classmethod
    def log(cls, msg, msgtype='INFO'):
        now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        now = f'[{msgtype}] {now} {msg}'
        cls.log_list.append(now)
        cls.log_cnt += 1
        if len(cls.log_list) > 200:
            # save to file
            with open('fuzzinspector.log', 'a') as f:
                f.write('\n'.join(cls.log_list[:100]))
            for _ in range(100):
                cls.log_list.pop(0)

    @classmethod
    def log_info(cls, msg):
        cls.log(msg, 'INFO')

    @classmethod
    def log_warning(cls, msg):
        cls.log(msg, 'WARN')

    @classmethod
    def log_error(cls, msg):
        cls.log(msg, 'ERROR')

    def __init__(self):
        threading.Thread.__init__(self)
        self.queue = queue.Queue()
        self.data = {'bitmap': {},
                     'bitmap_cnt': 0,
                     'cpustate_cnt': 0,
                     'relationship_cnt': 0}
        self.bin_info = BinaryInfo()

    def hit_info(self, blocks):
        result = {}
        result['addrs'] = {}
        # if block is empty, give it all
        if not blocks:
            blocks = self.data['bitmap'].keys()
        # prepare hit, seeds
        for block in blocks:
            # set default value
            result['addrs'][block] = {'hit': 0, 'fuzzers': {}}
            cur_block = result['addrs'][block]
            # set value if exist
            if block in self.data['bitmap']:
                cur_block['hit'] = self.data['bitmap'][block]['hit']
                cur_block['fuzzers'] = self.data['bitmap'][block]['fuzzers']
                # set seeds for choosing path
                # only set at first hitted block
                if 'seeds' not in result:
                    result['seeds'] = sorted(self.data['bitmap'][block]['seeds'])
        return result

    def to_json(self, blocks, bitmap_cnt, cpustate_cnt,
                relationship_cnt, log_cnt):
        # init
        result = dict(self.data)
        # bitmap
        if self.data['bitmap_cnt'] == bitmap_cnt:
            result['bitmap'] = None
        else:
            result['bitmap'] = self.hit_info(blocks)
        # cpustate
        if self.data['cpustate_cnt'] == cpustate_cnt:
            result['cpustate'] = None
        # relationship
        if self.data['relationship_cnt'] == relationship_cnt:
            result['relationship'] = None
        # log
        if BitmapReceiver.log_cnt == log_cnt:
            result['log'], result['log_cnt'] = None, log_cnt
        else:
            result['log'], result['log_cnt'] = self.log2json(log_cnt)
        return json.dumps(result)

    def log2json(self, log_cnt):
        cur_cnt = BitmapReceiver.log_cnt
        if log_cnt > cur_cnt:
            return BitmapReceiver.log_list[:], cur_cnt
        return BitmapReceiver.log_list[log_cnt - cur_cnt:], cur_cnt

    def run(self):
        cnt = 1
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
            result_info = VisualizeHelper.map_search(addr, self.map_info)

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
        addr = self.binaries[name].addr_ql_to_r2(addr)
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

    def get_basic_block_func_dot(self, addr):
        bin_addr, binary = self.addr2bin(addr)
        result = [binary.addr_r2_to_ql(0)]
        result.append(json.dumps(binary.get_basic_block_func_dot(bin_addr)))
        return result


class BlockParser:
    def __init__(self, elf, base=0):
        self.base = base
        self.elf = elf
        self.r2 = r2pipe.open(self.elf)
        print(f'start analyze {self.elf}...')
        self.r2.cmd('aaa')
        self.bits = json.loads(self.r2.cmd('iIj'))['bits']

    def get_basic_block_func_dot(self, addr):
        return self.r2.cmd(f'agfd @{addr}')

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
            rebase_addr = self.addr_r2_to_ql(block['addr'])
            key = hex(block['addr'])
            blocks[key] = blocks.get(key, {'name': hex(rebase_addr), 'children': []})

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
        result = self.r2.cmdj(f'pdbj @{addr}')
        for i in result:
            i['offset'] = self.addr_r2_to_ql(i['offset'])
        return result

    def get_block_addr(self, addr):
        result = self.r2.cmdj(f'pdbj @{addr}')[0]['offset']
        result = self.addr_r2_to_ql(result)
        return hex(result)

    def get_func_addr(self, addr):
        result = self.r2.cmdj(f'pdbj @{addr}')[0]['fcn_addr']
        result = self.addr_r2_to_ql(result)
        return hex(result)

    def addr_r2_to_ql(self, addr):
        return addr - self.r2.cmdj('ij')['bin']['baddr'] + self.base

    def addr_ql_to_r2(self, addr):
        # ql = r2 - baddr + base
        # r2 = ql - (0 - baddr + base)
        return addr - self.addr_r2_to_ql(0)


if __name__ == '__main__':
    block_info = BlockParser('/usr/bin/readelf')
    print(block_info.get_func_block('main'))
    bitmap = BitmapReceiver("/tmp/afl_visualizer.pipe")
    bitmap.start()
    bitmap.join()
