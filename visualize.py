import pika
import threading
import time
import os
import select
import subprocess
import struct
import r2pipe
import json


class BitmapReceiver (threading.Thread):

    def __init__(self, queue_name, addr_size=4):
        threading.Thread.__init__(self)
        self.data = {}
        self.queue_name = queue_name
        self.addr_size = addr_size
        conn_param = pika.ConnectionParameters(host='localhost')
        self.connection = pika.BlockingConnection(conn_param)
        self.channel = self.connection.channel()
        self.channel.queue_declare(queue=self.queue_name)

    def generate_data(self, body):
        addr_len = self.addr_size * 2  # ascii
        while body:
            addr = hex(int(body[:addr_len], 16))
            self.data[addr] = self.data.get(addr, 0)
            self.data[addr] += 1
            body = body[addr_len:]

    def run(self):
        for method_frame, _, body in self.channel.consume(self.queue_name):

            # Display the message parts
            self.generate_data(body)

            # Acknowledge the message
            self.channel.basic_ack(method_frame.delivery_tag)

    def print(self, addr):
        print('--------------------')
        addr = struct.unpack("<Q", addr)[0]
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


if __name__ == '__main__':
    block_info = BlockParser('/usr/bin/readelf')
    print(block_info.get_func_block('main'))
    bitmap = BitmapReceiver("/tmp/afl_visualizer.pipe")
    bitmap.start()
    bitmap.join()
