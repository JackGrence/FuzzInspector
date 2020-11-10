import pika
import sys
import os
import unicornafl

# Make sure Qiling uses our patched unicorn instead of it's own,
# second so without instrumentation!
unicornafl.monkeypatch()
from qiling import *


def ql_bitmap(ql, address, size):
    ql.s.append(f'{address:08x}')
    if len(ql.s) > 500:
        ql.channel.basic_publish(exchange='',
                                 routing_key=ql.queue_name,
                                 body=''.join(ql.s))
        ql.s = []


def start_afl(_ql: Qiling):
    # now emulate the EXE
    def place_input_callback(uc, inp, _, data):
        env_var = ("SCRIPT_NAME=/dniapi/").encode()
        env_vars = env_var + inp[:0x1000 - 1] + b"\x00"
        _ql.mem.write(_ql.target_addr, env_vars)
    """
    Callback from inside
    """
    # We start our AFL forkserver or run once if AFL is not available.
    # This will only return after the fuzzing stopped.
    try:
        print("Starting afl_fuzz().", hex(_ql.reg.pc))
        with_afl = _ql.uc.afl_fuzz(input_file=_ql.input_file,
                                   place_input_callback=place_input_callback,
                                   exits=[_ql.os.exit_point])
        if _ql.s:
            _ql.channel.basic_publish(exchange='',
                                      routing_key=_ql.queue_name,
                                      body=''.join(_ql.s))
            _ql.s = []
        if not with_afl:
            print("Ran once without AFL attached.")
            os._exit(0)  # that's a looot faster than tidying up.
    except unicornafl.UcAflError as ex:
        # This hook trigers more than once in this example.
        # If this is the exception cause, we don't care.
        # TODO: Chose a better hook position :)
        if ex != unicornafl.UC_AFL_RET_CALLED_TWICE:
            raise


def ql_hook_block_disasm(ql, address, size):
    ql.nprint("\n[+] Tracing basic block at 0x%x" % (address))


def debug(ql):
    print(hex(ql.reg.pc))


def web_sessions_length(ql):
    size = os.stat('./rootfs/tmp/web_sessions').st_size
    ql.reg.r3 += 0x2800 - size


def ignore_check_session(ql):
    ql.reg.pc += 4
    ql.reg.r0 = 0

def ql_hook(ql, main_addr):

    # Bitmap generator
    ql.hook_block(ql_bitmap)

    # find AFL input buffer
    addr = ql.mem.search("SCRIPT_NAME=/dniapi/".encode())
    ql.target_addr = addr[0]

    # hook entry point to start AFL
    ql.hook_address(start_afl, main_addr)

    # the trick to speed up admin.cgi
    ql.hook_address(web_sessions_length, 0x13694)

    ql.hook_address(ignore_check_session, 0x182b8)


with open('cur.env', 'r') as f:
    env = f.read()
env = {i.split('=', 1)[0]: i.split('=', 1)[1] for i in env.split('\n')[:-1]}


# sandbox to emulate the EXE
def my_sandbox(path, rootfs, input_file, debug_level=1):
    env['SCRIPT_NAME'] = env['SCRIPT_NAME'].ljust(0x1000, '\x00')
    # setup Qiling engine
    if debug_level == 2:
        ql = Qiling(path, rootfs, env=env, console=False)
    elif debug_level == 3:
        ql = Qiling(path, rootfs, output='default', env=env, verbose=1)
    elif debug_level == 4:
        ql = Qiling(path, rootfs, output='debug', env=env, verbose=5)
    else:
        ql = Qiling(path, rootfs, output='debug', env=env, verbose=5)
        ql.hook_block(ql_hook_block_disasm)

    ql.input_file = input_file

    # prepare bitmap generator by rabbitMQ
    ql.queue_name = 'hello'
    ql.s = []
    conn_param = pika.ConnectionParameters(host='localhost')
    ql.connection = pika.BlockingConnection(conn_param)
    ql.channel = ql.connection.channel()
    ql.channel.queue_declare(queue=ql.queue_name)

    # do hook stuff and assign entry point
    ql_hook(ql, ql.os.elf_entry)

    # optional for libpthread
    ql.multithread = True
    ql.run()
    os._exit(0)


if __name__ == "__main__":
    if len(sys.argv) <= 1:
        raise ValueError("No input file provided.")
    else:
        my_sandbox(["./rootfs/usr/sbin/admin.cgi"],
                   "./rootfs", sys.argv[1], len(sys.argv))
