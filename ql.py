import sys
import os
import unicornafl
from visualize import CPUStateHelper

# Make sure Qiling uses our patched unicorn instead of it's own,
# second so without instrumentation!
unicornafl.monkeypatch()
from qiling import *


def ql_bitmap(ql, address, size):
    print(f'visualizer_afl:0x{address:x} END')


def start_afl(_ql: Qiling):
    # now emulate the EXE
    def place_input_callback(uc, inp, _, data):
        env_var = ("SCRIPT_NAME=").encode()
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


def visualizer_hook(ql):
    # mem(type_len_addr):
    print('visualizer_afl:')
    print(CPUStateHelper.html(ql))
    ql.mem.show_mapinfo()
    print('VISEND')
    sys.stdout.flush()


def ql_hook(ql, main_addr, vishook):

    # find AFL input buffer
    addr = ql.mem.search("SCRIPT_NAME=/dniapi/".encode())
    ql.target_addr = addr[0]

    # hook entry point to start AFL
    ql.hook_address(start_afl, main_addr)

    # hook for visualizer
    if vishook is not None:
        ql.hook_address(visualizer_hook, vishook)

    # the trick to speed up admin.cgi
    ql.hook_address(web_sessions_length, 0x13694)

    # ql.hook_address(debug, 0x198b0)


with open('cur.env', 'r') as f:
    env = f.read()
env = {i.split('=', 1)[0]: i.split('=', 1)[1] for i in env.split('\n')[:-1]}


# sandbox to emulate the EXE
def my_sandbox(path, rootfs, input_file,
               trace=False, debug_level=1, hook=None, context=[]):
    env['SCRIPT_NAME'] = env['SCRIPT_NAME'].ljust(0x1000, '\x00')
    ql_arg = {'env': env,
              'verbose': debug_level}
    # setup Qiling engine
    if debug_level <= 1:
        ql_arg['console'] = False
    if debug_level > 1:
        ql_arg['output'] = 'debug'
    ql = Qiling(path, rootfs, **ql_arg)
    if debug_level >= 5:
        ql.hook_block(ql_hook_block_disasm)
    if trace:
        # Bitmap generator
        ql.hook_block(ql_bitmap)

    ql.input_file = input_file

    ql.viscontext = context

    # do hook stuff and assign entry point
    ql_hook(ql, ql.os.elf_entry, hook)

    # optional for libpthread
    ql.multithread = True
    ql.run()
    os._exit(0)


if __name__ == "__main__":
    # ./ql.py input [debug level] [trace] [hook address] [reg/mem...]
    if len(sys.argv) <= 1:
        raise ValueError("No input file provided.")
    else:
        arg = {}
        if len(sys.argv) > 2:
            arg['debug_level'] = int(sys.argv[2])
        if len(sys.argv) > 3:
            arg['trace'] = 'trace' in sys.argv[3]
        if len(sys.argv) > 4:
            arg['hook'] = int(sys.argv[4], 0)
        if len(sys.argv) > 5:
            arg['context'] = sys.argv[5:]
        my_sandbox(["./rootfs/usr/sbin/admin.cgi"],
                   "./rootfs", sys.argv[1], **arg)
