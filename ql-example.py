import sys
import os
import unicornafl
from visualizer import VisualizeHelper

# Make sure Qiling uses our patched unicorn instead of it's own,
# second so without instrumentation!
unicornafl.monkeypatch()
from qiling import *


def ql_bitmap(ql, address, size):
    print(f'visualizer_afl:0x{address:x} VISEND')


def start_afl(_ql: Qiling):
    # now emulate the EXE
    def place_input_callback(uc, inp, _, data):
        if _ql.relation:
            inp = VisualizeHelper.relationship(_ql, inp)
        _ql.uid = os.urandom(10).hex()
        # _ql.mem.write(0x7758a65c, _ql.pack32(0x7ff3bee8))
        with open('rootfs/cur', 'wb') as f:
            f.write(inp)
    """
    Callback from inside
    """
    # We start our AFL forkserver or run once if AFL is not available.
    # This will only return after the fuzzing stopped.
    try:
        print("Starting afl_fuzz().")
        with_afl = _ql.uc.afl_fuzz(input_file=_ql.input_file,
                                   place_input_callback=place_input_callback,
                                   exits=_ql.fuzz_end)
        if not with_afl:
            if _ql.trace:
                print(f'visualizer_afl: {_ql.mem.map_info} VISEND')
                sys.stdout.flush()
            print("Ran once without AFL attached.")
            os._exit(0)  # that's a looot faster than tidying up.
    except unicornafl.UcAflError as ex:
        # This hook triggers more than once in this example.
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
    ql.hitcount += 1
    # mem(type_len_addr):
    print('visualizer_afl:')
    print(f'HitCount: {ql.hitcount}<br>')
    print(VisualizeHelper.cpustate(ql))
    print('VISEND')
    sys.stdout.flush()


def ql_hook(ql):

    ql.hitcount = 0

    # Bitmap generator
    if ql.trace:
        ql.hook_block(ql_bitmap)

    # hook entry point to start AFL
    if not ql.noafl:
        ql.hook_address(start_afl, ql.fuzz_start)

    # hook for visualizer
    if ql.vishook is not None:
        ql.hook_address(visualizer_hook, ql.vishook)

    def touchfile(ql):
        filename = ql.mem.string(ql.reg.a0)
        if filename in  ['/proc']:
            return
        filename = './WF2419_rootfs/' + filename
        if not os.path.isfile(filename):
            with open(filename, 'w') as f:
                f.write('AAAA')
                pass
    # ql.hook_address(touchfile, 0x77514000)


# sandbox to emulate the EXE
def my_sandbox(path, rootfs, input_file, trace=False, noafl=False,
               debug_level=1, hook=None, context=[], relation=False):
    path += ['cur']
    ql_arg = {'verbose': debug_level}
    # setup Qiling engine
    if debug_level <= 1:
        ql_arg['console'] = False
    if debug_level > 1:
        ql_arg['output'] = 'debug'
    ql = Qiling(path, rootfs, **ql_arg)
    if debug_level >= 5:
        ql.hook_block(ql_hook_block_disasm)
    ql.trace = trace
    ql.relation = relation
    ql.noafl = noafl
    ql.vishook = hook
    ql.uid = 'uid'

    ql.input_file = input_file

    ql.viscontext = context

    # assign fuzz scope
    ql.fuzz_start = ql.os.elf_entry
    ql.fuzz_end = [ql.os.exit_point]

    # do hook stuff
    ql_hook(ql)

    # find AFL input buffer
    #addr = ql.mem.search('MYINPUT'.encode())
    #ql.target_addr = addr[0]
    #ql.mem.map(0x7ff3d000, 0x1000, info=['stack padding'])
    #addr = ql.mem.search('WF2419'.encode())
    #ql.mem.write(addr[0], b'netcore_get.cgi\x00')

    # optional for libpthread
    ql.multithread = True
    ql.run()
    os._exit(0)


if __name__ == "__main__":
    # ./ql.py input [debug level] [trace/relation] [hook address] [reg/mem...]
    if len(sys.argv) <= 1:
        raise ValueError("No input file provided.")
    else:
        arg = {}
        if len(sys.argv) > 2:
            arg['debug_level'] = int(sys.argv[2])
        if len(sys.argv) > 3:
            arg['trace'] = 'trace' in sys.argv[3]
            arg['relation'] = 'relation' in sys.argv[3]
            arg['noafl'] = 'noafl' in sys.argv[3]
        if len(sys.argv) > 4:
            arg['hook'] = int(sys.argv[4], 0)
        if len(sys.argv) > 5:
            arg['context'] = sys.argv[5:]
        my_sandbox(["./rootfs/bin/exif"],
                   "./rootfs", sys.argv[1], **arg)
