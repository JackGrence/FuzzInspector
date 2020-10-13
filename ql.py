import sys
import os
import unicornafl

# Make sure Qiling uses our patched unicorn instead of it's own, second so without instrumentation!
unicornafl.monkeypatch()
from qiling import *

def my_syscall(a, b, c, d, e, f, g):
    pass

def ignore_fork_check(ql):
    print('hihihih')
    print(ql.reg.read('R3'))
    print(ql.reg.read('LR'))
    ql.reg.write('R3', 0)



def debug_main(ql):
    fp = ql.reg.read('r11')
    print(hex(fp))
    value = ql.unpack32(ql.mem.read(fp - 0x18, 4))
    print(hex(value))
    env = ql.unpack32(ql.mem.read(0x7775a000 + 0x00116bf8, 4))
    print(hex(env))
    env = ql.unpack32(ql.mem.read(0x7775a000 + 0x00115130, 4))
    print(hex(env))
    env = ql.unpack32(ql.mem.read(env, 4))
    print(hex(env))
    input()

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
    else:
        ql = Qiling(path, rootfs, output='debug', env=env, verbose=5)

    def ql_hook_block_disasm(ql, address, size):
        ql.nprint("\n[+] tracing basic block at 0x%x" % (address))

    # now emulate the EXE
    def place_input_callback(uc, input, _, data):
        env_var = ("SCRIPT_NAME=/dniapi/").encode()
        env_vars = env_var + input + b"\x00" + (ql.path).encode() + b"\x00"
        ql.mem.write(ql.target_addr, env_vars)


    def start_afl(_ql: Qiling):

        """
        Callback from inside
        """
        # We start our AFL forkserver or run once if AFL is not available.
        # This will only return after the fuzzing stopped.
        try:
            print("Starting afl_fuzz().")
            if not _ql.uc.afl_fuzz(input_file=input_file,
                        place_input_callback=place_input_callback,
                        exits=[ql.os.exit_point]):
                print("Ran once without AFL attached.")
                os._exit(0)  # that's a looot faster than tidying up.
        except unicornafl.UcAflError as ex:
            # This hook trigers more than once in this example.
            # If this is the exception cause, we don't care.
            # TODO: Chose a better hook position :)
            if ex != unicornafl.UC_AFL_RET_CALLED_TWICE:
                raise

    addr = ql.mem.search("SCRIPT_NAME=/dniapi/".encode())
    ql.target_addr = addr[0]

    main_addr = ql.os.elf_entry
    ql.hook_address(callback=start_afl, address=main_addr)

    def web_sessions_length(ql):
        size = os.stat('./rootfs/tmp/web_sessions').st_size
        ql.reg.r3 += 0x2800 - size

    ql.hook_address(web_sessions_length, 0x13694)

    ql.multithread = True
    try:
        ql.run()
        os._exit(0)
    except:
        if enable_trace:
            print("\nFuzzer Went Shit")
        os.abort()
        os._exit(0)

if __name__ == "__main__":
    if len(sys.argv) <= 1:
        raise ValueError("No input file provided.")
    else:
        my_sandbox(["./rootfs/usr/sbin/admin.cgi"], "./rootfs", sys.argv[1], len(sys.argv))
