from pwn import *

data = open('table_encryption.xml.enc', 'rb').read()
known = b'<?xml version="1'
key = xor(known, data[:len(known)])
open('dec.xml', 'wb').write(xor(data, key))

# TUCTF{x0r_t4bl3s_R_fun!!!11!}
