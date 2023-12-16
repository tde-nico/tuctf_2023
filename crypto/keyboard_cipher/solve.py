from Crypto.Util.number import long_to_bytes
import base64

enc = 0x636a56355279424b615464354946686b566942794e586c4849455279523359674d47394d49486845643045675a316b315569426163304d675a316c715469426163314567616b6c7354534268563252594947745063434178643045675332395149466c6e536d343d
step1 = long_to_bytes(enc) # hex
step2 = base64.b64decode(step1) # base64 # cjV5RyBKaTd5IFhkViByNXlHIERyR3YgMG9MIHhEd0EgZ1k1UiBac0MgZ1lqTiBac1EgaklsTSBhV2RYIGtPcCAxd0EgS29QIFlnSm4=
print(step2) # key-strokes surrounding the actual key: r5yG Ji7y XdV r5yG DrGv 0oL xDwA gY5R ZsC gYjN ZsQ jIlM aWdX kOp 1wA KoP YgJn

# tuctf{pstxhakslqlh}
