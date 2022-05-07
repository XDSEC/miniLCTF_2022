flag = b'miniLctf{0ooo00oh!h3ll0_WASM_h4ck3r!}'
flag += b'\x00' * (8 - (len(flag) % 8))

print(flag)
print(len(flag))

def ROL(a, b):
    return ((a<<b) | (a>>(8-b))) & 0xff

def QUAROU(s, a, b, c, d):
    s[b] ^= ROL((s[a] + s[d]) & 0xff, 4)
    s[d] ^= ROL((s[c] + s[b]) & 0xff, 2)
    s[c] ^= ROL((s[b] + s[a]) & 0xff, 3)
    s[a] ^= ROL((s[d] + s[c]) & 0xff, 1)

enc = ""
context = [
    ord('D'), ord('3'), ord('3'), ord('.'),
    ord('B'), ord('4'), ord('T'), ord('0'),
    0, 0, 0, 0,
    0, 0, 0, 0
]
for j in range(0, len(flag), 8):
    block = flag[j : j + 8]
    for i in range(8):
        context[8 + i] = block[i]

    for rnd in range(42): # chacha20
        QUAROU(context, 12, 8, 4, 0)
        QUAROU(context, 13, 9, 5, 1)
        QUAROU(context, 14, 10, 6, 2)
        QUAROU(context, 15, 11, 7, 3)
        QUAROU(context, 15, 10, 5, 0)
        QUAROU(context, 12, 11, 6, 1)
        QUAROU(context, 13, 8, 7, 2)
        QUAROU(context, 14, 9, 4, 3)

    enc += ''.join(map(lambda x: f'{x:02x}', context))

print(enc)
print(len(enc))