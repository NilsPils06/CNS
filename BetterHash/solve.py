def rol(x, n):
    return ((x << n) | (x >> (8 - n))) & 0xff

def ror(x, n):
    return ((x >> n) | (x << (8 - n))) & 0xff

def better_hash(msg):
    state = bytearray(msg.encode())

    for rnd in range(8):

        for i in range(len(state)):
            state[i] ^= (rnd * 41 + i * 17) & 0xff
            state[i] = rol(state[i], (rnd + i) & 7)

        for i in range(1, len(state)):
            state[i] ^= state[i - 1]

        state = state[1:] + state[:1]

    return state.hex()

def decode(hash):
    state = bytearray.fromhex(hash)
    for rnd in reversed(range(8)):
        state = state[-1:] + state[:-1]
        for i in reversed(range(1, len(state))):
            state[i] ^= state[i-1]

        for i in range(len(state)):
            state[i] = ror(state[i], (rnd + i) & 7)
            state[i] ^= (rnd * 41 + i * 17) & 0xff

    return state.decode()

FLAG = ''
hash = "5f070b54361613bca31a123e95321cff154ba64f549bb34fdc7688f10efb569aed4ccbd6ba"

print(decode(hash))
