# checksum calculator
def checksum(data) -> int:
    if len(data) % 2 != 0:
        data += b'\0'

    s = 0
    for i in range(0, len(data), 2):
        s += ord(data[i:i+1]) + (ord(data[i+1:i+2]) << 8)

    s = (s >> 16) + (s & 0xffff)
    s = s + (s >> 16)
    return ~s & 0xffff