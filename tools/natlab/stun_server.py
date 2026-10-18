import socket, struct, sys, threading
MAGIC = 0x2112A442
def serve(ip):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind((ip, 3478))
    while True:
        data, (fip, fport) = s.recvfrom(2048)
        if len(data) < 20 or data[0:2] != b'\x00\x01':
            continue
        tx = data[8:20]
        xport = fport ^ (MAGIC >> 16)
        xip = struct.unpack('>I', socket.inet_aton(fip))[0] ^ MAGIC
        attr = struct.pack('>HHBBHI', 0x0020, 8, 0, 1, xport, xip)
        resp = struct.pack('>HHI', 0x0101, len(attr), MAGIC) + tx + attr
        s.sendto(resp, (fip, fport))
for ip in sys.argv[1:]:
    threading.Thread(target=serve, args=(ip,), daemon=True).start()
threading.Event().wait()
