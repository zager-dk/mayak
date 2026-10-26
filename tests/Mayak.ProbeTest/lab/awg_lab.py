"""Стенд для проверки AwgProbe: поднимает настоящий amneziawg-go (userspace) на TUN.

python3 awg_lab.py <amneziawg-go> <iface> <cidr-адрес> <файл UAPI>
Печатает READY, когда интерфейс настроен, и держит процесс, пока не закроют stdin.
"""
import fcntl
import os
import socket
import struct
import subprocess
import sys
import time

binary, iface, cidr, uapi_file = sys.argv[1:5]

# остатки прошлого запуска мешают поднять интерфейс заново
subprocess.run(["pkill", "-f", f"{binary} -f {iface}$"], check=False)
time.sleep(0.3)
try:
    os.remove(f"/var/run/amneziawg/{iface}.sock")
except FileNotFoundError:
    pass

proc = subprocess.Popen([binary, "-f", iface], stdout=open(f"/tmp/{iface}.log", "w"), stderr=subprocess.STDOUT,
                        env={**os.environ, "LOG_LEVEL": "verbose"})
sock_path = f"/var/run/amneziawg/{iface}.sock"
for _ in range(100):
    if os.path.exists(sock_path):
        break
    time.sleep(0.1)
else:
    print("NO SOCKET", flush=True)
    sys.exit(1)

# адрес и UP через ioctl (iproute2 на стенде нет)
SIOCSIFADDR, SIOCSIFNETMASK, SIOCGIFFLAGS, SIOCSIFFLAGS = 0x8916, 0x891C, 0x8913, 0x8914
addr, prefix = cidr.split("/")
mask = socket.inet_ntoa(struct.pack("!I", (0xFFFFFFFF << (32 - int(prefix))) & 0xFFFFFFFF))
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
ifn = iface.encode().ljust(16, b"\0")


def sockaddr(ip):
    return struct.pack("H2s4s8s", socket.AF_INET, b"\0\0", socket.inet_aton(ip), b"\0" * 8)


fcntl.ioctl(s, SIOCSIFADDR, ifn + sockaddr(addr))
fcntl.ioctl(s, SIOCSIFNETMASK, ifn + sockaddr(mask))
flags = struct.unpack("H", fcntl.ioctl(s, SIOCGIFFLAGS, ifn + b"\0" * 16)[16:18])[0]
fcntl.ioctl(s, SIOCSIFFLAGS, ifn + struct.pack("H", flags | 0x1) + b"\0" * 14)

u = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
u.connect(sock_path)
u.sendall(open(uapi_file).read().encode())
resp = b""
while not resp.endswith(b"\n\n"):
    chunk = u.recv(4096)
    if not chunk:
        break
    resp += chunk
u.close()
if b"errno=0" not in resp:
    print("UAPI ERROR " + resp.decode(), flush=True)
    proc.kill()
    sys.exit(1)

print("READY", flush=True)
try:
    sys.stdin.read()
finally:
    proc.kill()
    proc.wait(timeout=5)
