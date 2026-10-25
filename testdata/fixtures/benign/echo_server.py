import socket

server = socket.socket()
server.bind(("127.0.0.1", 9000))
server.listen(1)
conn, addr = server.accept()
data = conn.recv(1024)
conn.sendall(data)
