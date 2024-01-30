import socket

HOST = "10.0.0.1"  # The server's hostname or IP address
PORT = 65432  # The port used by the server

# Create a socket using IPv4 (AF_INET) and TCP (SOCK_STREAM)
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.connect((HOST, PORT)) # connecting port and host
    s.sendall(b"Hello, world") # sending a hello world message
    data = s.recv(1024) # receiving up to 1024 byte of data 

print(f"Received {data!r}") # print the recieved message
