import socket

HOST = "10.0.0.1"  # Standard loopback interface address (localhost)
PORT = 65432  # Port to listen on (non-privileged ports are > 1023)

# Create a socket object for the server using IPv4 and TCP
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    # Bind the socket to the host and port
    s.bind((HOST, PORT))  # This associates the socket with the specified host and port
    s.listen()  # Start listening for incoming connections

    # Accept an incoming connection and create a new socket for communication
    conn, addr = s.accept()  # Accept a connection and get the client's address
    with conn:
        print(f"Connected by {addr}")  # Print a message when a client is connected

        # Enter a loop to receive and send data
        while True:
            data = conn.recv(1024)  # Receive data from the client, up to 1024 bytes at a time
            if not data:
                break  # Exit the loop if no more data is received

            conn.sendall(data)  # Send the received data back to the client

