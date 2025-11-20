from threading import Thread
from socket import socket, AF_INET, SOCK_STREAM, SOL_SOCKET, SO_REUSEADDR

global connection_list
connection_list = []

def handleClient(socket, addr):
    # Handle communication with one client
    while (socket._closed != True):
        try:
            # Receive message from thread's client
            text = socket.recv(1024).decode()
            # Send message back to all clients
            for connection in connection_list:
                if (connection != socket):
                    connection.sendall(text.encode())
        except:
            # Remove client and close connection
            connection_list.remove(socket)
            socket.close()

def main():
    try:
        server_socket = socket(AF_INET, SOCK_STREAM)
        server_socket.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
        server_socket.bind(("", 5123))
        server_socket.listen(10)

        while True:#some_condition_to_check_here:
            connection_socket, addr = server_socket.accept()
            t = Thread(target = handleClient, args=(connection_socket, addr))
            # Add client connection and start thread
            connection_list.append(connection_socket)
            t.start()
    finally:
        for connection in connection_list:
            connection.sendall("<SERVER 5123> CLOSE PROGRAM".encode())
            server_socket.close()

if __name__ == "__main__":
    main()
