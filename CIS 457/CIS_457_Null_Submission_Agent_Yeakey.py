# Wirehark Filter: tcp.port == 9000
# Anderson Yeakey

from socket import socket, AF_INET, SOCK_STREAM, SOL_SOCKET, SO_REUSEADDR
from threading import Thread
import re

def main():
    # Create a TCP socket that listens to port 9000 on the local host
    welcomeSocket = socket(AF_INET, SOCK_STREAM)
    welcomeSocket.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
    welcomeSocket.bind(("", 9000))
    welcomeSocket.listen(4)    # Max backlog 4 connections

    print ('Server is listening on port 9000')

    threads = []
    while (True):
        connectionSocket, addr = welcomeSocket.accept()
        print ("Accept a new connection", addr)
        t = Thread(target = manageConnection, args=(connectionSocket, addr))
        t.start()
        threads.append(t)

    welcomeSocket.close()
    for t in threads:
        t.join()
    print("End of server")

def manageConnection(connectionSocket, addr):
    # Read AT MOST 1024 bytes from the socket
    # decode(): converts bytes to text
    # encode(): convert text to bytes

    receivers = 0
    receivingData = False
    messageSize = 0

    # Initial connection
    connectionSocket.sendall("220 127.0.0.1\r\n".encode())

    while (connectionSocket._closed != True):
        text = connectionSocket.recv(1024).decode()

        if (text.split(' ', 1)[0] == "EHLO"):
            connectionSocket.sendall("502 OK\r\n".encode()) # Handle EHLO

        elif (text.split(' ', 1)[0] == "HELO"):
            connectionSocket.sendall("250 OK\r\n".encode()) # Handle HELO

        elif (re.search(':', text) and text.split(':', 1)[0] == "MAIL FROM"):
            connectionSocket.sendall("250 OK\r\n".encode()) # Handle MAIL FROM

        elif (re.match(r"RCPT TO:<\S+@\w+\.(com|org|net|edu|io|app)>\r\n", text)):
            if (receivers < 5):
                connectionSocket.sendall("250 OK\r\n".encode()) # Handle RCPT TO
                receivers += 1
            else:
                connectionSocket.sendall("550 Requested action not taken: too many recipients\r\n".encode()) # Reject >5 recipients
        elif (re.match(r"RCPT TO:(?!<\S+@\w+\.(com|org|net|edu|io|app)>)\r\n", text)):
            connectionSocket.sendall("550 Requested action not taken: mailbox unavailable\r\n".encode()) # Reject misformatted recipients

        elif (receivingData == False and text == "DATA\r\n"):
            receivingData = True
            connectionSocket.sendall("354 OK\r\n".encode()) # Handle DATA

        elif (receivingData == True and re.match(r"(.|\n)*Message-ID:(.|\n)*", text)):
            if (re.match(r"(.|\n)Subject:(.|\n)*\r\n\r\n(.|\n)*\r\n\r\n", text)):
                connectionSocket.sendall("451 Requested action aborted: empty subject header\r\n".encode()) # Reject empty subjects
            else:
                messageSize += len(text.encode())
                print(text) # "Save" email body
        elif (receivingData == True and text == ".\r\n"):
            receivingData = False
            connectionSocket.sendall("250 OK\r\n".encode()) # Handle . (end of email body)

        elif (text == "QUIT\r\n"):
            connectionSocket.sendall("221 OK\r\n".encode()) # Handle QUIT
            connectionSocket.close()

        elif (text == ""):
            connectionSocket.close() # Handle abrupt end-of-transmissions

        elif (receivingData and messageSize >= 1024):
            connectionSocket.sendall("451 Requested action aborted: message too large\r\n".encode()) # Handle message too large
            connectionSocket.close()

        elif (not receivingData):
            connectionSocket.sendall("500 Syntax error, command unrecognized\r\n".encode()) # Handle unknown transmissions
            connectionSocket.close()

if __name__ == "__main__":
    main()
