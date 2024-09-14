import socket


def custom_hash(data):
    h = 5381
    for c in data.decode():
        h = (h * 33) + ord(c)
    return h & 0xffffffff



def main():
    cli = socket.socket()
    cli.connect(('localhost', 11335))

    while True:
        msg = input("Enter message to send to the server (or type 'exit' to quit): ")
        if msg.lower() == 'exit':
            msg_bytes = msg.encode()
            cli.sendall(msg_bytes)
            cli.close()
            break

        msg_bytes = msg.encode()
        cli.sendall(msg_bytes)

        received_data = b''
        while len(received_data) < len(msg_bytes):
            part = cli.recv(len(msg_bytes) - len(received_data))
            if not part:
                break
            received_data += part

        received_hash = b''
        while True:
            part = cli.recv(1024)
            if not part:
                break
            received_hash += part
            if len(received_hash) >= 10:
                break

        received_hash = int(received_hash.decode())
        computed_hash = custom_hash(received_data)

        if received_data == msg_bytes and received_hash == computed_hash:
            print('Data integrity verified')
        else:
            print('Data integrity compromised')

    cli.close()


if __name__ == "__main__":
    main()

