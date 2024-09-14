import socket

def custom_hash(data):
    h = 5381
    for c in data.decode():
        h = (h * 33) + ord(c)
    return h & 0xffffffff

def handle_client(conn):
    data = conn.recv(1024)
    hsh = custom_hash(data)
    if data.decode().lower() == "exit":
        conn.close()
        return
    print(f"Received data: {data.decode()}")
    print(f"Computed hash: {hsh}")
    conn.sendall(data)
    conn.sendall(str(hsh).encode())
    conn.close()

def main():
    srv = socket.socket()
    srv.bind(('localhost', 11335))
    srv.listen(1)
    print('Server is listening...')
    while True:
        conn, _ = srv.accept()
        handle_client(conn)

if __name__ == "__main__":
    main()
