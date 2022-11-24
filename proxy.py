import select
import socket
import threading

# import socketserver
# from time import sleep
# from uuid import uuid4


# Codes 


SOCKS_VERSION = 5





class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

print("\n\n#########################################")
print(socket.gethostbyname(socket.gethostname()))
print("#########################################\n\n")


class ProxyServer():


    username = "TEST"
    password = "TEST"


    def __init__(self, host: str, port: int, **kwargs) -> None:
        self.host = host
        self.port = port
        self.address = (host, port)
        self.clients = {}
        self.threads = {}
        for key, value in kwargs.items():
            setattr(self, key, value)
    

    def run(self):
        with socket.create_server(("", self.port)) as sock:
        # with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            # sock.bind(self.address)
            print(f"{bcolors.OKCYAN}[STARTING]{bcolors.ENDC} Starting server at all interfaces on port", self.port)
            # print(f"{bcolors.OKCYAN}[STARTING]{bcolors.ENDC} Starting server at", self.host, self.port)
            sock.listen()
            while True:
                connection, address = sock.accept()
                thread = threading.Thread(target=self.handle_client, kwargs={"connection":connection, "address":address})
                print(f"{bcolors.OKBLUE}[NEW CONNECTION]{bcolors.ENDC} Got new connection request at", address)
                thread.start()
                self.clients.update({address:connection})
                self.threads.update({address:thread})
            

    def handle_client(self, connection, address):
        version , nmethods = connection.recv(2)
        methods = self.get_available_methods(nmethods, connection) 

        if 2 not in set(methods):
            connection.close()
            # print(f"{bcolors.WARNING}[CLOSE CONNECTION]{bcolors.ENDC} Connection close at", address, "at 2 not in set methods")

            return
        
        # Send welcome message
        connection.sendall(bytes([SOCKS_VERSION, 2]))
        
        
        if not self.verify_credentials(connection, address):
            return
        
        version, cmd, _, address_type = connection.recv(4)

        if address_type == 1:
            address = socket.inet_ntoa(connection.recv(4))
        elif address_type == 3:
            domin_length = connection.recv(1)[0]
            address = connection.recv(domin_length)
            address = socket.gethostbyname(address)
        

        port = int.from_bytes(connection.recv(2), 'big', signed=False)
        try:
            if cmd == 1:
                remote = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                remote.connect((address, port))
                bind_address = remote.getsockname()
                # print(f"{bcolors.OKBLUE}*{bcolors.ENDC} Connected to {address} {port}")
            else:
                connection.close()
                # print(f"{bcolors.WARNING}[CLOSE CONNECTION]{bcolors.ENDC} Connection close at", address, "at handle client cmd == 1")
            
            addr = int.from_bytes(socket.inet_aton(bind_address[0]), 'big', signed=False)
            port = bind_address[1]
            reply = b''.join([
                SOCKS_VERSION.to_bytes(1, 'big'),
                int(0).to_bytes(1, 'big'),
                int(0).to_bytes(1, 'big'),
                int(1).to_bytes(1, 'big'),
                addr.to_bytes(4, 'big'),
                port.to_bytes(4, 'big'),
            ])


        except Exception as e:
            reply = self.generate_failed_reply(address_type, 5)
        

        connection.sendall(reply)

        if reply[1] == 0 and cmd == 1:
            self.exchange_loop(connection, remote)

        
        connection.close()
        # print(f"{bcolors.WARNING}[CLOSE CONNECTION]{bcolors.ENDC} Connection close at", address, "at handle client after exchange loop")



    def exchange_loop(self, client, remote):
        while True: 
            r, w, e = select.select([client, remote], [], [])
            try:
                if client in r:
                    data = client.recv(4096)
                    if remote.send(data) <= 0:
                        break
                
                if remote in r:
                    data = remote.recv(4096)
                    if client.send(data) <= 0:
                        break
            except ConnectionResetError:
                # print(f"{bcolors.WARNING}[CONNECTION RESET]{bcolors.ENDC}Connection reseted.")
                pass
            


    def generate_failed_reply(self, address_type, error_number):
        return b''.join([
            SOCKS_VERSION.to_bytes(1, 'big'),
            error_number.to_bytes(1, 'big'),
            int(0).to_bytes(1, 'big'),
            address_type.to_bytes(1, 'big'),
            int(0).to_bytes(0, 'big'),
            int(0).to_bytes(0, 'big'),
        ])


    def verify_credentials(self, connection, address):
        version = ord(connection.recv(1))

        username_len = ord(connection.recv(1))
        username = connection.recv(username_len).decode('utf-8')
        
        password_len = ord(connection.recv(1))
        password = connection.recv(password_len).decode('utf-8')


        if username == self.username and password == self.password:
            response = bytes([version, 0])
            connection.sendall(response)
            print(f"{bcolors.OKGREEN}[AUTHENTICATION]{bcolors.ENDC} Authentication successfull for", address)
            return True
        

        response = bytes([version, 0xFF])
        connection.sendall(response)
        connection.close()
        # print(f"{bcolors.WARNING}[CONNECTION]{bcolors.ENDC} Refuse connection request at", address, "credentians not valid")
        return False




    def get_available_methods(self, nmethods, connection):
        methods = []
        for i in range(nmethods):
            methods.append(ord(connection.recv(1)))
        return methods



if __name__ == "__main__":
    server = ProxyServer(host="127.0.0.1", port=80)
    server.run()