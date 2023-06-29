import select
import socket
import threading
import logging
import ssl
import argparse


# Set up logging configuration
logging.basicConfig(
    filename="proxy.log",
    level=logging.ERROR,
    format='[%(levelname)s] %(message)s',
)

# Create logger object
logger = logging.getLogger()

context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)


# Codes


SOCKS_VERSION = 5


class ProxyServer():
    """Proxy server Object
        It can be used via Django
    """

    def __init__(self, host: str, port: int, **kwargs) -> None:
        self.host = host
        self.port = port
        logging.debug(f"[INIT] {self.host} : {self.port}")
        for key, value in kwargs.items():
            setattr(self, key, value)
            logging.debug(f"[INIT] {key} : {value}")

    def run(self):
        """
        Run the server for ever and accept
        connection if goteds a conncetion
        """
        with socket.create_server(("", self.port), family=socket.AF_INET6, dualstack_ipv6=True) as sock:
            logging.info(
                f"[STARTING] Starting server at all interfaces on port {self.port}")
            sock.listen()
            logging.info(f"[LISTENING] LISTENING for connection")
            while True:
                connection, address = sock.accept()
                thread = threading.Thread(target=self.handle_client, kwargs={
                                          "connection": connection, "address": address})
                logging.debug(
                    f"[NEW CONNECTION] Got new connection request at {address}")
                thread.start()
                logging.debug(f"[START THREAD] Thread for connecton started.")

    def handle_client(self, connection, address):
        """Handle first Client connection
        """
        version, nmethods = connection.recv(2)
        methods = self.get_available_methods(nmethods, connection)

        if 2 not in set(methods):
            connection.close()
            logging.warning(
                f"[CLOSE CONNECTION] Connection close at {address} at 2 not in set methods")
            return

        # Send welcome message
        connection.sendall(bytes([SOCKS_VERSION, 2]))

        if not self.verify_credentials(connection, address):
            return False

        version, cmd, rsv, address_type = connection.recv(4)
        if address_type == 1:
            address = socket.inet_ntoa(connection.recv(4))
        elif address_type == 3:
            domin_length = connection.recv(1)[0]
            address = connection.recv(domin_length)
            address = socket.gethostbyname(address)
        elif address_type == 4:
            address = socket.inet_ntop(socket.AF_INET6, connection.recv(16))

        port = int.from_bytes(connection.recv(2), 'big', signed=False)
        try:
            if cmd == 1:
                remote = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                remote.connect((address, port))
                # SSL support
                try:
                    if port == 443:
                        remote = context.wrap_socket(
                            remote, server_hostname=address, server_side=True,
                            do_handshake_on_connect=True,
                            suppress_ragged_eofs=True)
                except ValueError as error:
                    if port == 443:
                        remote = context.wrap_socket(
                            remote, server_hostname=address,
                            do_handshake_on_connect=True,
                            suppress_ragged_eofs=True)
                except Exception as error:
                    print(type(error).__name__)
                    logging.error(f"[Exception Error] {error}, {address}")

                bind_address = remote.getsockname()
                logging.info(f"* Connected to {address} {port}")
            else:
                connection.close()
                logging.warning(
                    f"[CLOSE CONNECTION] Connection close at {address} at handle client cmd == 1")

            addr = int.from_bytes(socket.inet_aton(
                bind_address[0]), 'big', signed=False)
            port = bind_address[1]
            reply = b''.join([
                SOCKS_VERSION.to_bytes(1, 'big'),
                int(0).to_bytes(1, 'big'),
                int(0).to_bytes(1, 'big'),
                int(1).to_bytes(1, 'big'),
                addr.to_bytes(4, 'big'),
                port.to_bytes(4, 'big'),
            ])

        except Exception as error:
            logging.critical(
                f"[Exception] Connection close unexpectedly, {str(error)}")
            reply = self.generate_failed_reply(address_type, 5)

        connection.sendall(reply)

        if reply[1] == 0 and cmd == 1:
            self.exchange_loop(connection, remote)
        connection.close()
        logging.warning(
            f"[CLOSE CONNECTION] Connection closed at {address} at handle client after exchange loop")

    def exchange_loop(self, client, remote):
        """Exchange data between client and destenation server
        """
        while True:
            r, w, e = select.select([client, remote], [], [])
            try:
                if client in r:
                    data = client.recv(8192)
                    if remote.send(data) <= 0:
                        break

                if remote in r:
                    data = remote.recv(8192)
                    if client.send(data) <= 0:
                        break
            except ConnectionResetError as error:
                logging.error(
                    f"[CONNECTION RESET] {error}")

    def generate_failed_reply(self, address_type, error_number):
        """Generate Failed Reply for client   
        """
        return b''.join([
            SOCKS_VERSION.to_bytes(1, 'big'),
            error_number.to_bytes(1, 'big'),
            int(0).to_bytes(1, 'big'),
            address_type.to_bytes(1, 'big'),
            int(0).to_bytes(0, 'big'),
            int(0).to_bytes(0, 'big'),
        ])

    def verify_credentials(self, connection, address):
        """Authentication

        Args:
            connection (socker_conncetion): Socket conection of client
            address (IP address): Ip address of client

        Returns:
            Bool: User is authenticated or not
        """
        version = ord(connection.recv(1))

        username_len = ord(connection.recv(1))
        username = connection.recv(username_len).decode('utf-8')

        password_len = ord(connection.recv(1))
        password = connection.recv(password_len).decode('utf-8')

        if username == self.username and password == self.password:
            response = bytes([version, 0])
            connection.sendall(response)
            logging.info(
                f"[AUTHENTICATION] Authentication successfull for {address}")
            return True

        response = bytes([version, 0xFF])
        connection.sendall(response)
        connection.close()
        logging.warning(
            f"[CONNECTION] Refuse connection request at {address} credentians is not valid")
        return False

    def get_available_methods(self, nmethods, connection):
        """Get Available Methods for current conncetion

        Returns:
            list: list of available methods
        """
        methods = []
        for i in range(nmethods):
            methods.append(ord(connection.recv(1)))
        return methods


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", "-ho", default="::",
                        help="IPv4/IPv6 of proxy to run over it")
    parser.add_argument("--port", "-po", default=9090,
                        help="Port of Socks5 that you want to run default is 9090")
    parser.add_argument("--username", "-u", default="TEST",
                        help="Username for authentication default is TEST")
    parser.add_argument("--password", "-p", default="TEST",
                        help="Password for authentication default is TEST")

    args = parser.parse_args()
    server = ProxyServer(host=args.host, port=args.port,
                         username=args.username, password=args.password)
    server.run()
