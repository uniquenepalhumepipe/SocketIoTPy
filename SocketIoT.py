import socket
import struct
import ssl
import time


MSG_LOGIN = 1
MSG_WRITE = 2
MSG_READ = 3
MSG_PING = 4

SOCKET_IOT_MAX_TIMEOUT = 5

def time_ms():
    return int(time.time() * 1000)


class SocketIoTException(Exception):
    pass


class SocketIoT:
    CONNECTING = 0
    CONNECTED = 1
    DISCONNECTED = 2


    last_recv = 0
    last_ping = 0
    last_send = 0


    def __init__(self, token, host, port, timeout=0.05, use_ssl=True, heartbeat = 10000):
        self.token = token
        self.host = host
        self.port = port
        self.timeout = timeout
        self.use_ssl = use_ssl
        self.state = SocketIoT.DISCONNECTED
        self.heartbeat = heartbeat


    def send(self, buf):
        self.last_send = time_ms()
        self.socket.send(buf)

    def create_msg(self, msg_type, *args):
        msg = "\0".join([str(i) for i in args]).encode("utf-8")
        return struct.pack("!HH", len(msg), msg_type) + msg

    def recvmsg(self, bytes, timeout):
        dbuff = b''
        try:
            self.socket.settimeout(timeout)
            dbuff += self.socket.recv(bytes)
            return dbuff
        except Exception as e:
            if 'timed out' in str(e):
                return b''
            raise

    def parse_msg(self, msglen):
        return self.recvmsg(msglen, self.timeout).decode("utf-8").split("\0")

    def authenticate(self):
        self.send(self.create_msg(MSG_LOGIN, self.token))
        msg_len, _ = struct.unpack("!HH", self.recvmsg(4, SOCKET_IOT_MAX_TIMEOUT))
        msg = self.recvmsg(msg_len, SOCKET_IOT_MAX_TIMEOUT).decode("utf-8").split("\0")
        self.last_recv = time_ms()
        if msg[0] == "1":
            self.state = SocketIoT.CONNECTED
            print("Connected")
        else:
            raise SocketIoTException("Authentication failed")

    def connect(self):
        try:
            self.state = SocketIoT.CONNECTING
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.connect(socket.getaddrinfo(self.host, self.port)[0][-1])
            if self.use_ssl:
                self.ssl_context = ssl.create_default_context()
                self.socket = self.ssl_context.wrap_socket(self.socket, server_hostname=self.host)
            self.state = SocketIoT.CONNECTING
            self.authenticate()
        except(SocketIoTException) as e:
            raise e
        except(Exception):
            pass

    def disconnect(self):
        self.socket.close()
        self.state = SocketIoT.DISCONNECTED
        print("Disconnected")

    def checkserver(self):
        now = time_ms()
        d_last_recv = now - self.last_recv
        d_last_ping = now - self.last_ping
        d_last_send = now - self.last_send

        if (d_last_recv > self.heartbeat + self.heartbeat // 2):
            return False

        if (d_last_ping > self.heartbeat and (d_last_recv > self.heartbeat or d_last_send > self.heartbeat)):
            self.send(self.create_msg(MSG_PING))
            self.last_ping = time_ms()
            print("Ping")
        return True

        
    def run(self):
        if(self.state == self.CONNECTED):
            header = self.recvmsg(4, self.timeout)
            if header:
                msg_len, msg_type = struct.unpack("!HH", header)
                msg = self.parse_msg(msg_len)
                if msg:
                    self.last_recv = time_ms()
                    print("Got Message", msg_type)
            if not self.checkserver():
                self.disconnect()
        else:
            self.connect()
        
