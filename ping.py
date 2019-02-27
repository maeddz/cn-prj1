import select
import struct
import sys
import time
import socket
import random
import base64
import six
import string
from impacket import ImpactPacket
import commands

if len(sys.argv) < 2:
    print "add number of hosts as argv 1"
    exit()

RETURN_HOME_MESSAGE = "@RETURN_HOME@"
CHUNK_SIZE = 64
ICMP_ECHOREPLY = 0  # Echo reply (per RFC792)
ICMP_ECHO = 8  # Echo request (per RFC792)
ICMP_MAX_RECV = 2048  # Max size of incoming buffer


class SentFile(object):
    def __init__(self, filename, num_of_chunks, encryption_key):
        self.filename = filename
        self.num_of_chunks = num_of_chunks
        self.encryption_key = encryption_key
        self.chunks_received = []
        self.return_wanted = False

    def received_all(self):
        return len(self.chunks_received) == self.num_of_chunks

    @classmethod
    def get_key(cls, item):
        return item[1]

    def save(self):
        filename = "RECEIVED_" + self.filename
        f = open(filename, "w+")
        received_data = ""
        for chunk in sorted(self.chunks_received, key=self.get_key):
            received_data += '\n'.join(chunk[0].split('\n')[1:])  # ignore file name
        f.write(Ping.decrypt(received_data, self.encryption_key))
        f.close()


class ReturnRequest(object):
    def __init__(self, filename, ip):
        self.filename = filename
        self.ip = ip
        self.completely_returned = False


class PayloadMessage(object):
    @staticmethod
    def is_return_message(payload_message):
        return RETURN_HOME_MESSAGE in payload_message

    @staticmethod
    def get_return_message_data(payload_message):
        return payload_message.split('\n')[1:]

    @staticmethod
    def get_filename(payload_message):
        if PayloadMessage.is_return_message(payload_message):
            return payload_message.split()[2]
        else:
            return payload_message.split()[0]


class Ping(object):
    def __init__(self):
        self.return_list = []
        self.send_list = []
        self.num_of_hosts = int(sys.argv[1])
        self.source = None
        self.destination = None
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        self.socket.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        self.ip = commands.getoutput("/sbin/ifconfig").split("\n")[1].split()[1][5:]

    @staticmethod
    def header2dict(names, struct_format, data):
        unpacked_data = struct.unpack(struct_format, data)
        return dict(zip(names, unpacked_data))

    @staticmethod
    def add_ip_prefix(number):
        return "10.0.0.{0}".format(number)

    def generate_two_random_ips(self):
        h1 = self.ip
        while h1 == self.ip:
            h1 = Ping.add_ip_prefix(random.randint(1, self.num_of_hosts))
        h2 = self.ip
        while h2 == self.ip or h2 == h1:
            h2 = Ping.add_ip_prefix(random.randint(1, self.num_of_hosts))
        return [h1, h2]

    def send_one_ping(self, current_socket, data, identifier):
        print "-Sending an ICMP ECHO_REQUEST packet from {0} to {1}".format(self.source, self.destination)
        src, dst = self.source, self.destination
        ip = ImpactPacket.IP()
        ip.set_ip_src(src)
        ip.set_ip_dst(dst)
        icmp = ImpactPacket.ICMP()
        icmp.set_icmp_type(icmp.ICMP_ECHO)
        icmp.contains(ImpactPacket.Data(data))
        ip.contains(icmp)
        icmp.set_icmp_id(identifier)
        icmp.set_icmp_cksum(0)
        icmp.auto_checksum = 1
        try:
            current_socket.sendto(ip.get_packet(), (dst, 1))
        except socket.error:
            current_socket.close()

    def get_owner_ip(self, filename):
        for item in self.return_list:
            if item.filename == filename:
                return item.ip
        return None

    def is_in_return_list(self, filename):
        for item in self.return_list:
            if item.filename == filename:
                return True
        return False

    def get_sent_file_data(self, filename):
        for item in self.send_list:
            if item.filename == filename:
                return item
        return None

    def is_in_send_list(self, filename):
        for item in self.send_list:
            if filename == item.filename:
                return item.return_wanted
        return False

    def create_return_message(self, filename):
        return RETURN_HOME_MESSAGE + "\n" + self.ip + "\n" + filename

    def remove_sent_file(self, sent_file):
        self.send_list.remove(sent_file)

    @staticmethod
    def split_len(seq, length):
        return [seq[i:i + length] for i in range(0, len(seq), length)]

    @staticmethod
    def encrypt(text, key):
        encoded_chars = []
        for i in range(len(text)):
            key_c = key[i % len(key)]
            encoded_c = chr(ord(text[i]) + ord(key_c) % 256)
            encoded_chars.append(encoded_c)
        encoded_string = ''.join(encoded_chars)
        encoded_string = encoded_string.encode('latin') if six.PY3 else encoded_string
        return base64.urlsafe_b64encode(encoded_string).rstrip(b'=')

    @staticmethod
    def decrypt(text, key):
        text = base64.urlsafe_b64decode(text + b'===')
        text = text.decode('latin') if six.PY3 else text
        encoded_chars = []
        for i in range(len(text)):
            key_c = key[i % len(key)]
            encoded_c = chr((ord(text[i]) - ord(key_c) + 256) % 256)
            encoded_chars.append(encoded_c)
        encoded_string = ''.join(encoded_chars)
        return encoded_string

    def get_chunks_from_file(self, filename, key):
        with open(filename, 'r') as f:
            content = self.encrypt(f.read(), key)
        return self.split_len(content, CHUNK_SIZE)

    @staticmethod
    def generate_random_key():
        return ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(5))

    def run(self):
        while True:
            input_ready, _, _ = select.select([self.socket, sys.stdin], [], [])
            for sender in input_ready:
                if sender == sys.stdin:
                    self.process_user_input()
                elif sender == self.socket:
                    self.process_socket_reply()
            time.sleep(0.3)

    def process_user_input(self):
        data = raw_input().split()
        if len(data) == 0:
            cmd = ""
        else:
            cmd = data[0]
        if cmd == 'send':
            filename = data[1]
            encryption_key = self.generate_random_key()
            chunks = self.get_chunks_from_file(filename, encryption_key)
            for i in range(len(chunks)):
                self.source, self.destination = self.generate_two_random_ips()
                data = filename + "\n" + chunks[i]
                self.send_one_ping(self.socket, data, i)
            self.send_list.append(SentFile(filename, len(chunks), encryption_key))
        elif cmd == 'return':
            filename = data[1]
            sent_file = self.get_sent_file_data(filename)
            if sent_file is None:
                print "-The file {0} isn't sent by you.".format(filename)
            else:
                sent_file.return_wanted = True
                self.source, self.destination = self.generate_two_random_ips()
                self.send_one_ping(self.socket, self.create_return_message(filename), 0xFFFF)
        elif cmd == 'exit':
            print "-Exiting..."
            time.sleep(0.5)
            exit()
        else:
            print "-Wrong command."

    def process_socket_reply(self):
        packet_data, _ = self.socket.recvfrom(ICMP_MAX_RECV)
        icmp_header = Ping.header2dict(
            names=[
                "type", "code", "checksum",
                "packet_id", "seq_number"
            ],
            struct_format="!BBHHH",
            data=packet_data[20:28]
        )
        ip_header = Ping.header2dict(
            names=[
                "version", "type", "length",
                "id", "flags", "ttl", "protocol",
                "checksum", "src_ip", "dest_ip"
            ],
            struct_format="!BBHHHBBHII",
            data=packet_data[:20]
        )
        if ip_header['ttl'] != 64:
            return

        received_data = packet_data[28:]
        ip = socket.inet_ntoa(struct.pack("!I", ip_header["src_ip"]))
        print "-Received an ICMP ECHO_REPLY packet from {0}".format(ip)

        if PayloadMessage.is_return_message(received_data):
            ip, filename = PayloadMessage.get_return_message_data(received_data)
            if self.is_in_send_list(filename) and self.get_sent_file_data(filename).received_all():
                return
            if not self.is_in_return_list(filename):
                self.return_list.append(ReturnRequest(filename, ip))
        else:
            filename = PayloadMessage.get_filename(received_data)
            if self.is_in_send_list(filename):
                print "-One part of file {0} returned home.".format(filename)
                sent_file = self.get_sent_file_data(filename)
                sent_file.chunks_received.append((received_data, icmp_header["packet_id"]))
                if sent_file.received_all():
                    print "-All parts of file {0} received!".format(filename)
                    sent_file.save()
                    self.remove_sent_file(sent_file)
                return
            elif self.is_in_return_list(filename):
                print "-Returning packet to owner. Owner ip is {0}".format(self.get_owner_ip(filename))
                self.destination = self.ip
                self.source = self.get_owner_ip(filename)
                self.send_one_ping(self.socket, received_data, icmp_header["packet_id"])
                return
        self.source, self.destination = self.generate_two_random_ips()
        self.send_one_ping(self.socket, received_data, icmp_header["packet_id"])


p = Ping()
p.run()
