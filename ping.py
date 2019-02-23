import os
import select
import signal
import struct
import sys
import time
import socket
import random
from impacket import ImpactPacket
import commands

RETURN_HOME_MESSAGE = "@RETURN_HOME@"
FINISH_TRANSMISSION_MESSAGE = "@FINISH_TRANS@"
RETURNED_TO_OWNER_MESSAGE = "@RETURNED@"

if len(sys.argv) < 2:
    print "add number of hosts as argv 1"
    exit()

if sys.platform.startswith("win32"):
    default_timer = time.clock
else:
    default_timer = time.time

ICMP_ECHOREPLY = 0  # Echo reply (per RFC792)
ICMP_ECHO = 8  # Echo request (per RFC792)
ICMP_MAX_RECV = 2048  # Max size of incoming buffer

MAX_SLEEP = 1000


def is_valid_ip4_address(addr):
    parts = addr.split(".")
    if not len(parts) == 4:
        return False
    for part in parts:
        try:
            number = int(part)
        except ValueError:
            return False
        if number > 255 or number < 0:
            return False
    return True


def to_ip(addr):
    if is_valid_ip4_address(addr):
        return addr
    return socket.gethostbyname(addr)


class SentFile(object):
    def __init__(self, filename, num_of_chunks):
        self.filename = filename
        self.num_of_chunks = num_of_chunks
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
        for chunk in sorted(self.chunks_received, key=self.get_key):
            data = '\n'.join(chunk[0].split('\n')[1:])  # ignore file name
            print "Writing Data: {0}".format(data)
            f.write(data)
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
    def is_returned_to_owner_message(payload_message):
        return RETURNED_TO_OWNER_MESSAGE in payload_message

    @staticmethod
    def get_return_message_data(payload_message):
        return payload_message.split('\n')[1:]

    @staticmethod
    def get_filename(payload_message):
        if PayloadMessage.is_return_message(payload_message):
            return payload_message.split()[2]
        elif PayloadMessage.is_returned_to_owner_message(payload_message):
            return payload_message.split()[1]
        else:
            return payload_message.split()[0]

    @staticmethod
    def is_finish_transmission_message(payload_message):
        return FINISH_TRANSMISSION_MESSAGE in payload_message


class Ping(object):
    def __init__(self, timeout=1000, packet_size=55, own_id=None, quiet_output=False, udp=False, bind=None):
        self.return_list = []
        self.quiet_output = quiet_output
        self.num_of_hosts = int(sys.argv[1])
        self.source = None
        self.destination = None
        self.timeout = timeout
        self.packet_size = packet_size
        self.udp = udp
        self.bind = bind
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        self.socket.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        self.ip = commands.getoutput("/sbin/ifconfig").split("\n")[1].split()[1][5:]
        self.send_list = []
        if own_id is None:
            self.own_id = os.getpid() & 0xFFFF
        else:
            self.own_id = own_id

        self.seq_number = 0
        self.send_count = 0
        self.receive_count = 0
        self.min_time = 999999999
        self.max_time = 0.0
        self.total_time = 0.0

    # --------------------------------------------------------------------------

    def print_unknown_host(self, e):
        msg = "\nPYTHON-PING: Unknown host: %s (%s)\n" % (self.destination, e.args[1])
        print(msg)

        raise Exception, "unknown_host"

    def print_success(self, delay, ip, packet_size, ip_header, icmp_header, header=False):
        if ip == self.destination:
            from_info = ip
        else:
            from_info = "%s (%s)" % (self.destination, ip)

        msg = "%d bytes from %s: icmp_seq=%d ttl=%d time=%.1f ms" \
              % (packet_size, from_info, icmp_header["seq_number"], ip_header["ttl"], delay)

        print(msg)
        if header:
            print("IP header: %r" % ip_header)
            print("ICMP header: %r" % icmp_header)

    def print_failed(self):
        msg = "Request timed out."
        print(msg)

    def print_exit(self):
        msg = "\n----%s PYTHON PING Statistics----" % self.destination
        print(msg)

        lost_count = self.send_count - self.receive_count
        lost_rate = float(lost_count) / self.send_count * 100.0

        msg = "%d packets transmitted, %d packets received, %0.1f%% packet loss" % (
            self.send_count, self.receive_count, lost_rate)
        print(msg)

        if self.receive_count > 0:
            msg = "round-trip (ms)  min/avg/max = %0.3f/%0.3f/%0.3f" % (
                self.min_time, self.total_time / self.receive_count, self.max_time)
            print(msg)
        print('')

    # --------------------------------------------------------------------------

    def signal_handler(self, signum, frame):
        """
        Handle print_exit via signals
        """
        self.print_exit()
        msg = "\n(Terminated with signal %d)\n" % signum
        print(msg)

        sys.exit(0)

    def setup_signal_handler(self):
        signal.signal(signal.SIGINT, self.signal_handler)  # Handle Ctrl-C
        if hasattr(signal, "SIGBREAK"):
            signal.signal(signal.SIGBREAK, self.signal_handler)

    # --------------------------------------------------------------------------

    def header2dict(self, names, struct_format, data):
        """ unpack the raw received IP and ICMP header informations to a dict """
        unpacked_data = struct.unpack(struct_format, data)
        return dict(zip(names, unpacked_data))

    # --------------------------------------------------------------------------
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
        # h1, h2 = random.sample(range(1, self.num_of_hosts + 1), 2)
        return [h1, h2]

    def send_one_ping(self, current_socket, data, id):
        print "SENDING FROM {0} TO {1}".format(self.source, self.destination)
        # print data
        src, dst = self.source, self.destination
        # TODO: check if loopback address (address of myself) is ok or not?

        ip = ImpactPacket.IP()
        ip.set_ip_src(src)
        ip.set_ip_dst(dst)
        icmp = ImpactPacket.ICMP()
        icmp.set_icmp_type(icmp.ICMP_ECHO)
        icmp.contains(ImpactPacket.Data(data))
        ip.contains(icmp)
        icmp.set_icmp_id(id)
        # TODO: Set when multiple packets are needed for sending a file
        icmp.set_icmp_cksum(0)
        icmp.auto_checksum = 1
        send_time = default_timer()
        try:
            current_socket.sendto(ip.get_packet(), (dst, 1))
        except socket.error:
            current_socket.close()
            return
        return send_time

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

    def has_transmission_finished(self, filename):
        for item in self.return_list:
            if filename == item.filename:
                return item.completely_returned
        return None

    def run(self):
        while True:
            inputready, _, _ = select.select([self.socket, sys.stdin], [], [])
            for sender in inputready:
                if sender == sys.stdin:
                    # print("Stdin sent something")
                    self.process_user_input()
                elif sender == self.socket:
                    # print("socket reply")
                    self.process_socket_reply()
                else:
                    print("else")
            time.sleep(1)

    def process_user_input(self):
        data = raw_input().split()
        cmd, filename = data[0], data[1]
        if cmd == 'send':
            with open(filename, 'r') as f:
                content = f.read()
            chunks = list(map(''.join, zip(*[iter(content)]*3)))
            # print "chunks are:"
            # print "----"
            # print chunks
            # print "----"
            self.send_list.append(SentFile(filename, len(chunks)))
            for i in range(len(chunks)):
                self.source, self.destination = self.generate_two_random_ips()
                data = filename + "\n" + chunks[i]
                self.send_one_ping(self.socket, data, id=i)
        elif cmd == 'return':
            sent_file = self.get_sent_file_data(filename)
            sent_file.return_wanted = True
            self.source, self.destination = self.generate_two_random_ips()
            self.send_one_ping(self.socket, self.create_return_message(filename), id=0xFFFF)

    def finish_transmission(self, filename):
        for item in self.return_list:
            if filename == item.filename:
                item.completely_returned = True
                return

    def process_socket_reply(self):
        packet_data, address = self.socket.recvfrom(ICMP_MAX_RECV)
        icmp_header = self.header2dict(
            names=[
                "type", "code", "checksum",
                "packet_id", "seq_number"
            ],
            struct_format="!BBHHH",
            data=packet_data[20:28]
        )
        ip_header = self.header2dict(
            names=[
                "version", "type", "length",
                "id", "flags", "ttl", "protocol",
                "checksum", "src_ip", "dest_ip"
            ],
            struct_format="!BBHHHBBHII",
            data=packet_data[:20]
        )

        received_data = packet_data[28:]
        if ip_header['ttl'] != 64:
            # filename = PayloadMessage.get_filename(received_data)
            # # print "--ICMP REQUEST ARRIVED"
            # if self.is_in_send_list(filename):
            #     print "my file is back"
            #     sent_file = self.get_sent_file_data(filename)
            #     sent_file.chunks_received.append((received_data, icmp_header["packet_id"]))
            #     if sent_file.received_all():
            #         # self.destination, self.source = self.generate_two_random_ips()
            #         # self.send_one_ping(self.socket, self.create_finish_transmission_message(filename))
            #         print "All Chunks of File {0} Received!".format(filename)
            #         print sent_file.chunks_received
            #         # TODO: save file (headeresh!)
            return

        ip = socket.inet_ntoa(struct.pack("!I", ip_header["src_ip"]))
        print "RECEIVED FROM {0}".format(ip)
        # print received_data

        if PayloadMessage.is_return_message(received_data):
            # print "---------------user wants data to return"
            ip, filename = PayloadMessage.get_return_message_data(received_data)
            # if self.has_transmission_finished(filename):
            #     return
            if self.is_in_send_list(filename) and self.get_sent_file_data(filename).received_all():
                return
            # elif PayloadMessage.is_finish_transmission_message(received_data):
            if not self.is_in_return_list(filename):
                self.return_list.append(ReturnRequest(filename, ip))

        #     print "Transmission Finished!"
        #     filename = PayloadMessage.get_filename(received_data)
        #     self.finish_transmission(filename)
        #     return
        else:
            filename = PayloadMessage.get_filename(received_data)
            # if PayloadMessage.is_returned_to_owner_message(received_data):
            #     return
            if self.is_in_send_list(filename):
                print "my file is back"
                sent_file = self.get_sent_file_data(filename)
                sent_file.chunks_received.append((received_data, icmp_header["packet_id"]))
                if sent_file.received_all():
                    # self.destination, self.source = self.generate_two_random_ips()
                    # self.send_one_ping(self.socket, self.create_finish_transmission_message(filename))
                    print "All Chunks of File {0} Received!".format(filename)
                    print sent_file.chunks_received
                    sent_file.save()
                    # TODO: save file (headeresh!)
                return
            elif self.is_in_return_list(filename):
                self.destination = self.ip
                print "Return to owner. Owner ip is {0}".format(self.destination)
                self.source = self.get_owner_ip(filename)
                self.send_one_ping(self.socket, received_data, id=icmp_header["packet_id"])
                return
        receive_time = default_timer()
        packet_size = len(packet_data) - 28
        self.source, self.destination = self.generate_two_random_ips()
        self.send_one_ping(self.socket, received_data, id=icmp_header["packet_id"])
        return receive_time, packet_size, ip, ip_header, icmp_header

    def create_return_message(self, filename):
        msg = RETURN_HOME_MESSAGE + "\n"
        msg += self.ip + "\n"
        msg += filename
        return msg

    # def create_finish_transmission_message(self, filename):
    #     return FINISH_TRANSMISSION_MESSAGE + "\n" + filename
    # def add_return_to_owner_header(self, received_data):
    #     return RETURNED_TO_OWNER_MESSAGE + "\n" + received_data


def ping(timeout=1000, packet_size=55, *args, **kwargs):
    p = Ping(timeout, packet_size, *args, **kwargs)
    return p.run()


ping()  # put your IP and destination IP address as the ping function argument and run the code. you can ping
# the destination with your own code!!!
