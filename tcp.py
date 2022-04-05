import time
import socket
import random
import struct
from typing import NamedTuple
from multiprocessing import Process
from ip import IpHandler
from helper import checksum


class Packet(NamedTuple):
    '''
    RFC 793: https://datatracker.ietf.org/doc/html/rfc793#section-3.1

    TCP Header Format:
     0                   1                   2                   3
     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |          Source Port          |       Destination Port        |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                        Sequence Number                        |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                    Acknowledgment Number                      |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |  Data |           |U|A|P|R|S|F|                               |
    | Offset| Reserved  |R|C|S|S|Y|I|            Window             |
    |       |           |G|K|H|T|N|N|                               |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |           Checksum            |         Urgent Pointer        |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                    Options                    |    Padding    |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                             data                              |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    '''
    sourcePort:             int     = 0
    destinationPort:        int     = 0
    seqNum:                 int     = 0
    ackNum:                 int     = 0
    dataOffset:             int     = 5
    reserved:               bytes   = 0
    URG:                    int     = 0
    ACK:                    int     = 0
    PSH:                    int     = 0
    RST:                    int     = 0
    SYN:                    int     = 0
    FIN:                    int     = 0
    window:                 int     = 1400
    checksum:               int     = 0
    urgentPointer:          int     = 0
    options:                bytes   = b''
    data:                   bytes   = b''


# A handler for tcp protocol with basic congestion control to establish connection, send/recv data, and teardown.
class TcpHandler(object):
    def __init__(self, retransmit_timeout=60) -> None:
        self.ipHandler = None   # initialized when connecting

        self.srcIp = IpHandler.fetch_ip()
        self.srcPort = TcpHandler.fetch_port()

        self.destIp = None
        self.destPort = None

        self.seqNum = random.randint(0, 2 ** 32)
        self.ackNum = None

        self.retransmit_timeout = retransmit_timeout
        self.cwin = 1

        self.recv_buffer = []

    # fetch an available port from os
    @staticmethod
    def fetch_port() -> int:
        sock = socket.socket()
        sock.bind(('', 0))
        port = sock.getsockname()[1]
        sock.close()
        return port

    # establish a connection
    def connect(self, destIp, destPort) -> None:
        self.ipHandler = IpHandler(destIp)

        self.destIp = destIp
        self.destPort = destPort

        # first handshake and second handshake
        self.__send_and_wait(Packet(sourcePort=self.srcPort, destinationPort=destPort,
                                    seqNum=self.seqNum, SYN=1))

        # third handshake
        self.__send(encode(self.srcIp, self.destIp, Packet(sourcePort=self.srcPort, destinationPort=destPort,
                                                           seqNum=self.seqNum, ackNum=self.ackNum, ACK=1)))

    # send data and receive response
    def send(self, data) -> None:
        # send data
        send_buffer = data
        while len(send_buffer) != 0:
            received = self.__send_and_wait(Packet(sourcePort=self.srcPort, destinationPort=self.destPort,
                                                   seqNum=self.seqNum, ackNum=self.ackNum, ACK=1,
                                                   data=send_buffer[:self.cwin]))
            self.recv_buffer.append(received.data)

            send_buffer = send_buffer[self.cwin:]
            self.cwin += max(self.cwin * 2, 1000)

        # receive data
        finished = False
        last_retry = None
        while not finished:
            received, retry = self.__recv_and_ack()
            self.recv_buffer.append(received.data)

            # stop retransmit of the last ack and update to this ack
            if last_retry is not None:
                last_retry.terminate()
            last_retry = retry

            finished = received.FIN

        if last_retry is not None:
            last_retry.terminate()

    # send and wait for ack
    def __send_and_wait(self, packet) -> Packet:
        self.__send(encode(self.srcIp, self.destIp, packet))
        # print(packet)

        # start a process to retransmit packet
        retry = Process(target=self.__retransmit, args=(packet,))
        retry.start()

        while True:
            received = self.__recv()
            if received.ackNum == packet.seqNum + len(packet.data) + packet.SYN + packet.FIN:
                retry.terminate()

                self.seqNum = received.ackNum
                self.ackNum = received.seqNum + len(received.data)

                return received

    # wait for a packet and ack
    def __recv_and_ack(self) -> (Packet, Process):
        while True:
            received = self.__recv()
            if received.seqNum == self.ackNum:
                self.seqNum = received.ackNum
                self.ackNum += len(received.data) + received.FIN

                ack_pkt = Packet(sourcePort=self.srcPort, destinationPort=self.destPort,
                                 seqNum=self.seqNum, ackNum=self.ackNum, ACK=1)
                self.__send(encode(self.srcIp, self.destIp, ack_pkt))

                # start a process to retransmit ack
                retry = Process(target=self.__retransmit, args=(ack_pkt,))
                retry.start()

                return received, retry
            elif received.seqNum < self.ackNum:
                self.cwin = 1

    # send packet after each retransmit timeout
    def __retransmit(self, packet) -> None:
        while True:
            time.sleep(self.retransmit_timeout)

            # TODO: test
            # print('retry...')
            self.cwin = 1
            packet = Packet(packet.sourcePort, packet.destinationPort, packet.seqNum, packet.ackNum,
                            packet.dataOffset, packet.reserved,
                            packet.URG, packet.ACK, packet.PSH, packet.RST, packet.SYN, packet.FIN,
                            packet.window, data=packet.data[:self.cwin])
            self.__send(encode(self.srcIp, self.destIp, packet))

    # send one packet to ip layer
    def __send(self, encoded) -> None:
        self.ipHandler.send(self.destIp, self.destPort, encoded)

    # receive all data in buffer
    def recvall(self) -> bytes:
        data = b''.join(self.recv_buffer)
        self.recv_buffer.clear()
        return data

    # receive one packet
    def __recv(self) -> Packet:
        while True:
            packet = decode(self.ipHandler.recv(), self.srcIp, self.destIp)
            if packet is not None and packet.destinationPort == self.srcPort:
                return packet

    # close connection
    def close(self) -> None:
        self.__send_and_wait(Packet(sourcePort=self.srcPort, destinationPort=self.destPort,
                                    seqNum=self.seqNum, ackNum=self.ackNum, ACK=1, FIN=1))


def encode(src_ip, dest_ip, packet) -> bytes:
    # tcp header
    offset = packet.dataOffset << 4
    flags = packet.FIN + (packet.SYN << 1) + (packet.RST << 2) + (packet.PSH << 3) + (packet.ACK << 4) + (packet.URG << 5)
    tcp_header = struct.pack('!HHLLBBHHH', packet.sourcePort, packet.destinationPort,
                             packet.seqNum, packet.ackNum,
                             offset, flags, packet.window, 0, packet.urgentPointer)

    # pseudo header
    pseudo_header = struct.pack('!4s4sBBH', socket.inet_aton(src_ip), socket.inet_aton(dest_ip),
                                0, 6, len(tcp_header) + len(packet.data))

    # replace checksum
    csum = checksum(pseudo_header + tcp_header + packet.data)
    tcp_header = tcp_header[:16] + struct.pack('H', csum) + tcp_header[18:]

    return tcp_header + packet.data


# decode the packet, if checksum is incorrect, return None
def decode(raw, client_ip, server_ip) -> Packet:
    # parse tcp header
    source_port, destination_port, \
        sequence_number, acknowledgment_number, \
        offset, flags, window, = struct.unpack('!HHLLBBH', raw[:16])
    csum, = struct.unpack('H', raw[16:18])

    offset = (offset >> 4) * 4

    fin = flags & 0x01
    flags >>= 1
    syn = flags & 0x01
    flags >>= 1
    rst = flags & 0x01
    flags >>= 1
    psh = flags & 0x01
    flags >>= 1
    ack = flags & 0x01
    flags >>= 1
    urg = flags & 0x01

    # print(Packet(source_port, destination_port, sequence_number, acknowledgment_number,
    #               offset, b'', urg, ack, psh, rst, syn, fin, window, csum, urgent_pointer, b'',
    #               raw[offset:]))
    # print(str(destination_port) + " " + str(sequence_number) + " " + str(acknowledgment_number))

    # verify checksum
    pseudo_header = struct.pack('!4s4sBBH', socket.inet_aton(server_ip), socket.inet_aton(client_ip), 0, 6, len(raw))
    tcp_header_without_csum = raw[:16] + bytes(2) + raw[18:offset]
    computed_csum = checksum(pseudo_header + tcp_header_without_csum + raw[offset:])
    # print('computed: {}, packet {}'.format(computed_csum, raw[:20].hex()))
    if computed_csum != csum:
        # print("checksum incorrect! Psh: {}".format(psh))
        # print()
        return None

    return Packet(source_port, destination_port, sequence_number, acknowledgment_number,
                  offset, b'', urg, ack, psh, rst, syn, fin, window, csum, raw[18:20], b'', raw[offset:])
