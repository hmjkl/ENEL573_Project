from scapy.all import *

ServerIp = '192.168.0.1'
ClientIp = '192.168.0.2'

packets = rdpcap('ENEL573_Proj_PartA.pcap')
packets = list(packet for packet in packets if packet.haslayer('UDP')) 

class Computer:

    def __init__(self, IP):
        self.IP = IP
        
    IP = None

    NumPacketsSent = 0
    NumPacketsReceived = 0

    FirstPacketReceiveTime = None
    LastPacketReceiveTime = None

Server = Computer('192.168.0.1')
Client = Computer('192.168.0.2')

for packet in packets:
    Sender = None
    Receiver = None

    if packet['IP'].src == Server.IP and packet['IP'].dst == Client.IP:
        Sender = Server
        Receiver = Client
    elif packet['IP'].src == Client.IP and packet['IP'].dst == Server.IP: 
        Sender = Client
        Receiver = Server

    if Sender != None and Receiver != None:
        Sender.NumPacketsSent += 1
        Receiver.NumPacketsReceived += 1

        Sender.LastPacketSentTime = packet.sent_time
        Receiver.LastPacketReceiveTime = packet.time

        if Receiver.FirstPacketReceiveTime == None:
            Receiver.FirstPacketReceiveTime = packet.time


print('Number of packets sent by server: {}\nNumber of packets sent by client: {}\n'.format(Server.NumPacketsSent, Client.NumPacketsSent))
print('Time between when the server first and last receives UDP packet from client: {}'.format(Server.LastPacketReceiveTime - Server.FirstPacketReceiveTime));
print('Time between when the client first and last receives UDP packet from server: {}'.format(Client.LastPacketReceiveTime - Client.FirstPacketReceiveTime));
