# Server code

from scapy.all import *
from scapy.layers.inet import UDP, IP

def get_port_ascii_char(packet):
    """
    Returns the ASCII character representation of the port of the packet if the packet is empty.
    :param packet: the UDP packet to check
    :return: ASCII character representation of the port if the packet is empty, otherwise an empty string
    """
    if is_empty_packet(packet):
        port = packet[UDP].dport
        if 97 <= port <= 123:  # Check if port is between 97 and 123
            print(chr(port))
            return chr(port)
    return ""

def is_empty_packet(packet):
    """
    Checks if a packet has an empty payload.
    :param packet: the UDP packet to check
    :return: True if packet is empty else False
    """
    payload = packet[UDP].payload
    print("is empty", len(payload) == 0)
    return len(payload) == 0

def sniff_packets(packet):
    """
    Turns the packets sent to the message
    :param packet: the UDP packet to decode
    :return: None
    """
    print("here1")
    ascii_char = get_port_ascii_char(packet)
    if ascii_char:
        print(ascii_char, end="")

def main():
    """
    the main function
    :return: None
    """
    sniff(prn=sniff_packets, filter="udp and dst portrange 97-123", store=0)

if __name__ == '__main__':
    main()
