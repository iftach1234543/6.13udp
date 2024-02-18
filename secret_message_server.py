from scapy.all import *
from scapy.layers.inet import UDP, IP


def get_port_ascii_char(packet1):
    """
    Returns the ASCII character representation of the port of the packet if the packet is empty.
    param packet1: The packet to check.
    :return: The ASCII character for the port if packet is empty, otherwise an empty string.
    """
    if UDP in packet1 and is_empty_packet(packet1):
        port = packet1[UDP].dport
        if 0 <= port <= 255:
            return chr(port)
    return ""


def is_empty_packet(packet2):
    """
    Checks if a packet has an empty payload.
    param packet2: The packet to check.
    :return: True if packet payload is empty else False.
    """
    return len(packet2[UDP].payload) == 0


def sniff_packets(packet3):
    """
    Processes packets captured by sniffing based on certain criteria.
    param packet3: The packet captured by sniffing.
    """
    ascii_char = get_port_ascii_char(packet3)
    if ascii_char:
        print(ascii_char, end="", flush=True)


def test_functions():
    """
    Tests the functionality of other functions independently of network traffic.
    """
    packet4 = IP() / UDP(dport=65) / ""
    assert get_port_ascii_char(packet4) == 'A', "get_port_ascii_char did not return expected ASCII character for 'A'."
    assert is_empty_packet(packet4) == True, "is_empty_packet did not identify an empty packet correctly."


def main():
    """
    Main function to start packet sniffing.
    """
    sniff(prn=sniff_packets, filter="udp and dst portrange 0-255", store=0)


if __name__ == '__main__':
    try:
        test_functions()  # Run assertions before main
        main()
    except Exception as e:
        print(f"An error occurred: {e}")

