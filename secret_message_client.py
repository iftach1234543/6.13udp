# Client code

from scapy.all import *
from scapy.layers.inet import IP, UDP


def send_message(message) -> None:
    """
    Handles the message sending and formatting
    :param message: The message to send
    :return: None
    """
    server_ip = "127.0.0.1"  # Loopback address for local testing
    server_port = 8080  # Use the same port number as specified in the server code
    for char in message:
        ascii_value = ord(char)
        packet = IP(dst=server_ip) / UDP(dport=ascii_value)


        send(packet)
        print("Sent empty message to port: ", ascii_value)

def main() -> None:
    """
    the Main function
    :return: None
    """
    message = input("Enter msg: ")
    send_message(message)
    print("Msg sent!")

if __name__ == '__main__':
    main()
