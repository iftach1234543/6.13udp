from scapy.all import *
from scapy.layers.inet import IP, UDP

SERVERIP = "34.98.7.6"  # Set this to the actual server IP when testing


def send_message(message) -> None:
    """
    Sends a message by transmitting packets to the server with the payload encoded in the destination port.
    param message: The message to send.
    """
    for char in message:
        ascii_value = ord(char)
        packet1 = IP(dst=SERVERIP) / UDP(dport=ascii_value) / ""
        try:
            send(packet1)
            print(f"Sent empty message to port: {ascii_value}")
        except Exception as i:
            print(f"An error occurred while sending a message: {i}")


def main():
    """
    Main function for the client to interactively send a message.
    """
    message = input("Enter msg: ")
    send_message(message)
    print("Msg sent!")


if __name__ == '__main__':
    try:
        main()
    except Exception as e:
        print(f"An error occurred: {e}")
