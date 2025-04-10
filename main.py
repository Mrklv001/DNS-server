import socket


def build_dns_header():
    # Packet Identifier (ID) - 16 bits (1234 in big-endian)
    id = 1234
    flags = 0x8000

    # Counts (all 0)
    qdcount = 0
    ancount = 0
    nscount = 0
    arcount = 0

    # Pack all fields in big-endian format
    header = (
        id.to_bytes(2, byteorder='big') +
        flags.to_bytes(2, byteorder='big') +
        qdcount.to_bytes(2, byteorder='big') +
        ancount.to_bytes(2, byteorder='big') +
        nscount.to_bytes(2, byteorder='big') +
        arcount.to_bytes(2, byteorder='big')
    )

    return header


def main():
    udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp_socket.bind(("127.0.0.1", 2053))

    while True:
        try:
            buf, source = udp_socket.recvfrom(512)

            # Build DNS response header
            response = build_dns_header()

            # Send the response back
            udp_socket.sendto(response, source)
        except Exception as e:
            print(f"Error receiving data: {e}")
            break


if __name__ == "__main__":
    main()
