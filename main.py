import socket


def build_dns_header():
    # Packet Identifier (ID) - 16 bits (1234 in big-endian)
    id = 1234
    # Flags: QR=1 (response), остальные флаги 0
    flags = 0x8000  # 1000 0000 0000 0000 in binary
    # QDCOUNT = 1 (один вопрос)
    qdcount = 1
    # ANCOUNT, NSCOUNT, ARCOUNT = 0 (пока не используются)
    ancount = 0
    nscount = 0
    arcount = 0

    # Упаковываем всё в big-endian
    header = (
        id.to_bytes(2, byteorder='big') +
        flags.to_bytes(2, byteorder='big') +
        qdcount.to_bytes(2, byteorder='big') +
        ancount.to_bytes(2, byteorder='big') +
        nscount.to_bytes(2, byteorder='big') +
        arcount.to_bytes(2, byteorder='big')
    )
    return header


def build_dns_question():
    name = (
        b"\x0ccodecrafters"  # \x0c (12) + "codecrafters"
        b"\x02io"            # \x02 (2) + "io"
        b"\x00"               # Завершающий нулевой байт
    )

    qtype = 1
    qclass = 1

    question = (
        name +
        qtype.to_bytes(2, byteorder='big') +
        qclass.to_bytes(2, byteorder='big')
    )
    return question


def main():
    udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp_socket.bind(("127.0.0.1", 2053))

    while True:
        try:
            buf, source = udp_socket.recvfrom(512)

            # Собираем DNS-ответ:
            # 1. Заголовок (12 байт)
            response = build_dns_header()
            # 2. Question Section (домен + тип + класс)
            response += build_dns_question()

            # Отправляем ответ
            udp_socket.sendto(response, source)
        except Exception as e:
            print(f"Error receiving data: {e}")
            break


if __name__ == "__main__":
    main()
