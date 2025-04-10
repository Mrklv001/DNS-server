import socket


def build_dns_header():
    # Packet Identifier (ID) - 16 bits (1234 in big-endian)
    id = 1234
    # Flags: QR=1 (response), остальные флаги 0
    flags = 0x8000  # 1000 0000 0000 0000 in binary
    # QDCOUNT = 1 (один вопрос)
    qdcount = 1
    # ANCOUNT = 1 (один ответ)
    ancount = 1
    # NSCOUNT, ARCOUNT = 0 (пока не используются)
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
    # Доменное имя: codecrafters.io
    name = (
        b"\x0ccodecrafters"  # \x0c (12) + "codecrafters"
        b"\x02io"            # \x02 (2) + "io"
        b"\x00"               # Завершающий нулевой байт
    )

    # Тип записи (1 = A-запись)
    qtype = 1
    # Класс записи (1 = IN, интернет)
    qclass = 1

    # Упаковываем всё в big-endian
    question = (
        name +
        qtype.to_bytes(2, byteorder='big') +
        qclass.to_bytes(2, byteorder='big')
    )
    return question


def build_dns_answer():
    # Доменное имя (то же, что в вопросе)
    name = (
        b"\x0ccodecrafters"  # \x0c (12) + "codecrafters"
        b"\x02io"            # \x02 (2) + "io"
        b"\x00"               # Завершающий нулевой байт
    )

    # Тип записи (1 = A-запись)
    atype = 1
    # Класс записи (1 = IN, интернет)
    aclass = 1
    # TTL (60 секунд)
    ttl = 60
    # Длина данных (4 байта для IPv4)
    rdlength = 4
    # Данные (IPv4-адрес: 8.8.8.8)
    rdata = b"\x08\x08\x08\x08"

    # Упаковываем всё в big-endian
    answer = (
        name +
        atype.to_bytes(2, byteorder='big') +
        aclass.to_bytes(2, byteorder='big') +
        ttl.to_bytes(4, byteorder='big') +
        rdlength.to_bytes(2, byteorder='big') +
        rdata
    )
    return answer


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
            # 3. Answer Section (ответ)
            response += build_dns_answer()

            # Отправляем ответ
            udp_socket.sendto(response, source)
        except Exception as e:
            print(f"Error receiving data: {e}")
            break


if __name__ == "__main__":
    main()
