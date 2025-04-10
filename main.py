import socket


def parse_dns_header(header):
    # Разбираем первые 12 байт запроса
    id = int.from_bytes(header[0:2], byteorder='big')
    flags = int.from_bytes(header[2:4], byteorder='big')

    # Извлекаем флаги
    qr = (flags >> 15) & 0x1
    opcode = (flags >> 11) & 0xF
    rd = (flags >> 8) & 0x1

    return {
        'id': id,
        'qr': qr,
        'opcode': opcode,
        'rd': rd
    }


def build_dns_header(request_header):
    # Парсим заголовок запроса
    parsed_header = parse_dns_header(request_header)

    # ID берём из запроса
    id = parsed_header['id']

    # Формируем флаги ответа
    qr = 1  # Ответ (1)
    opcode = parsed_header['opcode']
    aa = 0  # Не авторитативный ответ
    tc = 0  # Не обрезан
    rd = parsed_header['rd']  # Копируем из запроса
    ra = 0  # Рекурсия недоступна
    z = 0   # Зарезервировано (0)

    # RCODE: 0, если OPCODE=0, иначе 4
    rcode = 0 if opcode == 0 else 4

    # Собираем флаги в 2 байта
    flags = (qr << 15) | (opcode << 11) | (aa << 10) | (
        tc << 9) | (rd << 8) | (ra << 7) | (z << 4) | rcode

    # Счётчики (можно оставить как в прошлый раз)
    qdcount = 1
    ancount = 1
    nscount = 0
    arcount = 0

    # Упаковываем в big-endian
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

    question = (
        name +
        qtype.to_bytes(2, byteorder='big') +
        qclass.to_bytes(2, byteorder='big')
    )
    return question


def build_dns_answer():
    # Доменное имя (то же, что в вопросе)
    name = (
        b"\x0ccodecrafters"
        b"\x02io"
        b"\x00"
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
            # 1. Заголовок (анализируем запрос)
            response = build_dns_header(buf[:12])
            # 2. Question Section
            response += build_dns_question()
            # 3. Answer Section
            response += build_dns_answer()

            # Отправляем ответ
            udp_socket.sendto(response, source)
        except Exception as e:
            print(f"Error receiving data: {e}")
            break


if __name__ == "__main__":
    main()
