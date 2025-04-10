import socket


def parse_dns_header(header):
    id = int.from_bytes(header[0:2], byteorder='big')
    flags = int.from_bytes(header[2:4], byteorder='big')
    qr = (flags >> 15) & 0x1
    opcode = (flags >> 11) & 0xF
    rd = (flags >> 8) & 0x1
    return {
        'id': id,
        'qr': qr,
        'opcode': opcode,
        'rd': rd
    }


def parse_dns_question(data, offset):
    # Извлекаем имя домена
    labels = []
    while True:
        length = data[offset]
        if length == 0:
            offset += 1
            break
        labels.append(data[offset+1:offset+1+length])
        offset += 1 + length
    name = b''.join(
        [bytes([len(label)]) + label for label in labels]) + b'\x00'

    # Тип и класс (после имени)
    qtype = int.from_bytes(data[offset:offset+2], byteorder='big')
    qclass = int.from_bytes(data[offset+2:offset+4], byteorder='big')
    offset += 4

    return {
        'name': name,
        'qtype': qtype,
        'qclass': qclass,
        'end_offset': offset
    }


def build_dns_header(request_header):
    parsed_header = parse_dns_header(request_header)
    id = parsed_header['id']
    qr = 1
    opcode = parsed_header['opcode']
    aa = 0
    tc = 0
    rd = parsed_header['rd']
    ra = 0
    z = 0
    rcode = 0 if opcode == 0 else 4
    flags = (qr << 15) | (opcode << 11) | (aa << 10) | (
        tc << 9) | (rd << 8) | (ra << 7) | (z << 4) | rcode
    qdcount = 1
    ancount = 1
    nscount = 0
    arcount = 0
    header = (
        id.to_bytes(2, byteorder='big') +
        flags.to_bytes(2, byteorder='big') +
        qdcount.to_bytes(2, byteorder='big') +
        ancount.to_bytes(2, byteorder='big') +
        nscount.to_bytes(2, byteorder='big') +
        arcount.to_bytes(2, byteorder='big')
    )
    return header


def build_dns_question(name):
    qtype = 1  # A-запись
    qclass = 1  # IN
    question = (
        name +
        qtype.to_bytes(2, byteorder='big') +
        qclass.to_bytes(2, byteorder='big')
    )
    return question


def build_dns_answer(name):
    atype = 1  # A-запись
    aclass = 1  # IN
    ttl = 60  # 60 секунд
    rdlength = 4  # IPv4 = 4 байта
    rdata = b"\x08\x08\x08\x08"  # 8.8.8.8
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

            # Разбираем заголовок запроса
            request_header = buf[:12]
            parsed_header = parse_dns_header(request_header)

            # Разбираем Question Section
            question_data = parse_dns_question(buf, 12)
            name = question_data['name']
            qtype = question_data['qtype']
            qclass = question_data['qclass']

            # Формируем ответ
            response = build_dns_header(request_header)
            response += build_dns_question(name)
            response += build_dns_answer(name)

            udp_socket.sendto(response, source)
        except Exception as e:
            print(f"Error receiving data: {e}")
            break


if __name__ == "__main__":
    main()
