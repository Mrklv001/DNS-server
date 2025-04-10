import socket


def parse_dns_header(header):
    if len(header) < 12:
        raise ValueError("Invalid DNS header length")
    id = int.from_bytes(header[0:2], byteorder='big')
    flags = int.from_bytes(header[2:4], byteorder='big')
    qdcount = int.from_bytes(header[4:6], byteorder='big')
    ancount = int.from_bytes(header[6:8], byteorder='big')
    nscount = int.from_bytes(header[8:10], byteorder='big')
    arcount = int.from_bytes(header[10:12], byteorder='big')
    return {
        'id': id,
        'flags': flags,
        'qdcount': qdcount,
        'ancount': ancount,
        'nscount': nscount,
        'arcount': arcount
    }


def parse_compressed_name(data, offset):
    labels = []
    visited = set()
    while True:
        if offset in visited:
            raise ValueError("Compression loop detected")
        visited.add(offset)

        length = data[offset]
        if (length & 0xC0) == 0xC0:
            if offset + 1 >= len(data):
                raise ValueError("Invalid compression pointer")
            pointer = int.from_bytes(data[offset:offset+2], 'big') & 0x3FFF
            if pointer >= offset:
                raise ValueError("Invalid forward compression pointer")
            part_name, _ = parse_compressed_name(data, pointer)
            labels.append(part_name[1:])  # Remove length byte
            offset += 2
            break
        elif length > 0:
            if offset + 1 + length > len(data):
                raise ValueError("Label exceeds packet length")
            labels.append(data[offset+1:offset+1+length])
            offset += 1 + length
        else:
            offset += 1
            break

    name = b''.join(
        [bytes([len(label)]) + label for label in labels]) + b'\x00'
    return name, offset


def parse_dns_question(data, offset):
    name, offset = parse_compressed_name(data, offset)
    if offset + 4 > len(data):
        raise ValueError("Question section truncated")
    qtype = int.from_bytes(data[offset:offset+2], 'big')
    qclass = int.from_bytes(data[offset+2:offset+4], 'big')
    return {
        'name': name,
        'qtype': qtype,
        'qclass': qclass,
        'end_offset': offset + 4
    }


def build_dns_header(request_header, qdcount, ancount, rcode=0):
    id_bytes = request_header[0:2]
    request_flags = int.from_bytes(request_header[2:4], byteorder='big')

    rd_flag = request_flags & 0x0100
    opcode = request_flags & 0x7800

    if opcode != 0:
        # Not implemented: QR=1, RA=1, RCODE=4
        flags = 0x8000 | 0x0080 | rd_flag | opcode | 0x0004
        qdcount = 0
        ancount = 0
    else:
        # Normal response: QR=1, RA=1, RCODE=0, preserve RD
        flags = 0x8000 | 0x0080 | rd_flag | opcode | rcode

    return (
        id_bytes +
        flags.to_bytes(2, 'big') +
        qdcount.to_bytes(2, 'big') +
        ancount.to_bytes(2, 'big') +
        (0).to_bytes(2, 'big') +  # NSCOUNT
        (0).to_bytes(2, 'big')   # ARCOUNT
    )


def build_dns_question(name):
    qtype = 1
    qclass = 1
    return name + qtype.to_bytes(2, 'big') + qclass.to_bytes(2, 'big')


def build_dns_answer(name):
    atype = 1
    aclass = 1
    ttl = 60
    rdata = b'\x08\x08\x08\x08'
    return (
        name +
        atype.to_bytes(2, 'big') +
        aclass.to_bytes(2, 'big') +
        ttl.to_bytes(4, 'big') +
        len(rdata).to_bytes(2, 'big') +
        rdata
    )


def main():
    udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp_socket.bind(("127.0.0.1", 2053))
    print("DNS server started on port 2053")

    while True:
        try:
            buf, source = udp_socket.recvfrom(512)
            if len(buf) < 12:
                print("Received packet too small")
                continue

            try:
                header = parse_dns_header(buf[:12])
                qdcount = header['qdcount']
                opcode = header['flags'] & 0x7800

                questions = []
                offset = 12
                for _ in range(qdcount):
                    question = parse_dns_question(buf, offset)
                    questions.append(question)
                    offset = question['end_offset']

                # Build response header
                is_not_implemented = opcode != 0
                response_header = build_dns_header(
                    buf[:12], qdcount, qdcount, rcode=4 if is_not_implemented else 0)
                response = response_header

                if not is_not_implemented:
                    for q in questions:
                        response += build_dns_question(q['name'])
                    for q in questions:
                        response += build_dns_answer(q['name'])

                udp_socket.sendto(response, source)

            except ValueError as e:
                print(f"Error processing packet: {e}")
                continue

        except Exception as e:
            print(f"Fatal error: {e}")
            break


if __name__ == "__main__":
    main()
