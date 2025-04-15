import socket
import struct
import textwrap


TAB1 = '\t'
TAB2 = '\t\t'
TAB3 = '\t\t\t'
TAB3 = '\t\t\t\t'


def main():
    conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))

    while True:
        raw_data, addr = conn.recvfrom(65536)
        dest_mac, src_mac, eth_proto, data = ethernet_frame(raw_data)
        print('\nEthernet fram :')
        print(TAB1 + 'Destination: {}, Source: {}, Protocol: {}'.format(dest_mac, src_mac, eth_proto))

        # 8 for ipv4
        if eth_proto == 8:
            (version, headear_length, ttl, proto, src, target, data) = ipv4_packet(data)
            print(TAB1 + 'IPV4 Packet:')
            print(TAB2 + 'Version: {}, Header length: {}, TTL: {}'.format(version, headear_length, ttl))
            print(TAB2 + 'Protocol: {}, Source: {}, Target: {}'.format(proto, src, target))

           #icmp 
            if proto == 1:
                icmp_type, code, checksum, data = icmp_packet(data)
                print(TAB1 + 'ICMP Packet:')
                print(TAB2 + 'Type: {}, Code: {}, Checksum: {}'.format(icmp_type, code, checksum))
                print(TAB2 + 'DATA: ')
                print(format_multi_line(TAB3, data))
            
            #Tcp
            elif proto == 6:
                src_port, dest_port, sequence, acknowledgement, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, data  = tcp_packet(data)
                print(TAB1 + 'Tcp segment:')
                print(TAB2 + 'sorce port : {}, destination port: {} '.format(src_port,dest_port))
                print(TAB2 + 'sequence  : {}, acknowledgemet: {} '.format(sequence,acknowledgement))
                print(TAB2 + 'Flags: ')
                print(TAB3+ 'Urg: {}, Ack:{}, Psh: {}, RST : {}, SYN : {}, FIN : {}'.format(flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin))
                print(TAB2 + 'DATA: ')
                print(format_multi_line(TAB3, data))

            #udp 
            elif proto == 17:
                src_port, dest_port, size, data  = udp_segment(data)
                print(TAB1 + 'UDP SEGMENT:')
                print(TAB2 + 'sorce port: {}, dest port : {}, length: {}'.format(src_port, dest_port, size))
                print(TAB2 + 'DATA: ')
                print(format_multi_line(TAB3, data))

            #other
            else:
                print(TAB1 + 'DATA')
                print(format_multi_line(TAB2, data))
                
        else:
            print(TAB1 + 'DATA')
            print(format_multi_line(TAB2, data))
             
                



#Unpack ethernet frame
def ethernet_frame(data):
    dest_mac, src_mac, proto = struct.unpack('! 6s 6s H',data[:14])
    return get_mac_addr(dest_mac), get_mac_addr(src_mac), socket.htons(proto), data[14:]


#properly format mac adress (AA:BB:CC:EE:FF:DD)
def get_mac_addr(bytes_addr):
    bytes_str = map('{:02x}'.format, bytes_addr)
    return ':'.join(bytes_str).upper()


#unpack ipv4 packet
def ipv4_packet(data):
    version_header_lenght = data[0]
    version = version_header_lenght >> 4
    header_lenght = (version_header_lenght & 15)*4
    ttl, proto, src, target = struct.unpack('! 8x B B 2x 4s 4s', data[:20])
    return version, header_lenght, ttl, proto, ipv4(src), ipv4(target), data[header_lenght:]


#return properly formatted ipv4 address
def ipv4(addr):
    return '.'.join(map(str, addr))


#unpack icmp packet
def icmp_packet(data):
    icmp_type, code, checksum = struct.unpack('! B B H', data[:4])
    return icmp_type, code, checksum, data[4:]


#unpack Tcp packet
def tcp_packet(data):
    (src_port, dest_port, sequence, acknowledgement, offset_reserved_flag) = struct.unpack('! H H L L H', data[:14])
    offset = (offset_reserved_flag >> 12)*4 
    flag_urg = (offset_reserved_flag & 32) >> 5
    flag_ack = (offset_reserved_flag & 16) >> 4
    flag_psh = (offset_reserved_flag & 8) >> 3
    flag_rst = (offset_reserved_flag & 4) >> 2
    flag_syn = (offset_reserved_flag & 2) >> 1
    flag_fin = offset_reserved_flag & 1
    
    return src_port, dest_port, sequence, acknowledgement, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, data[offset:]


#unpack udp segment
def udp_segment(data):
    src_port, dest_port, size = struct.unpack('! H H 2x H', data[:8])
    return src_port, dest_port, size, data[8:]


#format multiline data
def format_multi_line(prefix, string, size=80):
    size -= len(prefix)
    if isinstance(string, bytes):
        string = ''.join(r'\x{:2x}'.format(byte) for byte in string)
        if size%2:
            size -=1
    return '\n'.join([prefix + line for line in textwrap.wrap(string, size)])



if __name__ == "__main__":
    main()