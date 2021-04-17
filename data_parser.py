import dpkt
from sys import argv
from asn1crypto import x509
from socket import inet_ntoa
from re import match
from pathlib import Path
from requests import get
from time import time

def tls_multifactory(buf):
    i, n = 0, len(buf)
    msgs = []
    while i + 5 <= n:
        v = buf[i + 1:i + 3]
        if v in dpkt.ssl.SSL3_VERSION_BYTES:
            try:
                msg = dpkt.ssl.TLSRecord(buf[i:])
                msgs.append(msg)
            except dpkt.NeedData:
                break
        else: 
            break
        i += len(msg)
    return msgs, i

def cert_parse(certificates):
    certInfo={}
    cert = x509.Certificate.load(certificates[0])
    if not cert:
        return {}
    str_certs = str(certificates[0])
    # length
    certInfo['size'] = len(certificates[0])
    # is self-signed - only one in chain
    certInfo['self_signed'] = 1 if len(certificates) < 2 else 0
    # subject
    if cert.subject:
        certInfo['subject'] = cert.subject.native['common_name']
        subject_pos = str_certs.find(certInfo['subject'], 0, len(str_certs))
    # issuer
    if cert.issuer:
        certInfo['issuer'] = cert.issuer.native['common_name']
        issuer_pos = str_certs.find(certInfo['issuer'], 0, len(str_certs))
    # validity position
    time_str = cert.not_valid_after.strftime("%-y%m%d%H%M%S")
    valid_pos = str_certs.find(time_str, 0, len(str_certs))
    # signature position
    sign_pos = str_certs.find(str(cert.signature)[2:-2], 0, len(str_certs))
    # public_key position
    pos = str(cert.public_key).find('b\'', 0, len(str(cert.public_key)))
    public_key_part = str(cert.public_key)[pos+3:-2]
    key_pos = str_certs.find(public_key_part, 0, len(str_certs))
    # fields order
    certInfo['order_1'] = 1 if (sign_pos < issuer_pos < valid_pos < subject_pos < key_pos) else 0 
    certInfo['order_2'] = 1 if (issuer_pos < valid_pos < subject_pos < key_pos < sign_pos) else 0 
    return certInfo

def tor_check_ip(ips):
    print('IP check running')
    with open("tor_ips.txt", "r") as f:
        for ip_tor in f:
            for (ip_pcap, port, ip_src) in ips:
                if ip_tor[:-1] == ip_pcap:
                    if port in {9001, 9002, 9003, 9004, 9030, 9031, 9032, 9033, 9100}:
                        print("User " + ip_src + ' connected to TOR ip ' + ip_pcap + ' with possibility 100%')
                    elif port in {80, 443}:
                        print("User " + ip_src + ' connected to TOR ip ' + ip_pcap + ' with possibility 75%')

def tor_check_2(certInfo):
    flags = {}
    flags['self_signed'] = certInfo['self_signed']
    flags['order'] = certInfo['order_1']
    flags['issuer'] = (match(r'www\.[a-zA-Z0-9]{8,20}\.com', certInfo['issuer']) is not None)
    flags['subject'] = (match(r'www\.[a-zA-Z0-9]{8,20}\.net', certInfo['subject']) is not None) and (not(certInfo['issuer'][:-4] == certInfo['subject'][:-4]))
    flags['result'] = str((int(flags['self_signed']) + int(flags['order']) + int(flags['issuer']) + int(flags['subject'])) * 100 / 4) + '%'
    return flags

def tor_check_3(certInfo, port):
    flags = {}
    flags['port'] = (port in {443, 9001, 8443, 22, 80, 8080, 9000, 20000, 20001, 20002})
    flags['subject'] = (match(r'www\.[a-zA-Z0-9]{8,20}\.net', certInfo['subject']) is not None)
    flags['size'] = (400 < certInfo['size'] < 600)
    flags['result'] = str((int(flags['port']) + int(flags['subject']) + int(flags['size'])) * 100 / 3) + '%'
    return flags

def tor_check_4(certInfo):
    flags = {}
    flags['issuer'] = (match(r'www\.[a-zA-Z0-9]{8,20}\.com', certInfo['issuer']) is not None)
    flags['subject'] = (match(r'www\.[a-zA-Z0-9]{8,20}\.net', certInfo['subject']) is not None) and (not(certInfo['issuer'][:-4] == certInfo['subject'][:-4]))
    flags['size'] = (400 < certInfo['size'] < 600)
    flags['self_signed'] = certInfo['self_signed']
    flags['result'] = str((int(flags['subject']) + int(flags['issuer']) + int(flags['size']) + int(flags['self_signed'])) * 100 / 4) + '%'
    return flags

def packet_analyse(cap):
    ips_set = set()
    for timestamp, packet in cap:
        try:
            eth = dpkt.ethernet.Ethernet(packet)
        except:
            pass
        if not(isinstance(eth.data, dpkt.ip.IP)):
            continue
        ip = eth.data
        if not(isinstance(ip.data, dpkt.tcp.TCP)):
            continue
        tcp = ip.data
        ips_set.add((inet_ntoa(ip.dst), tcp.dport, inet_ntoa(ip.src)))
        records = []
        try:
            records, bytes_used = tls_multifactory(tcp.data)
        except:
            continue
        for record in records:
            if len(record.data) == 0:
                continue
            hdtype = record.data[0]
            try:
                handshake = dpkt.ssl.TLSHandshake(record.data)
                hd = handshake.data
            except Exception as e:
                continue
            if hdtype == 11: # certificate
                certInfo = cert_parse(hd.certificates)
                print(inet_ntoa(ip.dst), tcp.dport, inet_ntoa(ip.src), tcp.sport)
                print(certInfo)
                print('2nd algo result: ' + str(tor_check_2(certInfo)))
                print('3rd algo result: ' + str(tor_check_3(certInfo, tcp.sport)))
                print('4th algo result: ' + str(tor_check_4(certInfo)))
                print()
    tor_check_ip(ips_set)

def get_ip_file():
    url = "https://www.dan.me.uk/torlist/"
    try:
        response = get(url)
        open('tor_ips.txt', 'wb').write(response.content)
    except Exception as e:
        print(e)

def file_update():
    fips = Path('tor_ips.txt')
    if not(fips.exists()):
        get_ip_file()
    half_hour = 1800
    file_time = fips.stat().st_mtime
    time_now = time()
    if (time_now - file_time > half_hour):
        print('Updating IP file')
        get_ip_file()

def main(filename):
    file_update()
    try:
        with open(filename, 'rb') as fp:
            capture = dpkt.pcap.Reader(fp)
            packet_analyse(capture)
    except Exception as e:
        print(e)

if __name__ == "__main__":
    if len(argv) != 2:
        print('Usage: ./data_parser.py <filename>')
    else:
        main(str(argv[1]))
