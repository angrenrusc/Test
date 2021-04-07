import dpkt
import struct
from asn1crypto import x509
from socket import inet_ntoa
from re import match
from pathlib import Path
from requests import get
from time import time

def get_ip_file():
    url = "https://www.dan.me.uk/torlist/"
    #url = "https://check.torproject.org/torbulkexitlist"
    #url = "https://raw.githubusercontent.com/gregcusack/tor_classifier/master/tor_ips.txt"
    response = get(url)
    open('tor_ips.txt', 'wb').write(response.content)

def tls_multi_factory_new(buf):
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
    # collecting data
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


def tor_check_1 (certInfo):
    flag = 1
    # self-signed check
    flag = flag & certInfo['self_signed']
    # order check
    flag = flag & (certInfo['order_1'] | certInfo['order_2'])
    # issuer check
    flag = flag & (match(r'www\.[a-zA-Z0-9]{8,20}\.com', certInfo['issuer']) is not None)
    # subject check
    flag = flag & (match(r'www\.[a-zA-Z0-9]{8,20}\.net', certInfo['subject']) is not None)
    # not the same check
    flag = flag & (not(certInfo['issuer'][:-4] == certInfo['subject'][:-4]))
    return flag


def tor_check_2 (certInfo, port):
    flag = 1
    # port check
    flag = flag & (port in {22, 80, 443, 8080, 8443, 9000, 9001, 20000, 20001, 20002})
    # subject check
    flag = flag & (match(r'www\.[a-zA-Z0-9]{8,20}\.net', certInfo['subject']) is not None)
    # size check
    flag = flag & (400 < certInfo['size'] < 600)
    return flag

def tor_check_3(ips):
    with open("tor_ips.txt", "r") as f:
        for ip_tor in f:
            for (ip_pcap, port) in ips:
                if ip_tor[:-1] == ip_pcap:
                    if port in {22, 80, 443, 8080, 8443, 9000, 9001, 9010, 20000, 20002}:
                        print('uhu')
    return 1

def packet_analyse(cap):
    i = 0
    ips_set = set()
    for timestamp, packet in cap:
        eth = dpkt.ethernet.Ethernet(packet)
        if not(isinstance(eth.data, dpkt.ip.IP)):
            continue
        ip = eth.data
        if not(isinstance(ip.data, dpkt.tcp.TCP)):
            continue
        tcp = ip.data
        ips_set.add((inet_ntoa(ip.dst), tcp.dport))
        records = []
        try:
            records, bytes_used = tls_multi_factory_new(tcp.data)
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
            if hdtype == 11:
                certInfo = cert_parse(hd.certificates)
                print(tcp.sport, tcp.dport, inet_ntoa(ip.dst), inet_ntoa(ip.src)) #source and destination ports
                print(certInfo)
                print(tor_check_1(certInfo))
                print(tor_check_2(certInfo, tcp.sport))
    print(tor_check_3(ips_set))

def main():
    fips = Path('tor_ips.txt')
    if not(fips.exists()):
        get_ip_file()
    half_hour = 1800
    file_time = fips.stat().st_mtime
    time_now = time()
    if (time_now - file_time > half_hour):
        print('Updating ip_s file')
        get_ip_file()

    with open('stolen2.pcap', 'rb') as fp:
        capture = dpkt.pcap.Reader(fp)
        packet_analyse(capture)

if __name__ == "__main__":
    main()
