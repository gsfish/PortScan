#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os
import random
import struct
import argparse
from itertools import repeat
from binascii import b2a_hex
from multiprocessing import Pool, Queue

import netaddr
from Crypto import Random
from scapy.all import *



def get_tcp_seq(validation):
    return struct.unpack('>I', validation[:4])[0]


def get_src_port(dport, validation):
    return (struct.unpack('>I', validation[-4:])[0] + dport) % 0x10000


def check_dport(dport, validation):
    return dport == struct.unpack('>I', validation[-4:])[0] % 0x10000


def args_storage(**kw_store):
    def decorator(func):
        def wrapper(pkt, *args, **kwargs):
            return func(pkt, *args, **kw_store, **kwargs)
        return wrapper
    return decorator


def synscan_check_pkt(pkt, sport_lst, validation):
    if not TCP in pkt:
        return False
    if pkt[TCP].sport not in sport_lst:
        return False
    pkt.show()
    return True
    if not check_dport(pkt[TCP].dport, validation):
        return False
    if pkt[TCP].ack != struct.unpack('>I', validation[:4])[0] + 1:
        return False
    return True


def on_ack(pkt):
    print(pkt.sprintf('[+] %IP.src%:%IP.sport% open'))


def pkt_send(dst, dport, validation, **kwargs):
    print('[*] scanning {0}'.format(dst))
    tcp_seq = get_tcp_seq(validation)
    tcp_sport = get_src_port(dport, validation)
    pkt = IP(dst=str(dst)) / TCP(flags='S', seq=tcp_seq, sport=tcp_sport, dport=dport)
    send(pkt, **kwargs)


def pkt_recv(sport_lst, validation):
    # synscan_filter = args_storage(sport_lst=sport_lst, validation=validation)(synscan_check_pkt)
    # sniff(lfilter=synscan_filter, prn=on_ack)
    valid_ack = get_tcp_seq(validation) + 1
    synscan_filter = 'tcp and tcp[8:4] == {0}'.format(valid_ack)
    sniff(filter=synscan_filter, prn=on_ack)


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument('host', action='store', type=check_host)
    parser.add_argument('-p', '--port', action='store', dest='ports', type=check_ports, required=True,
                        help='specify ports')
    parser.add_argument('-n', '--process', action='store', dest='process', type=check_process, default=1,
                        help='set process number')
    parser.add_argument('-i', '--interval', action='store', dest='interval', type=int, default=0,
                        help='set sending interval')
    parser.add_argument('-v', '--verbose', action='store_true', dest='verbose', default=False,
                        help='show verbose')
    results = parser.parse_args()
    return results


def check_host(value):
    if not netaddr.valid_nmap_range(value):
        raise argparse.ArgumentTypeError('invalid host value: {0!r}'.format(value))
    return netaddr.iter_nmap_range(value)


def check_ports(value):
    try:
        if ',' in value:
            val_chk = map(lambda p: p.isdigit() and 0 < int(p) < 0x10000, value.split(','))
            if not all(val_chk):
                raise ValueError
            else:
                value = list(map(int, value.split(',')))
        elif '-' in value:
            val_chk = map(lambda p: p.isdigit() and 0 < int(p) < 0x10000, value.split('-'))
            if not all(val_chk):
                raise ValueError
            else:
                val_lst = list(map(int, value.split('-')))
                if len(val_lst) != 2 or val_lst[0] > val_lst[1]:
                    raise ValueError
                else:
                    value = list(range(val_lst[0], val_lst[1]+1))
        else:
            if not value.isdigit() or int(value) < 0 or int(value) > 0x10000:
                raise ValueError
            else:
                value = [int(value)]
    except ValueError:
        raise argparse.ArgumentTypeError('invalid ports value: {0!r}'.format(value))
    return value


def check_process(value):
    if not value.isdigit() or int(value) < 1:
        raise argparse.ArgumentTypeError('invalid process value: {0!r}'.format(value))
    return int(value)


def main():
    if os.geteuid() != 0:
        print('[!] please run as root')
        exit(1)

    args = parse_args()
    validation = Random.new().read(8)
    print('[+] validation: {0}'.format(b2a_hex(validation)))

    pool = Pool(args.process+1)
    pool.apply_async(pkt_recv, args=(args.ports, validation))
    for host in args.host:
        for dport in args.ports:
            pool.apply_async(pkt_send, args=(host, dport, validation), kwds={'verbose': args.verbose})
    pool.close()
    pool.join()


if __name__ == '__main__':
    main()
