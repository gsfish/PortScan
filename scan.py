#!/usr/bin/env python
# -*- coding: utf-8 -*-

import random
import struct
import argparse
from itertools import repeat
from binascii import b2a_hex
from multiprocessing import Pool, Queue

import netaddr
from Crypto import Random
from Crypto.Cipher import AES
from scapy.all import *


res_queue = Queue()


def aes_enc(plain, key, iv):
    cryptor = AES.new(key, AES.MODE_CBC, iv)
    cipher = cryptor.encrypt(plain)
    return cipher


def aes_dec(cipher, key, iv):
    cryptor = AES.new(key, AES.MODE_CBC, iv)
    plain = cryptor.decrypt(cipher)
    return plain


def pad(raw, block_size, val):
    pad_len = block_size - (len(raw) % block_size)
    if pad_len % block_size == 0:
        padded = raw
    else:
        padded = raw + bytearray([val] * pad_len)
    return padded


def validation_gen(dst, key, iv):
    b_src = b'\x7f\x00\x00\x01'
    b_dst = struct.pack(">I", int(hex(dst),16))
    padded = pad(b_src+b_dst, AES.block_size, 0)
    validation = aes_enc(padded, key, iv)
    return validation


def get_src_port(validation):
    return struct.unpack('>I', validation[-4:])[0] % 0x10000


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
    if not check_dport(pkt[TCP].dport, validation):
        return False
    if pkt[TCP].ack != struct.unpack('>I', validation[:4])[0] + 1:
        return False
    return True


@args_storage(queue=res_queue)
def on_ack(pkt, queue):
    # print(pkt.sprintf('[+] %IP.src%:%IP.sport% open'))
    queue.put((pkt[IP].src, pkt[IP].sport))


def pkt_send(dst, dport, validation, **kwargs):
    tcp_seq = struct.unpack('>I', validation[:4])[0]
    tcp_sport = get_src_port(validation)
    pkt = IP(dst=str(dst)) / TCP(flags='S', seq=tcp_seq, sport=tcp_sport, dport=dport)
    send(pkt, **kwargs)


def pkt_recv(sport_lst, validation):
    synscan_filter = args_storage(sport_lst=sport_lst, validation=validation)(synscan_check_pkt)
    sniff(lfilter=synscan_filter, prn=on_ack)


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
    args = parse_args()

    val_key = Random.new().read(32)
    print('[+] val_key:{0}'.format(b2a_hex(val_key)))

    aes_key = Random.new().read(16)
    aes_iv = Random.new().read(16)
    print('[+] aes_key:{0} aes_iv:{1}'.format(b2a_hex(aes_key), b2a_hex(aes_iv)))

    pool = Pool(args.process+1)
    for host in args.host:
        print('[*] scanning {0}'.format(host))
        validation = validation_gen(host, aes_key, aes_iv)
        pool.apply_async(pkt_recv, args=(args.ports, validation))
        for dport in args.ports:
            pool.apply_async(pkt_send, args=(host, dport, validation), kwds={'inter': args.interval, 'verbose': args.verbose})
    print('[*] receiving')
    while True:
        res = res_queue.get()
        print('[+] {0}:{1} open'.format(res[0], res[1]))


if __name__ == '__main__':
    main()
