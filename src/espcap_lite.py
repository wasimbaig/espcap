#!/usr/bin/env python

import os
import sys
import click
import pyshark

from elasticsearch import Elasticsearch
from elasticsearch import helpers

def list_interfaces():
    proc = os.popen("tshark -D")  # Note tshark must be in $PATH
    tshark_out = proc.read()
    interfaces = tshark_out.splitlines()
    for i in range(len(interfaces)):
        interface = interfaces[i].strip(str(i+1)+".")
        print interface

def get_ip_version(packet):
    for layer in packet.layers:
        if layer._layer_name == 'ip':
            return 4
        elif layer._layer_name == 'ipv6':
            return 6

def dump_packets(capture):
    i = 1
    for packet in capture:
        if packet.transport_layer == 'TCP':
            ip = None
            ip_version = get_ip_version(packet)
            if ip_version == 4:
                ip = packet.ip
            elif ip_version == 6:
                ip = packet.ipv6
            print 'Packet %d' % i
            print 'Source IP        -', ip.src
            print 'Source port      -', packet.tcp.srcport
            print 'Destination IP   -', ip.dst
            print 'Destination port -', packet.tcp.dstport
            print
        i += 1

def index_packets(capture):
    for packet in capture:
        if packet.transport_layer == 'TCP':
            ip = None
            ip_version = get_ip_version(packet)
            if ip_version == 4:
                ip = packet.ip
            elif ip_version == 6:
                ip = packet.ipv6
            action = {
                '_op_type': 'index',
                '_index': 'packets_lite',
                '_type': 'test',
                '_source': {
                   'srcip' : ip.src,
                   'srcport' : packet.tcp.srcport,
                   'dstip' : ip.dst,
                   'dstport' : packet.tcp.dstport
                }
            }
            yield action

@click.command()
@click.option('--node', default=None, help='Elasticsearch IP and port (default=None)')
@click.option('--nic', default=None, help='Network interface for live capture (default=None, if file specified)')
@click.option('--file', default=None, help='PCAP file for file capture (default=None, if nic specified)')
@click.option('--list', is_flag=True, help='List the network interfaces')
def main(node, nic, file, list):
    if list:
        list_interfaces()
        sys.exit(0)
    elif nic == None and file == None:
        print 'You must specify either a network interface or packet capture file'
        sys.exit(1)

    capture = None
    if nic == None:
        capture = pyshark.FileCapture(file)
    elif file == None:
        capture = pyshark.LiveCapture(nic)

    if node == None:
        dump_packets(capture)
    else:
        es = Elasticsearch(node)
        helpers.bulk(es, index_packets(capture), chunk_size=100, raise_on_error=True)

if __name__ == '__main__':
    main()
