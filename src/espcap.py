#!/usr/bin/env python

import getopt
import os
import signal
import sys
import traceback
from datetime import datetime

import pyshark
from elasticsearch import Elasticsearch
from elasticsearch import helpers

supported_protocols = {}

# Get supported application protocols
def get_protocols():
    global supported_protocols
    fp = None
    if os.path.isfile('./protocols.list'):
        fp = open('./protocols.list')
    elif os.path.isfile('../conf/protocols.list'):
        fp = open('../conf/protocols.list')
    elif os.path.isfile('conf/protocols.list'):
        fp = open('conf/protocols.list')
    protocols = fp.readlines()
    for protocol in protocols:
        protocol = protocol.strip()
        supported_protocols[protocol] = 1

# Get application level protocol
def get_highest_protocol(packet):
    global supported_protocols
    if not supported_protocols:
        get_protocols()
    for layer in reversed(packet.layers):
        if layer.layer_name in supported_protocols:
            return layer.layer_name
    return 'wtf'

# Get the protocol layer fields
def get_layer_fields(layer):
    layer_fields = {}
    for field_name in layer.field_names:
        if len(field_name) > 0:
            layer_fields[field_name] = getattr(layer, field_name)
    return layer_fields

# Returns a dictionary containing the packet layer data
def get_layers(packet):
    n = len(packet.layers)
    highest_protocol = get_highest_protocol(packet)
    layers = {}

    # Link layer
    layers[packet.layers[0].layer_name] = get_layer_fields(packet.layers[0])
    layer_above_transport = 0

    # Get the rest of the layers
    for i in range(1,n):
        layer = packet.layers[i]

        # Network layer - ARP
        if layer.layer_name == 'arp':
            layers[layer.layer_name] = get_layer_fields(layer)
            return highest_protocol, layers

        # Network layer - IP or IPv6
        elif layer.layer_name == 'ip' or layer.layer_name == 'ipv6':
            layers[layer.layer_name] = get_layer_fields(layer)

        # Transport layer - TCP, UDP, ICMP, IGMP, IDMP, or ESP
        elif layer.layer_name == 'tcp' or layer.layer_name == 'udp' or layer.layer_name == 'icmp' or layer.layer_name == 'igmp' or layer.layer_name == 'idmp' or layer.layer_name == 'esp':
            layers[layer.layer_name] = get_layer_fields(layer)
            if highest_protocol == 'tcp' or highest_protocol == 'udp' or highest_protocol == 'icmp' or highest_protocol == 'esp':
                return highest_protocol, layers
            layer_above_transport = i+1
            break

        # Additional transport layer data
        else:
            layers[layer.layer_name] = get_layer_fields(layer)
            layers[packet.layers[i].layer_name]['envelope'] = packet.layers[i-1].layer_name

    for j in range(layer_above_transport,n):
        layer = packet.layers[j]

        # Application layer
        if layer.layer_name == highest_protocol:
            layers[layer.layer_name] = get_layer_fields(layer)

        # Additional application layer data
        else:
            layers[layer.layer_name] = get_layer_fields(layer)
            layers[layer.layer_name]['envelope'] = packet.layers[j-1].layer_name

    return highest_protocol, layers

# Index packets in Elasticsearch
def index_packets(capture, pcap_file, file_date_utc):
    for packet in capture:
        highest_protocol, layers = get_layers(packet)
        sniff_timestamp = float(packet.sniff_timestamp) # use this field for ordering the packets in ES
        action = {
            '_op_type' : 'index',
            '_index' : 'packets-'+datetime.utcfromtimestamp(sniff_timestamp).strftime('%Y-%m-%d'),
            '_type' : 'pcap_file',
            '_source' : {
                'file_name' : pcap_file,
                'file_date_utc' : file_date_utc.strftime('%Y-%m-%dT%H:%M:%S'),
                'sniff_date_utc' : datetime.utcfromtimestamp(sniff_timestamp).strftime('%Y-%m-%dT%H:%M:%S'),
                'sniff_timestamp' : sniff_timestamp,
                'protocol' : highest_protocol,
                'layers' : layers
            }
        }
        yield action

# Dump raw packets to stdout
def dump_packets(capture, file_date_utc):
    pkt_no = 1
    for packet in capture:
        highest_protocol, layers = get_layers(packet)
        sniff_timestamp = float(packet.sniff_timestamp)
        print 'packet no.', pkt_no
        print '* protocol        -', highest_protocol
        print '* file date UTC   -', file_date_utc.strftime('%Y-%m-%dT%H:%M:%S')
        print '* sniff date UTC  -', datetime.utcfromtimestamp(sniff_timestamp).strftime('%Y-%m-%dT%H:%M:%S')
        print '* sniff timestamp -', sniff_timestamp
        print '* layers'
        for key in layers:
            print '\t', key, layers[key]
        print
        pkt_no += 1

# Live capture function
def live_capture(nic, bpf, node, chunk, count, trace):
    try:
        es = None
        if (node != None):
            es = Elasticsearch(node)

        sniff_date_utc = datetime.utcnow()
        if bpf == None:
            capture = pyshark.LiveCapture(interface=nic)
        else:
            capture = pyshark.LiveCapture(interface=nic, bpf_filter=bpf)

        # Dump or index packets based on whether an Elasticsearch node is available
        if node == None:
            dump_packets(capture, sniff_date_utc, count)
        else:
            helpers.bulk(es,index_packets(capture, sniff_date_utc, count), chunk_size=chunk, raise_on_error=True)

    except Exception as e:
        print '[ERROR] ', e
        if trace == True:
            traceback.print_exc(file=sys.stdout)

# File capture function
def file_capture(pcap_files, node, chunk, trace):
    try:
        es = None
        if node != None:
            es = Elasticsearch(node)

        print 'Loading packet capture file(s)'
        for pcap_file in pcap_files:
            print pcap_file
            stats = os.stat(pcap_file)
            file_date_utc = datetime.utcfromtimestamp(stats.st_ctime)
            capture = pyshark.FileCapture(pcap_file)

            # If no Elasticsearch node specified, dump to stdout
            if node == None:
                dump_packets(capture, file_date_utc)
            else:
                helpers.bulk(es, index_packets(capture, pcap_file, file_date_utc), chunk_size=chunk, raise_on_error=True)

    except Exception as e:
        print '[ERROR] ', e
        if trace == True:
            traceback.print_exc(file=sys.stdout)

# Returns list of network interfaces (nic)
def list_interfaces():
    proc = os.popen('tshark -D')  # Note tshark must be in $PATH
    tshark_out = proc.read()
    interfaces = tshark_out.splitlines()
    for i in range(len(interfaces)):
        interface = interfaces[i].strip(str(i+1)+'.')
        print interface

def command_line_options():
    print 'espcap.py [--dir=pcap_directory] [--node=elasticsearch_host] [--chunk=chunk_size] [--trace]'
    print '          [--file=pcap_file] [--node=elasticsearch_host] [--chunk=chunk_size] [--trace]'
    print '          [--nic=interface] [--node=elasticsearch_host] [--bpf=packet_filter_string] [--chunk=chunk_size] [--count=max_packets] [--trace]'
    print '          [--help]'
    print '          [--list-interfaces]'

def example_usage():
    command_line_options()
    print
    print 'Example command line option combinations:'
    print 'espcap.py --dir=/home/pcap_directory --node=localhost:9200'
    print 'espcap.py --file=./pcap_file --node=localhost:9200 --chunk=1000'
    print 'espcap.py --nic=eth0 --node=localhost:9200 --bpf=\'tcp port 80\' --chunk=2000'
    print 'espcap.py --nic=en0 --node=localhost:9200 --bpf=\'udp port 53\' --count=500'
    sys.exit()

def usage():
    command_line_options()
    sys.exit()

def fine_print():
    print 'You must specify only one of the following input modes:'
    print '[--dir=pcap_directory]'
    print '[--file=pcap_file]'
    print '[--nic=nic]'
    print 'Run \'espcap.py --help\' for more info'
    sys.exit()

def doh(error):
    print error
    sys.exit(2)

def interrupt_handler(signum, frame):
    print
    print('Packet capture interrupted')
    print 'Done'
    sys.exit()

def main():
    if len(sys.argv) == 1:
        usage()
    try:
        opts,args = getopt.gnu_getopt(sys.argv[1:], '', ['trace','dir=','file=','nic=','node=','bpf=','chunk=','count=','help','list-interfaces'])
    except getopt.GetoptError as error:
        print str(error)
        usage()

    pcap_files = []
    pcap_dir = None
    pcap_file = None
    nic = None
    node = None
    bpf = None
    trace = False
    count = 0
    chunk = 100
    for opt, arg in opts:
        if opt == '--help':
            example_usage()
        elif opt == '--dir':
            if pcap_file == None and nic == None:
                pcap_dir = arg
            else:
                fine_print()
        elif opt == '--file':
            if pcap_dir == None and nic == None:
                pcap_file = arg
            else:
                fine_print()
        elif opt == '--nic':
            if pcap_file == None and pcap_dir == None:
                nic = arg
            else:
                fine_print()
        elif opt == '--node':
            node = arg
        elif opt == '--bpf':
            bpf = arg
        elif opt == '--chunk':
            chunk = int(arg)
        elif opt == '--count':
            count = int(arg)
        elif opt == '--trace':
            trace = True
        elif opt == '--list-interfaces':
            list_interfaces()
            sys.exit()
        else:
            doh('Unhandled option '+opt)

    # Bail if no nic or input file has been specified
    if nic == None and pcap_dir == None and pcap_file == None:
        fine_print()

    # Enables interrupting of continuous live capture
    signal.signal(signal.SIGINT, interrupt_handler)

    # Handle multiple pcap files in the given directory
    if pcap_dir != None:
        files = os.listdir(pcap_dir)
        files.sort()
        for file in files:
            if pcap_dir.find('/') > 0:
                pcap_files.append(pcap_dir+file)
            else:
                pcap_files.append(pcap_dir+'/'+file)
        file_capture(pcap_files, node, chunk, trace)

    # Handle only the given pcap file
    elif pcap_file != None:
        pcap_files.append(pcap_file)
        file_capture(pcap_files, node, chunk, trace)

    # Capture and handle packets off the wire
    else:
        live_capture(nic, bpf, node, chunk, count, trace)

if __name__ == '__main__':
    main()
    print 'Done'