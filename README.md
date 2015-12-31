# Espcap

__Espcap__ is a program that uses Pyshark to capture packets from a pcap file or live
from a network interface and index them with Elasticsearch.  Since __Espcap__ uses
Pyshark - which provides a wrapper API to tshark - it can use wireshark dissectors
to parse any protocol.

## Requirements

1. Python 2.7.10 (note that Espcap has not been tested on Python 3.x yet)
2. tshark (included in Wireshark)
2. Pyshark 0.3.5
3. trollius 1.0.4
4. Elasticsearch client for Python
5. click (for command line processing)

## Recommendations

It is highly recommended, although not required, that you use the Anaconda Python 
distribution by Continuum Analytics for __Espcap__. This distribution contains Python
2.7.x and bundles a rich set of programming packages for analytics and machine 
learning.  You can download Anaconda Python here: http://continuum.io/downloads.

## Installation

1. Install Wireshark for your OS.</li>
2. Install Pyshark, trollius, and the Elasticsearch client for Python with pip:
<pre>
pip uninstall pyshark
pip install pyshark==0.3.5
pip uninstall trollius
pip install trollius==1.0.4
pip install elasticsearch
pip install click
</pre>
3. Clone the espcap repo then cd into the espcap directory.
4. Create the packet index template by running scripts/templates.sh as follows specifying the node IP address and TCP port of yoru Elasticsearch instance (localhost:9200 in this example):

  ```
  scripts/templates.sh localhost:9200
  ```
  
5. Set the tshark_path variable in the <tt>pyshark/config.ini</tt> file.
6. Run <tt>espcap.py</tt> to index some packet data in Elasticsearch:
  
  ```
  src/espcap.py --file=test_pcaps/test_http.pcap --node=localhost:9200
  ```
  
7. Run <tt>packet_query.sh</tt> as follows to check that the packet data resides in your Elasticsearch instance:
  
  ```
  scripts/packet_query.sh localhost:9200
  ```

## Running Examples

+ Display the following help message:
  
  ```
  espcap.py --help
  Usage: espcap.py [OPTIONS]
  
  Options:
    --node TEXT      Elasticsearch IP and port (default=None, dump packets to
                     stdout)
    --nic TEXT       Network interface for live capture (default=None, if file
                     or dir specified)
    --file TEXT      PCAP file for file capture (default=None, if nic specified)
    --dir TEXT       PCAP directory for multiple file capture (default=None, if
                     nic specified)
    --bpf TEXT       Packet filter for live capture (default=all packets)
    --chunk INTEGER  Number of packets to bulk index (default=1000)
    --count INTEGER  Number of packets to capture during live capture
                     (default=0, capture indefinitely)
    --list           List the network interfaces
    --help           Show this message and exit.
  ```
  
+ Load the test packet capture files and index the packets in the Elasticsearch cluster running at 10.0.0.1:9200, assuming your present working directory is espcap/src:

  ```
  espcap.py --dir=../test_pcaps --node=10.0.0.1:9200
  ```
  
+ Same as the previous except load the test_pcaps/test_http.pcap file:
  
  ```
  espcap.py --file=../test_pcaps/test_http.pcap --node=10.0.0.1:9200
  ```
  
+ Do a live capture from the network interface <tt>eth0</tt>, get all packets and index them in the Elasticsearch cluster running at 10.0.0.1:9200:
  
  ```
  espcap.py --nic=eth0 --node=10.0.0.1:9200
  ```
  
+ Same as the previous except dump the packets to stdout:
  
  ```
  espcap.py --nic=eth0 
  ```
  
+ Do a live capture of TCP packets with source port or destination port == 80 and index in Elasticsearch running at 10.0.0.1:9200:
  
  ```
  espcap.py --nic=eth0 --bpf='tcp port 80' --node=10.0.0.1:9200
  ```
  
+ List the network interfaces
  
  ```
  espcap.py --list 
  ```

## Packet Indexing

### Time Series Indexing

When indexing packet captures into Elasticsearch, an new index is created for each day. The 
index naming format is <i>packets-yyyy-mm-dd</i>. The date is UTC derived from the packet sniff 
timestamp obtained from pyshark either for live captures or the sniff timestamp read from pcap 
files. Each index has two types, one for live capture <tt>pcap_live</tt> and file capture <tt>pcap_file</tt>. 
Both types are dynamically mapped by Elasticsearch with exception of the date fields for either 
<tt>pcap_file</tt> or <tt>pcap_live</tt> types which are mapped as Elasticsearch date fields if 
you run the templates.sh script before indexing an packet data.

Index IDs are automatically assigned by Elasticsearch.

### pcap_file type fields

```
file_name          Name of the pcap file from whence the packets were read
file_date_utc      Creation date UTC when the pcap file was created
sniff_date_utc     Date UTC when the packet was read off the wire
sniff_timestamp    Time in milliseconds after the Epoch whne the packet was read
protocol           The highest level protocol
layers             Dictionary containing the packet contents
```

### pcap_live type fields

The <tt>pcap_live</tt> type is comprised of the same fields except the <i>file_name</i> and
<i>file_date_utc</i> fields.

## Packet Layer Structure

Packet layers are mapped in four basic sections based in protocol type within each index:

+ Link - link to the physical network media, usually Ethernet (eth).
+ Network - network routing layer which is always IP (ip).
+ Transport - transport layer which is either TCP (tcp) or UDP (udp).
+ Application - high level Internet protocol such as HTTP (http), DNS (dns), etc.

Packet layers reside in a JSON section called <tt>layers</tt>. Each of the layers reside in a JSON 
that has the name of the protocol for that layer. The highest protocol for the whole packet, which 
is the application protocol if the packet has such a layer, is indicate by the <tt>protocol</tt> 
field that is at the sam level as the <tt>layers</tt> section.

Below is an example of an HTTP packet as indexed in Elasticsearch.

```
{
    "_index": "packets-2015-07-30",
    "_type": "pcap_file",
    "_id": "AVAaipoMtaVU9i_NA682",
    "_score": null,
    "_source": {
        "layers": {
            "xml": {
                "xmlpi_encoding": "UTF-8",
                "attribute": "nonce=\"a234fb85622b87cd9c8626e57250ece56310f2de\"",
                "envelope": "http",
                "tag": "<query nonce=\"a234fb85622b87cd9c8626e57250ece56310f2de\">",
                "cdata": "A new version with bug fix is available! Click to update.",
                "xmlpi_xml": "<?xml version=\"1.0\" encoding=\"UTF-8\"?>",
                "xmlpi_version": "1.0"
            },
            "ip": {
                "checksum_bad": "0",
                "checksum_good": "0",
                "ttl": "41",
                "id": "52361",
                "dsfield": "32",
                "addr": "83.145.197.2",
                "proto": "6",
                "flags_rb": "0",
                "dst": "10.0.0.4",
                "version": "4",
                "flags_mf": "0",
                "dsfield_dscp": "8",
                "hdr_len": "20",
                "len": "1020",
                "dsfield_ecn": "0",
                "host": "83.145.197.2",
                "frag_offset": "0",
                "src": "83.145.197.2",
                "checksum": "24251",
                "flags_df": "1",
                "dst_host": "10.0.0.4",
                "flags": "2",
                "src_host": "83.145.197.2"
            },
            "eth": {
                "dst_resolved": "60:f8:1d:cb:43:84",
                "lg": "0",
                "addr": "60:f8:1d:cb:43:84",
                "src": "58:23:8c:b4:42:56",
                "addr_resolved": "60:f8:1d:cb:43:84",
                "dst": "60:f8:1d:cb:43:84",
                "type": "2048",
                "src_resolved": "58:23:8c:b4:42:56",
                "ig": "0"
            },
            "http": {
                "content_length": "637",
                "_ws_expert": "Expert Info (Chat/Sequence): HTTP/1.1 200 OK\\r\\n",
                "cache_control": "no-store, max-age=0",
                "response_code": "200",
                "time": "0.196748000",
                "server": "Apache",
                "response_phrase": "OK",
                "connection": "close",
                "response_line": "Date: Thu, 30 Jul 2015 05:22:11 GMT\\xd\\xa",
                "request_version": "HTTP/1.1",
                "content_encoding": "gzip",
                "chat": "HTTP/1.1 200 OK\\r\\n",
                "content_length_header": "637",
                "date": "Thu, 30 Jul 2015 05:22:11 GMT",
                "_ws_expert_group": "33554432",
                "response": "1",
                "content_type": "application/xml",
                "request_in": "62",
                "_ws_expert_message": "HTTP/1.1 200 OK\\r\\n",
                "_ws_expert_severity": "2097152"
            },
            "tcp": {
                "flags_cwr": "0",
                "checksum_bad": "0",
                "seq": "1",
                "flags_ecn": "0",
                "options_type_class": "0",
                "flags_syn": "0",
                "checksum_good": "0",
                "flags_reset": "0",
                "window_size_value": "57",
                "options_type_copy": "0",
                "analysis_initial_rtt": "0.197580000",
                "window_size": "7296",
                "stream": "3",
                "option_len": "10",
                "flags_urg": "0",
                "port": "80",
                "options_timestamp_tsecr": "387046361",
                "window_size_scalefactor": "128",
                "dstport": "59807",
                "hdr_len": "32",
                "options_type_number": "1",
                "len": "968",
                "flags_res": "0",
                "urgent_pointer": "0",
                "analysis_bytes_in_flight": "968",
                "flags_push": "1",
                "flags_ns": "0",
                "flags_ack": "1",
                "option_kind": "8",
                "ack": "707",
                "checksum": "41766",
                "flags_fin": "0",
                "srcport": "80",
                "analysis": "SEQ/ACK analysis",
                "flags": "24",
                "options_timestamp_tsval": "551709239",
                "nxtseq": "969",
                "options": "01:01:08:0a:20:e2:6a:37:17:11:db:d9",
                "options_type": "1"
            }
        },
        "protocol": "http",
        "sniff_timestamp": 1438233732.662099,
        "file_name": "../test_pcaps/test_http.pcap",
        "sniff_date_utc": "2015-07-30T05:22:12+0000",
        "file_date_utc": "2015-09-23T01:41:26+0000"
    }
}
```

The convention for accessing protocol fields in the JSON layers structure is:

```
layers.protocol.field
```

Here are some examples of how to reference specific layer fields taken from the packet JSON shown above:

```
layers.ip.src             Sender IP address
layers.ip.dst             Receiver IP address
layers.tcp.srcport        Sender TCP port
layers.udp.dstport        Receiver UDP port
layers.http.chat          HTTP response
```

Note that some layer protocols span two sections. In the above example, the HTTP layer has an <tt>xml</tt> 
section associated with it. Extra sections like these can be associated with their protocol sections by 
checking the <tt>envelope</tt> field contents.

## Protocol Support

Technically __Espcap__ recognizes all the protocols supported by wireshark/tshark. However, the wireshark
dissector set includes some strange protocols that are not really Internet protocols in the strictest
sense, but are rather parts of other protocols. One example is <tt>media</tt> which is actually used to
label an additional layer for the <tt>http</tt> protocol among other things. __Espcap__ uses the <tt>protocols.list</tt> 
to help determine the application level protocol in any given packet. This file is derived from tshark by 
running the <tt>protocols.sh</tt> script in the <tt>conf</tt> directory. To ensure that __Espcap__ has only 
true Internet protocols to choose from, the entries in <tt>protocols.list</tt> that are not truly Internet 
protocols have been commented out. Currently the commented out protocols include the following:

```
_ws.expert
_ws.lua
_ws.malformed
_ws.number_string.decoding_error
_ws.short
_we.type_length
_ws.unreassembled
data
data-l1-events
data-text-lines
image-gif
image-jfif
media
null
png
xml
zip
```

If there are any other protocols you believe should not be considered, then you can comment them out in 
this fashion. 

On the other hand If you get a little too frisky and comment out too many protocols or you just want to 
generate a fresh list, do the following:

1. Run <tt>protocols.sh</tt> script which produces a clean protocol list in <tt>protocols.txt</tt>.
2. Comment out the protocols in the list above and others you don't want to consider.
3. Replace the contents of <tt>protocols.list</tt> with the contents of <tt>protocols.txt</tt>.

### Known Issues

1. It appears that __Espcap__ does not work with Python versions less than 2.7.10.
2. __Espcap__ has not yet been tested on Python 3.x.
