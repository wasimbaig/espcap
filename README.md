# Espcap

__Espcap__ is a program that uses Pyshark to capture packets from a pcap file or live
from a network interface and index them with Elasticsearch.  Since __Espcap__ uses
Pyshark - which provides a wrapper API to tshark - it can use wireshark dissectors
to parse any protocol.

## Requirements

1. Python 2.7.10 or greater 
2. tshark (included in Wireshark)
2. Pyshark 0.3.5
3. trollius 1.0.4
4. Elasticsearch client for Python
5. click (for command line processing)

## Recommendations

The easiest way to experiment with this or any other Python project is to use virtualenv and virtualenvwrapper to run __Espcap__ in a virtual environment. With that in mind I have included instructions for installing  these tools.

## Installation

1. Install Wireshark for your OS.
2. Install virtualenv then virtualenvwrapper:
  
   ```
   pip install virtualenv
   pip install virtualenvwrapper
   ```

3. Add this section of code to your `.bash_profile`:

   ```
   if [[ -r /usr/local/bin/virtualenvwrapper.sh ]]; then
      source /usr/local/bin/virtualenvwrapper.sh
   else
      echo "WARNING: Can't find virtualenvwrapper.sh"
   fi

   ```
4. Then source your `.bash_profile`:

   ```
   source $HOME/.bash_profile
   ```
5. Create a virtual environment for __Espcap__ called `vespcap` (or some other name you prefer) like this:

   ```
   mkvirtualenv vespcap
   ```
   Note that this will put you into the `vespcap` virtual environment. To leave this environment just type:

   ```
   deactivate
   ```
   To re-activate this environment to run __Espcap__ later type:

   ```
   workon vespcap
   ```
6. Install the required Python modules:

   ```
   pip install -r requirements.txt
   ```

7. Clone the __Espcap_ repo then cd into the `espcap` directory. 
8. Create the packet index template by running `scripts/templates.sh` as follows specifying the node IP address and TCP port of your Elasticsearch instance (localhost:9200 in this example):

   ```
   scripts/templates.sh localhost:9200
   ```
  
9. Set the tshark_path variable in the `pyshark/config.ini` file.
10. Run `espcap.py` to index some packet data in Elasticsearch:
  
    ```
    src/espcap.py --file=test_pcaps/test_http.pcap --node=localhost:9200
    ```
  
11. Run `packet_query.sh` as follows to check that the packet data resides in your Elasticsearch instance:
  
    ```
    scripts/packet_query.sh localhost:9200
    ```

## Running Examples

+ You must run these examples in your __Espcap__ directory and virtual environment, so activate your virtual environment first. Assuming you called your virtual environment `vespcap` run this command:

  ```
  workon vespcap
  ```

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
  
+ Load the test packet capture files and index the packets in the Elasticsearch cluster running at 10.0.0.1:9200, assuming your present working directory is `espcap/src`:

  ```
  espcap.py --dir=../test_pcaps --node=10.0.0.1:9200
  ```
  
+ Same as the previous except load the `test_pcaps/test_http.pcap` file:
  
  ```
  espcap.py --file=../test_pcaps/test_http.pcap --node=10.0.0.1:9200
  ```
  
+ Do a live capture from the network interface `eth0`, get all packets and index them in the Elasticsearch cluster running at 10.0.0.1:9200:
  
  ```
  espcap.py --nic=eth0 --node=10.0.0.1:9200
  ```
  
+ Same as the previous except dump the packets to `stdout``:
  
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
index naming format is _packets-yyyy-mm-dd_. The date is UTC derived from the packet sniff
timestamp obtained from pyshark either for live captures or the sniff timestamp read from pcap 
files. Each index has two types, one for live capture `pcap_live` and file capture `pcap_file`. 
Both types are dynamically mapped by Elasticsearch with exception of the date fields for either 
`pcap_file` or `pcap_live` types which are mapped as Elasticsearch date fields if 
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

The `pcap_live` type is comprised of the same fields except the _file_name_ and _file_date_utc_ 
fields.

## Packet Layer Structure

Packet layers reside in a JSON section called `layers`. Each of the layers reside in a JSON 
that has the name of the protocol for that layer. The highest protocol for the whole packet, 
which is the application protocol if the packet has such a layer, is indicate by the `protocol` 
field that is at the sam level as the `layers` section.

Note that the highest level protocol present in any given packet is indicated by the `protocol`
field. For packets lacking an application level protocol,
the protocol will be set to the transport, network, or link protocol name. For example, a TCP
SYN packet would have the protocol field set to `tcp`.

The convention for accessing protocol fields in the JSON layers structure is:

```
layers.protocol.field
```

Here are some examples of how to reference specific layer fields taken from the packet JSON 
shown above:

```
layers.ip.src             Sender IP address
layers.ip.dst             Receiver IP address
layers.tcp.srcport        Sender TCP port
layers.udp.dstport        Receiver UDP port
layers.http.chat          HTTP response
```

## Protocol Support

Technically __Espcap__ recognizes all the protocols supported by wireshark/tshark. However, 
the wiresharkdissectors create some layers that are not truly protocols but rather are special 
cases such as malformed packets.  __Espcap__ uses the `excluded_protocols.list` to prevent these 
layers created by tshark from  included for consideration as the application level protocol for 
any given packet.

If you want to see a complete list of protocols supported by tshark, run:

```
conf/protocols.sh
```

If you see other protocols that you want to exclude from being considered as application level 
protocols, add the from the list produced by this script to the `conf/excluded_protocols.list` 
file.

## Known Issues

1. Not all _ws.* layers are mapped to descriptive terms, except for _ws.expert.
2. __Espcap__ has not yet been tested on Python 3.x.

## Changelog

	0.1     - Converted _ws.* layer names to _ws-* which is compatible with Elasticsearch 2.x field
	          naming requirements. 
	        - Renamed _ws.expert layer name to `[Malformed_Packet]`
	        - Use `conf/excluded_protocols` to identify tshark expert layers that are not really
	          protocols