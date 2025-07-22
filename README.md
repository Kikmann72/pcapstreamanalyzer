# pcapstreamanalyzer

This tool parses sequence numbers of multicast data streams inside a pcap.

Each stream is considered to be transmited on an individual mutlicast group (ip + port) and has the sequence number in a fixed position. For the situation that there are multiple sequence number ranges inside one stream (e.g. multiple publishers), a fixed position of a senderid is supported and sequence numbers are considered per senderid.

[![License](https://img.shields.io/badge/license-MIT-blue.svg)](https://raw.githubusercontent.com/Kikmann72/pcapstreamanalyzer/master/LICENSE)

## Usage

```
usage: pcapstreamanalyzer [-d] -x streamdefs pcap 

  -x          stream definitions file
  -d          debug
```
and the streams definitions file has comma separated entries like

```
# multicast address, port, name, seqno pos, seqno length, seqno needsbswap, senderid pos, senderid length, senderid needsbswap
224.0.50.80, 59500, some stream, 4, 4, 1, 3, 1, 0
```

where
* _seqno pos, senderid pos_ - are the byte position of the field in the packet (first byte of packet is 0)
* _seqno length, senderid length_ - are the length of the fields in bytes (1,2,4,8)
* _seqno needsbswap, senderid needsbswap_ - is a flag whether a bswap is required on the data (0,1)

If there is no senderid, set all senderid fields to 0.


## Example

```
$ pcapstreamanalyzer -x mystreams.def example.pcap
```

where the mystreams.def file is the definition of the data streams

## Building & Installing

*pcapstreamanalyzer* requires [CMake](https://cmake.org/) 3.2 or higher,  
g++ and libpcap-dev to build and install.

Building on Debian/Ubuntu:

```
sudo apt install cmake libpcap-dev g++
cd pcapstreamanalyzer
mkdir build && cd build
cmake ..
make
```

Building on RHEL/CentOS:

```
sudo yum install cmake3 libpcap-devel gcc-c++
cd pcapstreamanalyzer
mkdir build && cd build
cmake3 ..
make
```


## About

This project was created by <[kikmann72](mailto:kikman@gmx.de)>.

This work is based on the original udpreplay from Erik Rigtorp (http://rigtorp.se) but heavily stripped.
