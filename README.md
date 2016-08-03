# PCAP Search


pacman -S nodejs

## Introduction

### `pcap2ap`: extract TCP/UDP streams from `.cap` to `.cap.ap`

Implement a [Dshell] plugin `dshell-defcon/dshell-decode` to split a `.cap` to several streams and reassemble them into a `.cap.ap` file.
A `.cap.ap` file is a concatenation of its streams, where each stream is composed of packets laid out in order. This format makes searching across packet boundary easier.

Dshell Prerequisites: `pip2 install --user dpkt pypcap`

See [./dshell-defcon/README.md] for detail.

`pcap2ap` is a shell wrapper of `dshell-decode`. It watches (inotify) `.cap` files in one or multiple directories and transforms them into `.cap.ap` files.

`pcap2ap` prerequisites: `bc, inotify-tools`

### `indexer -i`: build a full-text index `.cap.ap.fm` for each `.cap.ap`

`indexer` is a standalone compressed full-text string index based on FM-index. It has two modes: server mode and index mode. `indexer` running in index mode watches (inotify) data files in one or more directories and builds `.fm` indices for them.

### `indexer`: loading index files and serve search requests

`indexer` running in server mode watches `.fm` indices in one or more directories and acts as a unix socket server supporing auto complete and search. For both types of queries, it scans watched `.fm` indices and locates the needle in the data files.

### `web`: integrate `indexer` and the Dshell plugin

`web/web.rb` is a web application built upon Sinatra.

## Usage

```bash
mkdir -p /tmp/pcap/{all,eliza,wdub}
touch /tmp/pcap/all/a.cap
touch /tmp/pcap/wdub/a.cap
./pcap2ap /tmp/pcap &
./indexer -i /tmp/pcap &
./indexer /tmp/pcap &
web/web.rb
```

[Dshell]: https://github.com/USArmyResearchLab/Dshell



int32: number of sessions

struct {
  i32 n_sessions;
  Session sessions[];
};

struct Session {
  i32 n_packets;
  i32 server_ip;
  i32 server_port;
  i32 client_ip;
  i32 client_port;
  i32 first_timestamp;
  i32 last_timestamp;
  Packet packets[];
};

struct Packet {
  bool from_server;
  i32 len;
};
