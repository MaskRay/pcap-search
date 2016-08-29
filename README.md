# PCAP Search

PCAP Search is a full-text substring search engine based on FM-index and other
succinct data structures.

## Installation

```
# dependencies of dshell
pip2 install --user dpkt pypcap

# dependencies of pcap2ap
# bc, inotify-tools

# dependencies of web/web.rb
gem install --user-install sinatra sinatra-contrib tilt sass slim coffee-script
# nodejs
```

## Usage

```zsh
mkdir -p /tmp/pcap/{all,eliza,wdub}

# create /tmp/pcap/all/a.cap with tcpdump/tshark
# create /tmp/pcap/wdub/a.cap with tcpdump/tshark

# Transform .cap files into .cap.ap files
# This intermediate format removes redundant metadata in PCAP/PCAPNG
# and is used for locating a specific packet in PCAP/PCAPNG files.
./pcap2ap -r /tmp/pcap &

# Transform .cap.ap files into .cap.ap.fm files
./indexer -r /tmp/pcap &
```

`indexer` search for `.ap` files in a directory, index them, and listen on a
unix socket (`/tmp/search.sock` by default) to serve search queries.

Two types of search queries are provided: search and autocomplete.

### Search

The simplest query is constructed with `$'\0\0\0haystack'` (zsh's quoting
notation). `indexer` will print all the occurrences of `haystack` in all
its indexed `.ap` files. You can restrict `.ap` files to be searched
by providing the filename range: `\0 $filename_begin \0 $filename_end
\0 $query`.

`print` is a builtin command in zsh.

```zsh
query: \0 filename_begin \0 filename_end \0 query
result: filename \t offset \t context

# pattern is haystack
print -rn -- $'\0\0\0haystack' | socat -t 60 - unix:/tmp/search.sock
```

### Autocomplete

A search query can be turned into an autocomplete query by supplying an offset
number before the first `\0`.

```zsh
query: offset \0 filename_begin \0 filename_end \0 query
result: filename \t offset \t context

# search, skip first 3 matches
print -rn -- $'3\0\0\0haystack' | socat -t 60 - unix:/tmp/search.sock

# search filenames F satisfying ("a" <= F <= "b"), skip first 5, pattern is "stack\0\0\1". \-escape is allowed
print -rn -- $'5\0a\0b\0ha\0stack\0\\0\\1' | socat -t 60 - unix:/tmp/search.sock
```

### Web frontend

```zsh
# change `PCAP_DIR = File.expand_path '/tmp/pcap'` in `web/web.rb`
web/web.rb
```

The web server will listen on 127.0.0.1:4568.

## Internals

### `pcap2ap`: extract TCP/UDP streams from `.cap` to `.cap.ap`

Implement a [Dshell] plugin `dshell-defcon/dshell-decode` to split a `.cap` to several streams and reassemble them into a `.cap.ap` file.
A `.cap.ap` file is a concatenation of its streams, where each stream is composed of packets laid out in order. This format makes searching across packet boundary easier.

See [./dshell-defcon/README.md](./dshell-defcon/README.md) for detail.

`pcap2ap` is a shell wrapper of `dshell-decode`. It watches (inotify) `.cap` files in one or multiple directories and transforms them into `.cap.ap` files.

### `indexer`: build a full-text index `.cap.ap.fm` for each `.cap.ap` and serve requests

`indexer` watches `.fm` indices in one or more directories and acts as a unix socket server supporing auto complete and search. For both types of queries, it scans watched `.fm` indices and locates the needle in the data files.

### `web`: integrate `indexer` and the Dshell plugin

`web/web.rb` is a web application built upon Sinatra.

### `web/web.rb`

[Dshell]: https://github.com/USArmyResearchLab/Dshell

## `.ap` file specification

```c
struct Ap {
  int32_t n_sessions;
  Session sessions[];
};

struct Session {
  int32_t n_packets;
  int32_t server_ip;
  int32_t server_port;
  int32_t client_ip;
  int32_t client_port;
  int32_t first_timestamp;
  int32_t last_timestamp;
  Packet packets[];
};

struct Packet {
  bool from_server;
  int32_t len;
};
```

### `.fm` file specification

```c
struct FM {
  char magic[8]; // GOODMEOW
  off_t len;
  // serialization of struct FMIndex
};
```
