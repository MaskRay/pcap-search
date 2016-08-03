#include "common.hh"
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>

#if __WORDSIZE == 32
const char MAGIC[] = {'A','P','A','P'};
#elif __WORDSIZE == 64
const char MAGIC[] = {'A','A','P','P','A','A','P','P'};
#else
# error "not supported"
#endif

const char *listen_path = "/tmp/flow.sock";
string pcap_suffix = ".cap";
string ap_suffix = ".ap";
vector<const char *> pcap_dir;
long splitter_limit = 0;
double request_timeout = 1;
long request_count = -1;
bool opt_force_rebuild = false;
bool opt_inotify = true;
bool opt_recursive = false;
long left_context = 10;
long right_context = 10;

int inotify_fd = -1, pending = 0, pending_splitters = 0;
map<int, string> wd2dir;
map<string, int> dir2wd;
set<string> modified;

pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_cond_t manager_cond = PTHREAD_COND_INITIALIZER,
                pending_empty = PTHREAD_COND_INITIALIZER;
bool manager_quit = false;
vector<string> splitter_tasks;

struct Entry
{
  FILE* ap_fh;
  int pcap_fd, ap_fd;
  off_t pcap_size, ap_size;
  void *pcap_mmap, *ap_mmap;
  ~Entry() {
    if (pcap_mmap != MAP_FAILED)
      munmap(pcap_mmap, pcap_size);
    if (ap_mmap != MAP_FAILED)
      munmap(ap_mmap, ap_size);
    close(pcap_fd);
    if (ap_fh)
      fclose(ap_fh);
    else
      close(ap_fd);
  }
};
RefCountTreap<string, shared_ptr<Entry>> loaded;

struct ApHeader {
  char magic[sizeof(MAGIC)];
  int n_flows;
  off_t pcap_size;
  off_t flow_offsets[0];
} __attribute__((packed));

struct FlowKey {
  u32 client_ip, server_ip;
  u16 client_port, server_port;
  bool operator<(const FlowKey& rhs) const {
    if (client_ip != rhs.client_ip) return client_ip < rhs.client_ip;
    if (server_ip != rhs.server_ip) return server_ip < rhs.server_ip;
    if (client_port != rhs.client_port) return client_port < rhs.client_port;
    return server_port < rhs.server_port;
  }
};

struct FlowPacket {
  off_t offset, len;
  bool from_server;
  bool operator<(const FlowPacket& o) const {
    if (offset != o.offset) return offset < o.offset;
    return from_server < o.from_server;
  }
} __attribute__((packed));

struct FlowVal {
  FlowKey key;
  off_t len;
  u32 client_seq, server_seq, unix_time;
  long id;
  vector<FlowPacket> packets;
};

struct FlowHeader {
  FlowKey key;
  u32 unix_time;
  int n_packets;
  FlowPacket packets[0];
} __attribute__((packed));

void print_help(FILE *fh)
{
  fprintf(fh, "Usage: %s [OPTIONS] dir\n", program_invocation_short_name);
  fputs(
        "\n"
        "Options:\n"
        "  -c, --request-count %ld   max number of requests (default: -1)\n"
        "  -f, --force-rebuild       ignore exsistent indices\n"
        "  -i, --splitter-limit %ld  max number of concurrent splitter tasks\n"
        "  -o, --oneshot             run only once (no inotify)\n"
        "  -p, --path %s             path of listening Unix domain socket\n"
        "  -r, --recursive           recursive\n"
        "  -s, --pcap-suffix %s      data file suffix. (default: .cap)\n"
        "  -S, --ap-suffix %s        index file suffix. (default: .ap)\n"
        "  -t, --request-timeout %lf clients idle for more than T seconds will be dropped (default: 1)\n"
        "  -h, --help                display this help and exit\n"
        "\n"
        "Examples:\n"
        , fh);
  exit(fh == stdout ? 0 : EX_USAGE);
}

string escape(u8* a, off_t len)
{
  const char ab[] = "0123456789abcdef";
  string ret;
  REP(i, len)
    if (isprint(a[i]))
      ret += a[i];
    else {
      ret += "\\x";
      ret += ab[a[i]>>4&15];
      ret += ab[a[i]&15];
    }
  return ret;
}

string pcap_to_ap(const string& path)
{
  return path.substr(0, path.size()-pcap_suffix.size())+ap_suffix;
}

bool is_pcap(const string &path)
{
  return path.size() >= pcap_suffix.size() && path.substr(path.size()-pcap_suffix.size()) == pcap_suffix;
}

string to_path(string path, string name)
{
  if (! (path.size() && path.back() == '/'))
    path += '/';
  if (name.size() && name[0] == '/')
    name = name.substr(1);
  path += name;
  return path;
}

template<> vector<RefCountTreap<string, shared_ptr<Entry>>::Node*> RefCountTreap<string, shared_ptr<Entry>>::roots{};

void detached_thread(void* (*start_routine)(void*), void* data)
{
  pending++;
  pthread_t tid;
  pthread_attr_t attr;
  pthread_attr_init(&attr);
  if (pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED))
    err_exit(EX_OSERR, "pthread_attr_setdetachstate");
  if (pthread_create(&tid, &attr, start_routine, data))
    err_exit(EX_OSERR, "pthread_create");
  pthread_attr_destroy(&attr);
}

int inotify_add_dir(const string& dir)
{
  int wd = inotify_add_watch(inotify_fd, dir.c_str(), IN_CLOSE_WRITE | IN_CREATE | IN_DELETE | IN_IGNORED | IN_MODIFY | IN_MOVE | IN_MOVE_SELF);
  if (wd < 0) {
    err_msg("failed to inotify_add_watch %s", dir.c_str());
    return wd;
  }
  wd2dir[wd] = dir;
  dir2wd[dir] = wd;
  log_action("inotify_add_watch %s", dir.c_str());
  return wd;
}

void add_pcap(const string& pcap_path)
{
  splitter_tasks.push_back(pcap_path);
  pthread_cond_signal(&manager_cond);
}

void rm_pcap(const string& pcap_path)
{
  string ap_path = pcap_to_ap(pcap_path);
  if (! unlink(ap_path.c_str()))
    log_action("unlinked %s", ap_path.c_str());
  else if (errno != ENOENT)
    err_msg("failed to unlink %s", ap_path.c_str());
}

struct Frame
{
  double timestamp = 0;
  u32 offset;
  Frame() {}
  Frame(u32 offset) : offset(offset) {}
  bool operator<(const Frame &rhs) const {
    return offset < rhs.offset;
  }
};

class PCAP
{
public:
  vector<Frame> frames;

  virtual ~PCAP() {}

  virtual bool parse(void* a_, off_t len) {
    frames.clear();
    auto* a = (u8*)a_;
    if (len < 16) return false;
    if (*(u32*)a != 0xa1b2c3d4) return false;
    for (u32 j, i = 24; i <= len-16; i = j) {
      u8 *block = (u8*)a+i;
      j = i+16+*(u32*)&block[8];
      if (j < i+16) return false;
      Frame frame;
      frame.timestamp = *(u32*)&block[0] + double(*(u32*)&block[4]) * 1e-6;
      frame.offset = i+16;
      frames.push_back(frame);
    }
    return true;
  }

  int offset2pos(u32 offset) {
    return lower_bound(frames.begin(), frames.end(), Frame(offset))-frames.begin();
  }
};

class PCAPNG : public PCAP
{
public:
  double tsresol = 1e-6;

  bool parse_interface_description_block(u32 len, const u8 *block) {
    if (len < 4) return false;
    for (u32 j, i = 16; i < len-4; i = j) {
      u16 opt_code = *(u16*)(block+i), opt_len = *(u16*)(block+i+2);
      j = i+2+opt_len;
      j = ((j-1)|3)+1; // aligned to 32-bit
      if (j < i) return false;
      switch (opt_code) {
      case 9: // if_tsresol
        if (block[i+4] & 0x80)
          tsresol = pow(0.5, block[i+4] & 0x7f);
        else
          /// XXX
          tsresol = pow(0.1, block[i+4]-3);
        break;
      case 14: // if_tsoffset
        err_msg("offset %u: option code %d not implemented", i, opt_code);
        return false;
      }
    }
    return true;
  }

  bool parse(void* a_, off_t len) override {
    frames.clear();
    auto* a = (u8*)a_;
    if (len < 8) return false;
    errno = 0;
    for (u32 j, i = 0; i < len-8; i = j) {
      u8 *block = (u8*)a+i;
      u32 block_len = *(u32*)(a+i+4);
      j = i+block_len;
      if (j < i+12 || len < j) return false;
      u32 block_len2 = *(u32*)&a[j-4];
      if (block_len != block_len2) return false;
      switch (*(u32*)block) {
      case 0x0a0d0d0a:
        break;
      case 0x00000001: // Interface Description Block
        if (! parse_interface_description_block(block_len, block))
          return false;
        break;
      case 0x00000003: // Simple Packet Block
        err_msg("offset %u: simple packet block not implemented", i);
        return false;
      case 0x00000005: // Interface Statistics Block
        break;
      case 0x00000006: { // Enhanced Packet Block
        if (block_len < 28) return false;
        Frame frame;
        u64 timestamp = u64(*(u32*)&block[12]) << 32 | *(u32*)&block[16];
        frame.timestamp = timestamp * tsresol;
        frame.offset = i+28;
        frames.push_back(frame);
        break;
      }
      default:
        err_msg("offset %u: block type %u not implemented", i, *(u32*)block);
        return false;
      }
    }
    return true;
  }
};

void split(void* pcap_mmap, off_t pcap_size, FILE* fh)
{
  PCAP* pcap = NULL;
  PCAP pcapold;
  PCAPNG pcapng;
  if (pcapold.parse(pcap_mmap, pcap_size))
    pcap = &pcapold;
  else if (pcapng.parse(pcap_mmap, pcap_size))
    pcap = &pcapng;
  else
    return;
  vector<FlowVal> flow;
  map<FlowKey, long> tuple2flow;
  REP(i, pcap->frames.size()) {
    auto& frame = pcap->frames[i];
    off_t offset = frame.offset;
    if (sizeof(ether_header) > pcap_size-offset)
      return;
    auto* ether = (ether_header*)((u8*)pcap_mmap+offset);
    offset += sizeof(ether_header);
    if (ntohs(ether->ether_type) == ETHERTYPE_IP) {
      if (sizeof(iphdr) > pcap_size-offset)
        return;
      auto* ip = (iphdr*)((u8*)pcap_mmap+offset);
      if (ntohs(ip->tot_len) > pcap_size-offset ||
          ip->ihl*4 > ntohs(ip->tot_len))
        return;
      offset += ip->ihl*4;
      if (ip->protocol == IPPROTO_TCP) {
        auto* tcp = (tcphdr*)((u8*)pcap_mmap+offset);
        if (tcp->doff*4 > pcap_size-offset)
          return;
        if (ntohs(ip->frag_off) != IP_DF) // TODO fragmentation
          return;
        offset += tcp->doff*4;
        auto* payload = (u8*)pcap_mmap+offset;
        off_t len = ntohs(ip->tot_len)-ip->ihl*4-tcp->doff*4;
        printf("-- %ld\n", len);
        FlowKey key{ntohl(ip->saddr), ntohl(ip->daddr), ntohs(tcp->source), ntohs(tcp->dest)},
                key2{ntohl(ip->daddr), ntohl(ip->saddr), ntohs(tcp->dest), ntohs(tcp->source)};
        if (tcp->th_flags == TH_SYN) { // TODO new connection
          tuple2flow.erase(key);
          tuple2flow.erase(key2);
          tuple2flow[key] = flow.size();
          flow.emplace_back();
          flow.back().key = key;
          flow.back().client_seq = ntohl(tcp->seq)+len;
          flow.back().unix_time = frame.timestamp;
          flow.back().packets.push_back(FlowPacket{offset, len, false});
          flow.back().len = len;
        }
        else if (tcp->th_flags == (TH_SYN | TH_ACK)) { // TODO new connection
          if (tuple2flow.count(key2)) {
            auto& v = flow[tuple2flow[key2]];
            v.server_seq = ntohl(tcp->seq)+len;
            v.packets.push_back(FlowPacket{offset, len, false});
            v.len += len;
          } else {
            tuple2flow.erase(key);
            tuple2flow.erase(key2);
          }
        } else if (tuple2flow.count(key)) { // TODO reincarnation retransmit
          auto& v = flow[tuple2flow[key]];
          v.client_seq = ntohl(tcp->seq)+len;
          v.packets.push_back(FlowPacket{offset, len, false});
          v.len += len;
        } else if (tuple2flow.count(key2)) { // TODO reincarnation
          auto& v = flow[tuple2flow[key2]];
          v.server_seq = ntohl(tcp->seq)+len;
          v.packets.push_back(FlowPacket{offset, len, true});
          v.len += len;
        }
      }
    }
  }
  if (fseeko(fh, 0, SEEK_SET) < 0)
    err_exit(EX_OSERR, "fseeko");
  {
    // APHeader
    ApHeader ap_hdr;
    memcpy(ap_hdr.magic, MAGIC, sizeof MAGIC);
    ap_hdr.n_flows = flow.size();
    ap_hdr.pcap_size = pcap_size;
    if (fwrite(&ap_hdr, sizeof ap_hdr, 1, fh) != 1)
      err_exit(EX_OSERR, "fwrite");
    fflush(fh);

    // flow_offsets[]
    off_t offset = sizeof ap_hdr + sizeof(off_t)*flow.size();
    for (auto& f: flow) {
      if (fwrite(&offset, sizeof(off_t), 1, fh) != 1)
        err_exit(EX_OSERR, "fwrite");
      offset += sizeof(FlowHeader) + sizeof(FlowHeader::packets[0])*f.packets.size() + f.len;
    }

    // FlowHeader[] + payload
    offset = sizeof ap_hdr + sizeof(off_t)*flow.size();
    for (auto& f: flow) {
      FlowHeader flow_hdr;
      flow_hdr.key = f.key;
      flow_hdr.unix_time = f.unix_time;
      flow_hdr.n_packets = f.packets.size();
      if (fwrite(&flow_hdr, sizeof flow_hdr, 1, fh) != 1)
        err_exit(EX_OSERR, "fwrite");
      offset += sizeof(FlowHeader) + sizeof(FlowPacket)*f.packets.size();
      for (auto& p: f.packets) {
        FlowPacket t{offset, p.len, p.from_server};
        if (fwrite(&t, sizeof t, 1, fh) != 1)
          err_exit(EX_OSERR, "fwrite");
        offset += p.len;
      }
      for (auto& p: f.packets)
        if (p.len > 0 && fwrite((u8*)pcap_mmap+p.offset, p.len, 1, fh) != 1)
          err_exit(EX_OSERR, "fwrite");
    }
  }
  fflush(fh);
  if (ftruncate(fileno(fh), ftello(fh)) < 0)
    err_exit(EX_IOERR, "ftruncate");
}

void* splitter(void* pcap_path_)
{
  string* pcap_path = (string*)pcap_path_;
  string ap_path = pcap_to_ap(*pcap_path);
  int pcap_fd = -1, ap_fd = -1;
  off_t pcap_size, ap_size;
  void *pcap_mmap = MAP_FAILED, *ap_mmap = MAP_FAILED;
  bool rebuild = true;
  FILE* fh = NULL;
  errno = 0;
  if ((pcap_fd = open(pcap_path->c_str(), O_RDONLY)) < 0)
    goto quit;
  if ((pcap_size = lseek(pcap_fd, 0, SEEK_END)) < 0)
    goto quit;
  if (pcap_size > 0 && (pcap_mmap = mmap(NULL, pcap_size, PROT_READ, MAP_SHARED, pcap_fd, 0)) == MAP_FAILED)
    goto quit;
  if ((ap_fd = open(ap_path.c_str(), O_RDWR | O_CREAT, 0666)) < 0)
    goto quit;
  if ((ap_size = lseek(ap_fd, 0, SEEK_END)) < 0)
    goto quit;
  {
    if (! ap_size) goto rebuild;
    if ((ap_mmap = mmap(NULL, ap_size, PROT_READ, MAP_SHARED, ap_fd, 0)) == MAP_FAILED)
      goto quit;
    auto ap_hdr = (ApHeader*)ap_mmap;
    if (ap_size < sizeof(ApHeader) || memcmp(ap_hdr->magic, MAGIC, sizeof(MAGIC)))
      log_status("ap file %s: bad magic, rebuilding", ap_path.c_str());
    else if (ap_hdr->pcap_size != pcap_size)
      log_status("ap file %s: mismatching length of pcap file, rebuilding", ap_path.c_str());
    else if (! opt_force_rebuild) {
      printf("force rebuild %d\n", errno);
      goto load;
    }
  }
rebuild:
  if (loaded.find(*pcap_path)) {
    loaded.erase(*pcap_path);
    log_action("rebuilding flows of '%s", pcap_path->c_str());
  }
  {
    StopWatch sw;
    if (ap_mmap != MAP_FAILED) {
      munmap(ap_mmap, ap_size);
      ap_mmap = MAP_FAILED;
    }
    if (! (fh = fdopen(ap_fd, "r+")))
      goto quit;
    split(pcap_mmap, pcap_size, fh);
    ap_size = ftello(fh);
    log_action("created flows of %s. data: %ld, index: %ld, used %.3lf s", pcap_path->c_str(), pcap_size, ap_size, sw.elapsed());
  }
load:
  printf("load %d\n", errno);
  {
    if (ap_mmap != MAP_FAILED) {
      munmap(ap_mmap, ap_size);
      ap_mmap = MAP_FAILED;
    }
    if (ap_size > 0 && (ap_mmap = mmap(NULL, ap_size, PROT_READ, MAP_SHARED, ap_fd, 0)) == MAP_FAILED)
      goto quit;
    auto entry = make_shared<Entry>();
    entry->pcap_fd = pcap_fd;
    entry->ap_fd = ap_fd;
    entry->ap_fh = fh;
    entry->pcap_size = pcap_size;
    entry->ap_size = ap_size;
    entry->pcap_mmap = pcap_mmap;
    entry->ap_mmap = ap_mmap;
    pthread_mutex_lock(&mutex);
    loaded.insert(ap_path, entry);
    pthread_cond_signal(&manager_cond);
    pthread_mutex_unlock(&mutex);
    log_action("loaded flows of %s", pcap_path->c_str());
  }
  printf("load %d\n", errno);
  goto success;
quit:
  printf("quit %d\n", errno);
  if (fh)
    fclose(fh);
  else if (ap_fd >= 0)
    close(ap_fd);
  if (pcap_mmap != MAP_FAILED)
    munmap(pcap_mmap, pcap_size);
  if (pcap_fd >= 0)
    close(pcap_fd);
success:
  printf("success %d\n", errno);
  if (errno)
    err_msg("failed to split %s", pcap_path->c_str());
  delete pcap_path;
  pthread_mutex_lock(&mutex);
  pending--;
  pending_splitters--;
  pthread_cond_signal(&manager_cond);
  pthread_mutex_unlock(&mutex);
  return NULL;
}

void walk(long depth, long dir_fd, string path, const char* file)
{
  int fd = -1;
  struct stat statbuf;
  if (stat(path.c_str(), &statbuf) < 0)
    err_msg_g("stat");
  if (S_ISREG(statbuf.st_mode)) {
    if (is_pcap(path)) add_pcap(path);
  } else if (S_ISDIR(statbuf.st_mode)) {
    if (! opt_recursive && depth > 0) goto quit;
    if (inotify_fd >= 0)
      inotify_add_dir(path);
    fd = openat(dir_fd, file, O_RDONLY);
    if (fd < 0)
      err_msg_g("failed to open %s", path.c_str());
    DIR* dirp = fdopendir(fd);
    if (! dirp)
      err_msg_g("opendir");
    struct dirent dirent, *dirt;
    while (! readdir_r(dirp, &dirent, &dirt) && dirt)
      if (strcmp(dirent.d_name, ".") && strcmp(dirent.d_name, ".."))
        walk(depth+1, fd, to_path(path, dirent.d_name), dirent.d_name);
    closedir(dirp);
    fd = -1;
  }

quit:;
    if (fd >= 0)
      close(fd);
}

void process_inotify()
{
  char buf[sizeof(inotify_event)+NAME_MAX+1];
  int nread;
  if ((nread = read(inotify_fd, buf, sizeof buf)) <= 0)
    err_exit(EX_OSERR, "failed to read inotify fd");
  errno = 0;
  for (auto *ev = (inotify_event *)buf; (char *)ev < (char *)buf+nread;
        ev = (inotify_event *)((char *)ev + sizeof(inotify_event) + ev->len))
    if (ev->len > 0 || ev->mask & (IN_IGNORED | IN_MOVE_SELF)) {
      const char* dir = wd2dir[ev->wd].c_str();
      bool pcap = is_pcap(ev->name);
      string path = to_path(dir, ev->name);
      if (ev->mask & (IN_CREATE | IN_MOVED_TO)) {
        if (ev->mask & IN_CREATE)
          log_event("CREATE %s", path.c_str());
        else
          log_event("MOVED_TO %s", path.c_str());

        if (ev->mask & IN_ISDIR)
          opt_recursive && inotify_add_dir(path.c_str());
        else if (pcap) {
          struct stat statbuf;
          if (lstat(path.c_str(), &statbuf) < 0) continue;
          if (ev->mask & IN_MOVED_TO || S_ISLNK(statbuf.st_mode)) {
            modified.erase(path);
            add_pcap(path);
          } else
            modified.insert(path);
        }
      } else if (ev->mask & (IN_DELETE | IN_MOVED_FROM)) {
        if (ev->mask & IN_DELETE)
          log_event("DELETE %s", path.c_str());
        else
          log_event("MOVED_FROM %s", path.c_str());
        if (! (ev->mask & IN_ISDIR)) {
          modified.erase(path);
          if (pcap) rm_pcap(path);
        }
      } else if (ev->mask & IN_IGNORED) {
        log_event("IGNORED %s", dir);
        if (wd2dir.count(ev->wd)) {
          dir2wd.erase(wd2dir[ev->wd]);
          wd2dir.erase(ev->wd);
        }
      } else if (ev->mask & IN_MODIFY) {
        if (pcap) modified.insert(path);
      } else if (ev->mask & IN_MOVE_SELF)
        err_exit(EX_OSFILE, "%s has been moved", wd2dir[ev->wd].c_str());
      else if (ev->mask & IN_CLOSE_WRITE) {
        if (modified.count(path)) {
          log_event("CLOSE_WRITE after MODIFY %s", path.c_str());
          modified.erase(path);
          if (pcap) add_pcap(path);
        }
      }
    }
}

void locate(int connfd, const Entry* entry, off_t offset, off_t len)
{
  auto* ap_hdr = (ApHeader*)entry->ap_mmap;
  if (! ap_hdr || offset < 0 || entry->ap_size <= offset) return;
  off_t* flow_offset = upper_bound(ap_hdr->flow_offsets, ap_hdr->flow_offsets+ap_hdr->n_flows, offset);
  if (flow_offset == ap_hdr->flow_offsets) return;
  flow_offset--;
  auto* flow_hdr = (FlowHeader*)((u8*)entry->ap_mmap+*flow_offset);
  long pi = upper_bound(flow_hdr->packets, flow_hdr->packets+flow_hdr->n_packets, FlowPacket{offset, LONG_MAX, true}) - flow_hdr->packets;
  if (pi == flow_hdr->n_packets) return;
  pi--;
  string left, body, right;
  long nleft = 0, nbody = 0, nright = 0, epoch = 0, sport = 0, dport = 0;
  {
    off_t po = offset-flow_hdr->packets[pi].offset;
    auto i = pi;
    for (; i < flow_hdr->n_packets && nbody < len; i++, po = 0) {
      auto t = min(flow_hdr->packets[i].len-po, len-nbody);
      if (! t) continue;
      if (flow_hdr->packets[i].from_server)
        body += "<span class=\"red highlight\">";
      else
        body += "<span class=\"green highlight\">";
      body += escape((u8*)entry->ap_mmap+flow_hdr->packets[i].offset+po, t);
      body += "</span>";
      po += t;
      if ((nbody += t) == len) break;
    }
    for (; i < flow_hdr->n_packets && nright < right_context; i++, po = 0) {
      auto t = min(flow_hdr->packets[i].len-po, right_context-nright);
      if (! t) continue;
      if (flow_hdr->packets[i].from_server)
        right += "<span class=\"red\">";
      else
        right += "<span class=\"green\">";
      right += escape((u8*)entry->ap_mmap+flow_hdr->packets[i].offset+po, t);
      right += "</span>";
    }
    po = offset-flow_hdr->packets[pi].offset;
    vector<string> lefts;
    for (i = pi; nleft < left_context; ) {
      auto t = min(po, left_context-nleft);
      if (t) {
        lefts.emplace_back("</span>");
        lefts.emplace_back(escape((u8*)entry->ap_mmap+flow_hdr->packets[i].offset+po-t, t));
        if (flow_hdr->packets[i].from_server)
          lefts.emplace_back("<span class=\"red\">");
        else
          lefts.emplace_back("<span class=\"green\">");
      }
      if (! i) break;
      po = flow_hdr->packets[--i].len;
    }
    for (auto it = lefts.rbegin(); it != lefts.rend(); ++it)
      left += *it;
  }
  dprintf(connfd, "%" PRIu32 "\t%" PRIu16 "\t%" PRIu16 "\t%s", flow_hdr->unix_time, flow_hdr->key.client_port, flow_hdr->key.server_port, (left+body+right).c_str());
}

void* request_worker(void* connfd_)
{
  int connfd = intptr_t(connfd_);
  char buf[BUF_SIZE] = {};
  const char *p, *pos;
  int nread = 0;
  timespec timeout;
  {
    double tmp;
    timeout.tv_sec = modf(request_timeout, &tmp);
    timeout.tv_nsec = tmp;
  }

  struct pollfd fds;
  fds.fd = connfd;
  fds.events = POLLIN;
  for(;;) {
    int ready = ppoll(&fds, 1, &timeout, NULL);
    if (ready < 0) {
      if (errno == EINTR) continue;
      goto quit;
    }
    if (! ready) goto quit; // timeout
    ssize_t t = read(connfd, buf+nread, sizeof buf-nread);
    if (t < 0) goto quit;
    if (! t) break;
    nread += t;
  }

  for (p = buf; p < buf+nread && *p; p++);
  if (++p >= buf+nread) goto quit;
  pos = p;
  for (; p < buf+nread && *p; p++);
  if (++p >= buf+nread) goto quit;
  {
    char *end;
    errno = 0;
    ulong offset = strtoul(pos, &end, 0);
    if (! *end && ! errno) {
      ulong len = strtoul(p, &end, 0);
      if (! *end && ! errno) {
        pthread_mutex_lock(&mutex);
        auto* node = loaded.find(string(buf));
        if (node) node->refcnt++;
        pthread_mutex_unlock(&mutex);
        if (node) {
          locate(connfd, node->val.get(), offset, len);
          pthread_mutex_lock(&mutex);
          node->unref();
          pthread_mutex_unlock(&mutex);
        }
      }
    }
  }
quit:
  close(connfd);
  pthread_mutex_lock(&mutex);
  if (! --pending)
    pthread_cond_signal(&pending_empty);
  pthread_mutex_unlock(&mutex);
  return NULL;
}

void* manager(void*)
{
  for(;;) {
    pthread_mutex_lock(&mutex);
    while (! manager_quit && loaded.roots.empty() && (splitter_tasks.empty() || pending_splitters >= splitter_limit))
      pthread_cond_wait(&manager_cond, &mutex);
    while (splitter_tasks.size() && pending_splitters < splitter_limit) {
      pending_splitters++;
      detached_thread(splitter, new string(splitter_tasks.back()));
      splitter_tasks.pop_back();
    }
    while (loaded.roots.size()) {
      if (loaded.roots.back())
        loaded.roots.back()->unref();
      loaded.roots.pop_back();
    }
    pthread_mutex_unlock(&mutex);
    if (manager_quit) break;
  }
  pthread_mutex_lock(&mutex);
  if (! --pending)
    pthread_cond_signal(&pending_empty);
  pthread_mutex_unlock(&mutex);
  return NULL;
}

void run()
{
  signal(SIGPIPE, SIG_IGN); // SIGPIPE while writing to clients

  int sockfd = socket(AF_UNIX, SOCK_STREAM, 0);
  if (sockfd < 0)
    err_exit(EX_OSERR, "socket");
  struct sockaddr_un addr = {};
  addr.sun_family = AF_UNIX;
  strncpy(addr.sun_path, listen_path, sizeof(addr.sun_path)-1);
  if (! unlink(listen_path))
    log_action("removed old socket %s", listen_path);
  if (bind(sockfd, (struct sockaddr *)&addr, sizeof addr) < 0)
    err_exit(EX_OSERR, "bind");
  if (listen(sockfd, 1) < 0)
    err_exit(EX_OSERR, "listen");
  log_status("listening on %s", listen_path);

  // load existing
  if (opt_inotify)
    if ((inotify_fd = inotify_init()) < 0)
      err_exit(EX_OSERR, "inotify_init");
  for (auto dir: pcap_dir)
    walk(0, AT_FDCWD, dir, dir);
  if (opt_inotify)
    log_status("start inotify");
  pthread_mutex_lock(&mutex);
  detached_thread(manager, nullptr);
  pthread_mutex_unlock(&mutex);

  while (request_count) {
    struct pollfd fds[2];
    fds[0].fd = sockfd;
    fds[0].events = POLLIN;
    int nfds = 1;
    if (inotify_fd >= 0) {
      fds[1].fd = inotify_fd;
      fds[1].events = POLLIN;
      nfds = 2;
    }
    int ready = poll(fds, nfds, -1);
    if (ready < 0) {
      if (errno == EINTR) continue;
      err_exit(EX_OSERR, "poll");
    }
    if (fds[0].revents & POLLIN) { // socket
      int connfd = accept(sockfd, NULL, NULL);
      if (connfd < 0) err_exit(EX_OSERR, "accept");
      pthread_mutex_lock(&mutex);
      detached_thread(request_worker, (void*)(intptr_t)connfd);
      pthread_mutex_unlock(&mutex);
      if (request_count > 0) request_count--;
    }
    if (1 < nfds && fds[1].revents & POLLIN) // inotifyfd
      process_inotify();
  }
  if (inotify_fd >= 0)
    close(inotify_fd);
  close(sockfd);
  pthread_mutex_lock(&mutex);
  manager_quit = true;
  pthread_cond_signal(&manager_cond);
  while (pending > 0)
    pthread_cond_wait(&pending_empty, &mutex);
  pthread_mutex_unlock(&mutex);
}

int main(int argc, char *argv[])
{
  int opt;
  static struct option long_options[] = {
    {"ap-suffix",           required_argument, 0,   'S'},
    {"help",                no_argument,       0,   'h'},
    {"left-context",        required_argument, 0,   'L'},
    {"oneshot",             no_argument,       0,   'o'},
    {"path",                required_argument, 0,   'p'},
    {"pcap-suffix",         required_argument, 0,   's'},
    {"recursive",           no_argument,       0,   'r'},
    {"request-count",       required_argument, 0,   'c'},
    {"right-context",       required_argument, 0,   'R'},
    {"splitter-limit",      required_argument, 0,   'P'},
    {0,                     0,                 0,   0},
  };

  while ((opt = getopt_long(argc, argv, "-c:hL:op:P:s:S:rR:", long_options, NULL)) != -1) {
    switch (opt) {
    case 1: {
      struct stat statbuf;
      if (stat(optarg, &statbuf) < 0)
        err_exit(EX_OSFILE, "stat");
      if (! S_ISDIR(statbuf.st_mode))
        err_exit(EX_USAGE, "%s is not a directory", optarg);
      pcap_dir.push_back(optarg);
      break;
    }
    case 'c':
      request_count = get_long(optarg);
      break;
    case 'L':
      left_context = get_long(optarg);
      break;
    case 'o':
      opt_inotify = false;
      break;
    case 'p':
      listen_path = optarg;
      break;
    case 'P':
      splitter_limit = get_long(optarg);
      break;
    case 'r':
      opt_recursive = true;
      break;
    case 'R':
      right_context = get_long(optarg);
      break;
    case 's':
      pcap_suffix = optarg;
      break;
    case 'S':
      ap_suffix = optarg;
      break;
    case '?':
      print_help(stderr);
      break;
    }
  }
  if (pcap_dir.empty())
    print_help(stderr);
  if (! splitter_limit) {
    splitter_limit = sysconf(_SC_NPROCESSORS_ONLN);
    if (splitter_limit < 0)
      err_exit(EX_OSERR, "sysconf");
  }

  run();
}
