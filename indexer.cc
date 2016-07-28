#ifndef _GNU_SOURCE
# define _GNU_SOURCE
#endif
#include <algorithm>
#include <atomic>
#include <arpa/inet.h>
#include <cassert>
#include <cctype>
#include <climits>
#include <cmath>
#include <cstdint>
#include <memory>
#include <cstdio>
#include <cstring>
#include <dirent.h>
#include <errno.h>
#include <execinfo.h>
#include <fcntl.h>
#include <functional>
#include <getopt.h>
#include <map>
#include <netinet/in.h>
#include <poll.h>
#include <pthread.h>
#include <set>
#include <setjmp.h>
#include <signal.h>
#include <stack>
#include <stdarg.h>
#include <sys/inotify.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/un.h>
#include <sysexits.h>
#include <tuple>
#include <type_traits>
#include <unistd.h>
#include <utility>
#include <vector>
using namespace std;

typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;
typedef int32_t i32;

#define LEN_OF(x) (sizeof(x)/sizeof(*x))
#define REP(i, n) FOR(i, 0, n)
#define REPS(i, n, s) FORS(i, 0, n, s)
#define FOR(i, a, b) for (typename std::remove_cv<typename std::remove_reference<decltype(b)>::type>::type i = (a); i < (b); i++)
#define FORS(i, a, b, s) for (typename std::remove_cv<typename std::remove_reference<decltype(b)>::type>::type i = (a); i < (b); i += (s))
#define ROF(i, a, b) for (typename std::remove_cv<typename std::remove_reference<decltype(b)>::type>::type i = (b); --i >= (a); )

#define SGR0 "\x1b[m"
#define RED "\x1b[31m"
#define GREEN "\x1b[32m"
#define YELLOW "\x1b[33m"
#define BLUE "\x1b[34m"
#define MAGENTA "\x1b[35m"
#define CYAN "\x1b[36m"

const char MAGIC_BAD[] = "BAD ";
const char MAGIC_GOOD[] = "GOOD";
const long LOGAB = CHAR_BIT, AB = 1L << LOGAB;

const size_t BUF_SIZE = 512;
const char *listen_path = "/tmp/search.sock";
const pthread_t main_thread = pthread_self();
vector<const char *> data_dir;
string data_suffix = ".ap";
string index_suffix = ".fm";
long autocomplete_limit = 20;
long autocomplete_length = 20;
long search_limit = 20;
long fmindex_sample_rate = 32;
long rrr_sample_rate = 8;
double request_timeout = 1;
long request_count = -1;
bool opt_inotify = true;
bool opt_recursive = false;
atomic<int> ongoing(0);

///// log
int log_pipe[2];

void log_generic(const char *prefix, const char *format, va_list ap)
{
  int fd = main_thread == pthread_self() ? STDOUT_FILENO : log_pipe[1];
  char buf[BUF_SIZE];
  timeval tv;
  tm tm;
  gettimeofday(&tv, NULL);
  write(fd, prefix, strlen(prefix));
  if (localtime_r(&tv.tv_sec, &tm)) {
    strftime(buf, sizeof buf, "%T.%%06u ", &tm);
    dprintf(fd, buf, tv.tv_usec);
  }
  vdprintf(fd, format, ap);
  write(fd, SGR0, strlen(SGR0));
}

void log_event(const char *format, ...)
{
  va_list ap;
  va_start(ap, format);
  log_generic(CYAN, format, ap);
  va_end(ap);
}

void log_action(const char *format, ...)
{
  va_list ap;
  va_start(ap, format);
  log_generic(GREEN, format, ap);
  va_end(ap);
}

void log_status(const char *format, ...)
{
  va_list ap;
  va_start(ap, format);
  log_generic(YELLOW, format, ap);
  va_end(ap);
}

class StopWatch
{
  timeval start_;
public:
  StopWatch() { gettimeofday(&start_, NULL); }
  double elapsed() {
    timeval now;
    gettimeofday(&now, NULL);
    return (now.tv_sec-start_.tv_sec)+(now.tv_usec-start_.tv_usec)*1e-6;
  }
};

///// error

static const char *ENAME[] = {
    /*   0 */ "",
    /*   1 */ "EPERM", "ENOENT", "ESRCH", "EINTR", "EIO", "ENXIO",
    /*   7 */ "E2BIG", "ENOEXEC", "EBADF", "ECHILD",
    /*  11 */ "EAGAIN/EWOULDBLOCK", "ENOMEM", "EACCES", "EFAULT",
    /*  15 */ "ENOTBLK", "EBUSY", "EEXIST", "EXDEV", "ENODEV",
    /*  20 */ "ENOTDIR", "EISDIR", "EINVAL", "ENFILE", "EMFILE",
    /*  25 */ "ENOTTY", "ETXTBSY", "EFBIG", "ENOSPC", "ESPIPE",
    /*  30 */ "EROFS", "EMLINK", "EPIPE", "EDOM", "ERANGE",
    /*  35 */ "EDEADLK/EDEADLOCK", "ENAMETOOLONG", "ENOLCK", "ENOSYS",
    /*  39 */ "ENOTEMPTY", "ELOOP", "", "ENOMSG", "EIDRM", "ECHRNG",
    /*  45 */ "EL2NSYNC", "EL3HLT", "EL3RST", "ELNRNG", "EUNATCH",
    /*  50 */ "ENOCSI", "EL2HLT", "EBADE", "EBADR", "EXFULL", "ENOANO",
    /*  56 */ "EBADRQC", "EBADSLT", "", "EBFONT", "ENOSTR", "ENODATA",
    /*  62 */ "ETIME", "ENOSR", "ENONET", "ENOPKG", "EREMOTE",
    /*  67 */ "ENOLINK", "EADV", "ESRMNT", "ECOMM", "EPROTO",
    /*  72 */ "EMULTIHOP", "EDOTDOT", "EBADMSG", "EOVERFLOW",
    /*  76 */ "ENOTUNIQ", "EBADFD", "EREMCHG", "ELIBACC", "ELIBBAD",
    /*  81 */ "ELIBSCN", "ELIBMAX", "ELIBEXEC", "EILSEQ", "ERESTART",
    /*  86 */ "ESTRPIPE", "EUSERS", "ENOTSOCK", "EDESTADDRREQ",
    /*  90 */ "EMSGSIZE", "EPROTOTYPE", "ENOPROTOOPT",
    /*  93 */ "EPROTONOSUPPORT", "ESOCKTNOSUPPORT",
    /*  95 */ "EOPNOTSUPP/ENOTSUP", "EPFNOSUPPORT", "EAFNOSUPPORT",
    /*  98 */ "EADDRINUSE", "EADDRNOTAVAIL", "ENETDOWN", "ENETUNREACH",
    /* 102 */ "ENETRESET", "ECONNABORTED", "ECONNRESET", "ENOBUFS",
    /* 106 */ "EISCONN", "ENOTCONN", "ESHUTDOWN", "ETOOMANYREFS",
    /* 110 */ "ETIMEDOUT", "ECONNREFUSED", "EHOSTDOWN", "EHOSTUNREACH",
    /* 114 */ "EALREADY", "EINPROGRESS", "ESTALE", "EUCLEAN",
    /* 118 */ "ENOTNAM", "ENAVAIL", "EISNAM", "EREMOTEIO", "EDQUOT",
    /* 123 */ "ENOMEDIUM", "EMEDIUMTYPE", "ECANCELED", "ENOKEY",
    /* 127 */ "EKEYEXPIRED", "EKEYREVOKED", "EKEYREJECTED",
    /* 130 */ "EOWNERDEAD", "ENOTRECOVERABLE", "ERFKILL", "EHWPOISON"
};

#define MAX_ENAME 133

void output_error(bool use_err, const char *format, va_list ap)
{
  char text[BUF_SIZE], msg[BUF_SIZE], buf[BUF_SIZE];
  vsnprintf(msg, BUF_SIZE, format, ap);
  if (use_err)
    snprintf(text, BUF_SIZE, "[%s %s] ", 0 < errno && errno < MAX_ENAME ? ENAME[errno] : "?UNKNOWN?", strerror(errno));
  else
    strcpy(text, "");
  snprintf(buf, BUF_SIZE, RED "%s%s\n", text, msg);
  fputs(buf, stderr);
  fputs(SGR0, stderr);
  fflush(stderr);
}

void err_msg(const char *format, ...)
{
  va_list ap;
  va_start(ap, format);
  int saved = errno;
  output_error(errno > 0, format, ap);
  errno = saved;
  va_end(ap);
}
#define err_msg_g(...) ({err_msg(__VA_ARGS__); goto quit;})

void err_exit(int exitno, const char *format, ...)
{
  va_list ap;
  va_start(ap, format);
  int saved = errno;
  output_error(errno > 0, format, ap);
  errno = saved;
  va_end(ap);

  void *bt[99];
  char buf[1024];
  int nptrs = backtrace(bt, LEN_OF(buf));
  int i = sprintf(buf, "addr2line -Cfipe %s", program_invocation_name), j = 0;
  while (j < nptrs && i+30 < sizeof buf)
    i += sprintf(buf+i, " %#x", bt[j++]);
  strcat(buf, ">&2");
  fputs("\n", stderr);
  system(buf);
  //backtrace_symbols_fd(buf, nptrs, STDERR_FILENO);
  exit(exitno);
}

///// common

u64 clog2(u64 x)
{
  return x > 1 ? 64-__builtin_clzll(x-1) : 0;
}

u64 select_in_u16(u16 x, u64 k)
{
  for (; k; k--)
    x &= x - 1;
  return __builtin_ctzll(x);
}

u64 select_in_u64(u64 x, u64 k)
{
  u64 c;
  c =  __builtin_popcountll(u16(x));
  if (c > k) return select_in_u16(x, k) + 0;
  x >>= 16;
  k -= c;
  c =  __builtin_popcountll(u16(x));
  if (c > k) return select_in_u16(x, k) + 16;
  x >>= 16;
  k -= c;
  c =  __builtin_popcountll(u16(x));
  if (c > k) return select_in_u16(x, k) + 32;
  x >>= 16;
  k -= c;
  return select_in_u16(x, k) + 48;
}

long get_long(const char *arg)
{
  char *end;
  errno = 0;
  long ret = strtol(arg, &end, 0);
  if (errno)
    err_exit(EX_USAGE, "get_long: %s", arg);
  if (*end)
    err_exit(EX_USAGE, "get_long: nonnumeric character");
  return ret;
}

double get_double(const char *arg)
{
  char *end;
  errno = 0;
  double ret = strtod(arg, &end);
  if (errno)
    err_exit(EX_USAGE, "get_double: %s", arg);
  if (*end)
    err_exit(EX_USAGE, "get_double: nonnumeric character");
  return ret;
}

string escape(const string &str)
{
  const char ab[] = "0123456789abcdef";
  string ret;
  for (char c: str)
    if (isprint(c))
      ret += c;
    else {
      ret += "\\x";
      ret += ab[c>>4&15];
      ret += ab[c&15];
    }
  return ret;
}

string unescape(size_t n, const char *str)
{
  auto from_hex = [&](int c) {
    if ('0' <= c && c <= '9') return c-'0';
    if ('a' <= c && c <= 'f') return c-'a'+10;
    if ('A' <= c && c <= 'F') return c-'A'+10;
    return 0;
  };
  string ret;
  for (size_t i = 0; i < n; ) {
    if (str[i] == '\\') {
      if (i+4 <= n && str[i+1] == 'x') {
        ret.push_back(from_hex(str[i+2])*16+from_hex(str[i+3]));
        i += 4;
        continue;
      }
      if (i+1 <= n)
        switch (str[i+1]) {
        case 'a': ret += '\a'; i += 2; continue;
        case 'b': ret += '\b'; i += 2; continue;
        case 't': ret += '\t'; i += 2; continue;
        case 'n': ret += '\n'; i += 2; continue;
        case 'v': ret += '\v'; i += 2; continue;
        case 'f': ret += '\f'; i += 2; continue;
        case 'r': ret += '\r'; i += 2; continue;
        case '\\': ret += '\\'; i += 2; continue;
        }
      int j = i+1, v = 0;
      for (; j < n && j < i+4 && unsigned(str[j]-'0') < 8; j++)
        v = v*8+str[j]-'0';
      if (i+1 < j) {
        ret += char(v);
        i = j;
        continue;
      }
    }
    ret += str[i++];
  }
  return ret;
}

///// vector

template<class T>
class SArray
{
  u64 n_ = 0;
  T *a_ = nullptr;
  bool is_created_ = false;
public:
  SArray() {}

  SArray(const SArray<T> &) = delete;

  void operator=(SArray<T> &&o) {
    n_ = o.n_;
    a_ = o.a_;
    is_created_ = o.is_created_;
    o.n_ = 0;
    o.a_ = nullptr;
    o.is_created_ = false;
  }

  ~SArray() {
    if (is_created_)
      delete[] a_;
  }

  void init(u64 n) {
    assert(! a_ && ! is_created_); // not loaded
    is_created_ = true;
    n_ = n;
    a_ = new T[n];
  }

  void init(u64 n, const T &x) {
    init(n);
    fill_n(a_, n, x);
  }

  u64 size() const { return n_; }

  T &operator[](u64 i) { return a_[i]; }

  const T &operator[](u64 i) const { return a_[i]; }

  T *begin() { return a_; }

  T *end() { return a_+n_; }

  template<typename Archive>
  void serialize(Archive &ar) {
    ar.array(n_, a_);
    //if (n_ >= 3000)
    //printf("+ %ld * %d\n", sizeof(T), n_);
  }

  template<typename Archive>
  void deserialize(Archive &ar) {
    ar & n_;
    ar.align(alignof(T));
    a_ = (T*)ar.a_;
    ar.a_ = (T*)ar.a_ + n_;
  }
};

///// bitset

class BitSet
{
  u64 n_;
  SArray<u64> a_;
public:
  BitSet() {}

  BitSet(u64 n) {
    init(n);
  }

  void init(u64 n) {
    n_ = n;
    a_.init((n-1+64)/64, 0);
  }

  const SArray<u64> &words() const { return a_; }

  void set(u64 x) { set(x, true); }

  void set(u64 x, bool b) {
    if (b)
      a_[x/64] |= 1ull << x%64;
    else
      a_[x/64] &= ~ (1ull << x%64);
  }

  bool operator[](u64 x) const {
    return a_[x/64] & 1ull << x%64;
  }

  u64 get_bits(u64 x, u64 k) const {
    if (x % 64 + k <= 64)
      return (a_[x/64] >> x%64) & (1ull<<k)-1;
    return (a_[x/64] >> x%64 | a_[x/64+1] << 64-x%64) & (1ull<<k)-1;
  }

  u64 block(u64 k, u64 x) const { return get_bits(x*k, k); }

  void set_bits(u64 x, u64 k, u64 v) {
    if (! k) return;
    if (x % 64 + k <= 64) {
      u64 i = x%64;
      a_[x/64] = a_[x/64] & ~ (((1ull<<k)-1) << i) | v << i;
    } else {
      u64 i = x%64;
      a_[x/64] = a_[x/64] & ~ (-1ull<<i) | v << i;
      u64 j = k-(64-i);
      a_[x/64+1] = a_[x/64+1] & (-1ull<<j) | v >> 64-i;
    }
  }

  u64 size() const {
    return n_;
  }

  u64 popcount() const {
    u64 r = 0;
    REP(i, a_.size())
      r += __builtin_popcountll(a_[i]);
    return r;
  }

  template<typename Archive>
  void serialize(Archive &ar) {
    ar & n_ & a_;
  }
};

///// suffix array

namespace KoAluru
{
  bool *t;
  int *b;

  template<typename T>
  void bucket(T a[], int n, int k, bool end)
  {
    fill_n(b, k, 0);
    REP(i, n) b[a[i]]++;
    if (end)
      FOR(i, 1, k) b[i] += b[i-1];
    else {
      int s = 0;
      REP(i, k)
        s += b[i], b[i] = s-b[i];
    }
  }

  template<typename T>
  void plus_to_minus(T a[], int sa[], int n, int k)
  {
    bucket(a, n, k, false);
    sa[b[a[n-1]]++] = n-1;
    REP(i, n-1) {
      int j = sa[i]-1;
      if (j >= 0 && ! t[j])
        sa[b[a[j]]++] = j;
    }
  }

  template<typename T>
  void minus_to_plus(T a[], int sa[], int n, int k)
  {
    bucket(a, n, k, true);
    ROF(i, 0, n) {
      int j = sa[i]-1;
      if (j >= 0 && t[j])
        sa[--b[a[j]]] = j;
    }
  }

  template<typename T>
  void ka(T a[], int sa[], int n, int k)
  {
    t[n-1] = false;
    ROF(i, 0, n-1)
      t[i] = a[i] < a[i+1] || a[i] == a[i+1] && t[i+1];
    bool minor = 2 * count(t, t+n, false) > n;

    bucket(a, n, k, minor);
    fill_n(sa, n, -1);
    if (minor) {
      REP(i, n)
        if (t[i])
          sa[--b[a[i]]] = i;
      plus_to_minus(a, sa, n, k);
      minus_to_plus(a, sa, n, k);
    } else {
      sa[b[a[n-1]]++] = n-1;
      REP(i, n-1)
        if (! t[i])
          sa[b[a[i]]++] = i;
      minus_to_plus(a, sa, n, k);
      plus_to_minus(a, sa, n, k);
    }

    int last = -1, name = 0, nn = count(t, t+n, minor);
    int *sa2, *pi;
    if (minor)
      sa2 = sa, pi = sa+n-nn;
    else
      sa2 = sa+n-nn, pi = sa;
    fill_n(b, n, -1);
    REP(i, n)
      if (sa[i] >= 0 && minor == t[sa[i]]) {
        bool diff = last == -1;
        int p = sa[i];
        if (! diff)
          REP(j, n) {
            if (last+j >= n || p+j >= n || a[last+j] != a[p+j] || t[last+j] != t[p+j]) {
              diff = true;
              break;
            } else if (j > 0 && (minor == t[last+j] || minor == t[p+j]))
              break;
          }
        if (diff) {
          name++;
          last = p;
        }
        b[p] = name-1;
      }
    nn = 0;
    REP(i, n)
      if (b[i] >= 0)
        pi[nn++] = b[i];

    if (name < nn)
      ka(pi, sa2, nn, name);
    else
      REP(i, nn)
        sa2[pi[i]] = i;

    ROF(i, 0, nn)
      t[i] = a[i] < a[i+1] || a[i] == a[i+1] && t[i+1];

    nn = 0;
    bucket(a, n, k, minor);
    if (minor) {
      REP(i, n)
        if (minor == t[i])
          pi[nn++] = i;
      REP(i, nn)
        sa[i] = pi[sa2[i]];
      ROF(i, 0, nn) {
        int j = sa[i];
        sa[i] = -1;
        sa[--b[a[j]]] = j;
      }
    } else {
      REP(i, n)
        if (minor == t[i])
          pi[nn++] = i;
      ROF(i, 0, nn)
        sa[n-nn+i] = pi[sa2[i]];
      REP(i, nn) {
        int j = sa[n-nn+i];
        sa[n-nn+i] = -1;
        sa[b[a[j]]++] = j;
      }
    }
    if (minor)
      plus_to_minus(a, sa, n, k);
    else
      minus_to_plus(a, sa, n, k);
  }

  template<typename T>
  void main(T a[], int sa[], int b[], int n, int k)
  {
    if (n > 0) {
      KoAluru::b = b;
      t = new bool[n];
      ka(a, sa, n, k);
      delete[] t;
    }
  }
};

/// RRR

namespace RRRTable
{
  static const u64 SIZE = 20;
  vector<vector<u64>> binom;
  vector<vector<u32>> offset_bits, combinations(SIZE), klass_offset(SIZE), offset_pos(SIZE);

  void init() {
    REP(i, SIZE) {
      combinations[i].resize(1ull<<i);
      klass_offset[i].resize(i+1);
      offset_pos[i].resize(1ull<<i);
      u64 pcomb = 0;
      REP(klass, i+1) {
        u64 j = 0, start = (1ull<<klass)-1, stop = start<<i-klass, x = start;
        klass_offset[i][klass] = pcomb;
        for(;;) {
          combinations[i][pcomb++] = x;
          offset_pos[i][x] = j++;
          if (x == stop) break;
          u64 y = x | x-1;
          x = y+1 | (~y&-~y)-1 >> __builtin_ctzll(x)+1;
        }
      }
      assert(pcomb == (1ull << i));
    }
  }

  void raise(long size) {
    FOR(i, binom.size(), size) {
      binom.emplace_back(i+1);
      binom[i][0] = binom[i][i] = 1;
      FOR(j, 1, i)
        binom[i][j] = binom[i-1][j-1]+binom[i-1][j];
      offset_bits.emplace_back(i+1);
      REP(j, i+1)
        offset_bits[i][j] = clog2(binom[i][j]);
    }
  }
};

class RRR
{
  u64 n, block_len, sample_len, rank_sum, nblocks, nsamples, klass_bits, rsample_bits, osample_bits;
  BitSet klasses, offsets, rank_samples, offset_samples;

  u64 block2offset(u64 k, u64 x) const {
    if (block_len < RRRTable::SIZE)
      return RRRTable::offset_pos[block_len][x];
    u64 m = block_len-1, r = 0;
    for (; k; m--)
      if (x & 1ull << m) {
        if (k <= m)
          r += RRRTable::binom[m][k];
        k--;
      }
    return r;
  }

  u64 offset2block(u64 k, u64 off) const {
    if (block_len < RRRTable::SIZE)
      return RRRTable::combinations[block_len][RRRTable::klass_offset[block_len][k]+off];
    u64 m = block_len-1, r = 0;
    for (; k && k <= m; m--)
      if (RRRTable::binom[m][k] <= off) {
        off -= RRRTable::binom[m][k--];
        r |= 1ull << m;
      }
    if (k)
      r |= (1ull<<k) - 1;
    return r;
  }
public:
  void init(u64 n, u64 block_len, u64 sample_len, const BitSet &data) {
    this->n = n;
    this->block_len = block_len ? block_len : max(clog2(n), u64(15));
    this->sample_len = sample_len ? sample_len : rrr_sample_rate;
    auto& binom = RRRTable::binom;
    auto& offset_bits = RRRTable::offset_bits;
    RRRTable::raise(this->block_len+1);
    build(data);
  }

  void build(const BitSet &data) {
    const auto& offset_bits = RRRTable::offset_bits[block_len];
    nblocks = (n-1+block_len)/block_len;
    rank_sum = 0;
    u64 offset_sum = 0, o = 0;
    REP(i, nblocks) {
      u64 val = data.get_bits(o, min(block_len, n-o)), klass = __builtin_popcountll(val);
      o += block_len;
      rank_sum += klass;
      offset_sum += offset_bits[klass];
    }
    nsamples = (nblocks-1+sample_len)/sample_len;
    klass_bits = clog2(block_len+1);
    rsample_bits = clog2(rank_sum);
    osample_bits = clog2(offset_sum);
    klasses.init(klass_bits*nblocks);
    offsets.init(offset_sum);
    rank_samples.init(rsample_bits*nsamples);
    offset_samples.init(osample_bits*nsamples);

    rank_sum = offset_sum = o = 0;
    REP(i, nblocks) {
      if (i % sample_len == 0) {
        rank_samples.set_bits(i/sample_len*rsample_bits, rsample_bits, rank_sum);
        offset_samples.set_bits(i/sample_len*osample_bits, osample_bits, offset_sum);
      }
      u64 val = data.get_bits(o, min(block_len, n-o)), klass = __builtin_popcountll(val);
      o += block_len;
      klasses.set_bits(klass_bits*i, klass_bits, klass);
      rank_sum += klass;
      offsets.set_bits(offset_sum, offset_bits[klass], block2offset(klass, val));
      offset_sum += offset_bits[klass];
    }
  }

  u64 zero_bits() const { return n-rank_sum; }

  u64 one_bits() const { return rank_sum; }

  bool operator[](u64 i) const {
    const auto& offset_bits = RRRTable::offset_bits[block_len];
    u64 b = i / block_len,
        bi = i % block_len,
        s = b / sample_len,
        j = s * sample_len,
        o = offset_samples.block(osample_bits, s);
    for (; j < b; j++)
      o += offset_bits[klasses.block(klass_bits, j)];
    u64 k = klasses.block(klass_bits, j);
    return offset2block(k, offsets.get_bits(o, offset_bits[k])) >> bi & 1;
  }

  u64 rank0(u64 i) const { return i-rank1(i); }

  u64 rank1(u64 i) const {
    const auto& offset_bits = RRRTable::offset_bits[block_len];
    u64 b = i / block_len,
        bi = i % block_len,
        s = b / sample_len,
        j = s * sample_len,
        r = rank_samples.block(rsample_bits, s),
        o = offset_samples.block(osample_bits, s),
        k;
    for (; j < b; j++) {
      k = klasses.block(klass_bits, j);
      r += k;
      o += offset_bits[k];
    }
    k = klasses.block(klass_bits, j);
    return r + __builtin_popcountll(offset2block(k, offsets.get_bits(o, offset_bits[k])) & (1ull<<bi)-1);
  }

  u64 select0(u64 kth) const {
    if (kth >= zero_bits()) return -1ull;
    const auto& offset_bits = RRRTable::offset_bits[block_len];
    u64 l = 0, h = nsamples;
    while (l < h) {
      u64 m = l+(h-l)/2, idx = m*sample_len*block_len;
      if (idx - rank_samples.block(rsample_bits, m) <= kth)
        l = m+1;
      else
        h = m;
    }

    u64 s = l-1,
        b = sample_len*s,
        r = block_len*b - rank_samples.block(rsample_bits, s),
        o = offset_samples.block(osample_bits, s),
        k;
    for (; ; b++) {
      k = klasses.block(klass_bits, b);
      if (r+block_len-k > kth) break;
      r += block_len-k;
      o += offset_bits[k];
    }

    o = offsets.get_bits(o, offset_bits[k]);
    return block_len*b + select_in_u64(~ offset2block(k, o), kth-r);
  }

  u64 select1(u64 kth) const {
    if (kth >= rank_sum) return -1ull;
    const auto& offset_bits = RRRTable::offset_bits[block_len];
    u64 l = 0, h = nsamples;
    while (l < h) {
      u64 m = l+(h-l)/2;
      if (rank_samples.block(rsample_bits, m) <= kth)
        l = m+1;
      else
        h = m;
    }

    u64 s = l-1,
        b = sample_len*s,
        r = rank_samples.block(rsample_bits, s),
        o = offset_samples.block(osample_bits, s),
        k;
    for (; ; b++) {
      k = klasses.block(klass_bits, b);
      if (r+k > kth) break;
      r += k;
      o += offset_bits[k];
    }

    o = offsets.get_bits(o, offset_bits[k]);
    return block_len*b + select_in_u64(offset2block(k, o), kth-r);
  }

  template<class Archive>
  void serialize(Archive &ar) {
    ar & n & block_len & sample_len & rank_sum & klasses & offsets & rank_samples & offset_samples;
  }

  template<class Archive>
  void deserialize(Archive &ar) {
    serialize(ar);
    nblocks = (n-1+block_len)/block_len;
    nsamples = (nblocks-1+sample_len)/sample_len;
    klass_bits = clog2(block_len+1);
    rsample_bits = clog2(rank_sum);
    osample_bits = clog2(offsets.size());
    RRRTable::raise(block_len+1);
  }
};

class EliasFanoBuilder
{
public:
  u64 n, bound, l, num = 0, pos = 0;
  BitSet lows, highs;

  EliasFanoBuilder(u64 n, u64 bound) : EliasFanoBuilder(n, bound, n && clog2(bound/n)) {}

  EliasFanoBuilder(u64 n, u64 bound, u64 l) : n(n), bound(bound), l(l), lows(l*n), highs((bound>>l)+n+1) {}

  void push(u64 x) {
    if (l) {
      lows.set_bits(pos, l, x & (1ull<<l)-1);
      pos += l;
    }
    highs.set((x>>l) + num++);
  }
};

class EliasFano
{
public:
  u64 n, bound, l;
  BitSet lows;
  RRR highs;
public:
  void init(EliasFanoBuilder &b) {
    n = b.n;
    bound = b.bound;
    l = b.l;
    lows = move(b.lows);
    highs.init((bound>>l)+n+1, 0, 0, b.highs);
  }

  u64 operator[](u64 idx) const {
    u64 ret = highs.select1(idx) - idx << l;
    if (l)
      ret |= lows.get_bits(l*idx, l);
    return ret;
  }

  u64 rank(u64 x) const {
    if (x > bound) return n;
    u64 hi = x >> l, lo = x & (1ull<<l)-1;
    u64 i = highs.select0(hi),
        r = i - hi; // number of elements in highs <= hi
    while (i && highs[i-1] && (l ? lows.get_bits((r-1)*l, l) : 0) >= lo)
      i--, r--;
    return r;
  }

  bool exist(u64 x) const {
    u64 r = rank(x);
    return r < n && operator[](r) == x;
  }

  template<typename Archive>
  void serialize(Archive &ar) {
    ar & n & bound & l & lows & highs;
  }
};

///// Wavelet Matrix

class WaveletMatrix
{
  u64 n;
  RRR rrr[LOGAB];
public:
  WaveletMatrix() {}

  ~WaveletMatrix() {}

  void init(u64 n, u8 *text, u8 *tmp) {
    this->n = n;
    BitSet bs(n);
    REP(d, LOGAB) {
      u64 bit = LOGAB-1-d;
      REP(i, n)
        bs.set(i, text[i] >> bit & 1);
      rrr[d].init(n, 0, 0, bs);
      if (d < LOGAB-1) {
        u64 j = 0;
        REP(i, n)
          if (! (text[i] >> bit & 1))
            tmp[j++] = text[i];
        REP(i, n)
          if (text[i] >> bit & 1)
            tmp[j++] = text[i];
        swap(text, tmp);
      }
    }
  }

  u64 operator[](u64 i) const { return at(i); }
  u64 at(u64 i) const {
    return at(0, 0, AB, i);
  }
  u64 at(u64 d, u64 l, u64 h, u64 i) const {
    if (h-l == 1) return l;
    u64 m = l+h >> 1;
    u64 z = rrr[d].zero_bits();
    return ! rrr[d][i]
      ? at(d+1, l, m, rrr[d].rank0(i))
      : at(d+1, m, h, z+rrr[d].rank1(i));
  }

  // number of occurrences of symbol `x` in [0,i)
  u64 rank(u64 x, u64 i) const {
    return rank(0, 0, AB, x, i, 0);
  }
  u64 rank(u64 d, u64 l, u64 h, u64 x, u64 i, u64 p) const {
    if (h-l == 1) return i-p;
    u64 m = l+h >> 1;
    u64 z = rrr[d].zero_bits();
    return x < m
      ? rank(d+1, l, m, x, rrr[d].rank0(i), rrr[d].rank0(p))
      : rank(d+1, m, h, x, z+rrr[d].rank1(i), z+rrr[d].rank1(p));
  }
  // position of `k`-th occurrence of symbol `x`
  u64 select(u64 x, u64 k) const {
    return select(0, 0, AB, x, k, 0);
  }
  u64 select(u64 d, u64 l, u64 h, u64 x, u64 k, u64 p) const {
    if (l == h-1) return p+k;
    u64 m = l+h >> 1;
    u64 z = rrr[d].zero_bits();
    return x < m
      ? rrr[d].select0(select(d+1, l, m, x, k, rrr[d].rank0(p)))
      : rrr[d].select1(select(d+1, m, h, x, k, z+rrr[d].rank1(p)) - z);
  }

  template<typename Archive>
  void serialize(Archive &ar) {
    ar & n;
    REP(i, LOGAB)
      ar & rrr[i];
  }
};

///// FM-index

class FMIndex
{
  u64 n_, samplerate_, initial_;
  u64 cnt_lt_[AB+1];
  EliasFano sampled_ef_;
  SArray<u32> ssa_;
  WaveletMatrix bwt_wm_;
public:
  void init(u64 n, const u8 *text, u64 samplerate) {
    samplerate_ = samplerate;
    n_ = n;

    u64 cnt = 0;
    fill_n(cnt_lt_, AB, 0);
    REP(i, n)
      cnt_lt_[text[i]]++;
    REP(i, AB) {
      u64 t = cnt_lt_[i];
      cnt_lt_[i] = cnt;
      cnt += t;
    }
    cnt_lt_[AB] = cnt;

    int *sa = new int[n];
    int *tmp = new int[max(2*n, u64(AB))];
    u64 sampled_n = (n-1+samplerate)/samplerate;
    EliasFanoBuilder efb(sampled_n, n-1);
    ssa_.init(sampled_n);

    u64 nn = 0;
    KoAluru::main(text, sa, tmp, n, AB);
    REP(i, n)
      if (sa[i] % samplerate == 0) {
        ssa_[nn++] = sa[i];
        efb.push(i);
      }
    sampled_ef_.init(efb);

    // 'initial' is the position of '$' in BWT of text+'$'
    // BWT of text (sentinel character is implicit)
    u8 *bwt = (u8 *)tmp, *bwt_t = (u8 *)tmp+n;
    initial_ = -1;
    bwt[0] = text[n-1];
    REP(i, n)
      if (! sa[i])
        initial_ = i+1;
      else
        bwt[i + (initial_ == -1)] = text[sa[i]-1];
    bwt_wm_.init(n, bwt, bwt_t);
    delete[] tmp;
    delete[] sa;
  }
  // backward search: count occurrences in rotated string
  pair<u32, u32> get_range(u32 m, const u8 *pattern) const {
    u8 c = pattern[m-1];
    u32 i = m-1, l = cnt_lt_[c], h = cnt_lt_[c+1];
    // [l, h) denotes rows [l+1,h+1) of BWT matrix of text+'$'
    // row 'i' of the first column of BWT matrix is mapped to row i+(i<initial_) of the last column
    while (l < h && i) {
      c = pattern[--i];
      l = cnt_lt_[c] + bwt_wm_.rank(c, l + (l < initial_));
      h = cnt_lt_[c] + bwt_wm_.rank(c, h + (h < initial_));
    }
    return {l, h};
  }
  // m > 0
  u32 count(u32 m, const u8 *pattern) const {
    if (! m) return n_;
    auto x = get_range(m, pattern);
    return x.second-x.first;
  }

  u32 calc_sa(u32 rank) const {
    u32 d = 0, i = rank;
    while (! sampled_ef_.exist(i)) {
      int c = bwt_wm_[i + (i < initial_)];
      i = cnt_lt_[c] + bwt_wm_.rank(c, i + (i < initial_));
      d++;
    }
    return ssa_[sampled_ef_.rank(i)] + d;
  }

  u32 locate(u32 m, const u8 *pattern, bool autocomplete, u32 limit, u32 &skip, vector<u32> &res) const {
    u32 l, h, total;
    if (m) {
      auto x = get_range(m, pattern);
      l = x.first;
      h = x.second;
    } else {
      l = 0;
      h = n_;
    }
    total = h-l;
    u32 delta = min(h-l, skip);
    l += delta;
    skip -= delta;
    u32 step = autocomplete ? max((h-l)/limit, u32(1)) : 1;
    for (; l < h && res.size() < limit; l += step) {
      u32 d = 0, i = l;
      while (! sampled_ef_.exist(i)) {
        int c = bwt_wm_[i + (i < initial_)];
        i = cnt_lt_[c] + bwt_wm_.rank(c, i + (i < initial_));
        d++;
      }
      u32 pos = ssa_[sampled_ef_.rank(i)] + d;
      res.push_back(pos);
    }
    return total;
  }

  template<typename Archive>
  void serialize(Archive &ar) {
    ar & n_ & samplerate_ & initial_;
    REP(i, LEN_OF(cnt_lt_))
      ar & cnt_lt_[i];
    ar & sampled_ef_;
    ar & ssa_;
    ar & bwt_wm_;
  }
};

// serialization
//
// http://stackoverflow.com/questions/257288/is-it-possible-to-write-a-c-template-to-check-for-a-functions-existence
struct Serializer
{
  FILE *fh_;

  Serializer(FILE *fh) : fh_(fh) {}

  template<class T>
  auto serialize_imp(T &x, int) -> decltype(x.serialize(*this), void()) {
    x.serialize(*this);
  }

  template<class T>
  void serialize_imp(T &x, long) {
    fwrite(&x, sizeof x, 1, fh_);
  }

  template<class T>
  Serializer& operator&(T &x) {
    serialize_imp(x, 0);
    return *this;
  }

  Serializer& operator&(u64 &x) {
    // u64 scalars are serialized as u32 to save space
    fwrite(&x, sizeof(u32), 1, fh_);
    return *this;
  }

  void uint64(u64 &x) {
    fwrite(&x, sizeof(u64), 1, fh_);
  }

  template<class S, class T>
  void array(S n, T *a) {
    operator&(n);
    align(alignof(T));
    REP(i, n)
      operator&(a[i]);
  }

  template<class S>
  void array(S n, u64 *a) {
    operator&(n);
    align(alignof(u64));
    REP(i, n)
      uint64(a[i]);
  }

  void align(size_t n) {
    off_t o = ftello(fh_);
    if (o == -1)
      err_exit(EX_IOERR, "ftello");
    if (o%n && fseek(fh_, o+n-o%n, SEEK_SET))
      err_exit(EX_IOERR, "fseek");
  }
};

struct Deserializer
{
  void *a_;

  Deserializer(void *a) : a_(a) {}

  template<class T>
  Deserializer &operator&(T &x) {
    deserialize_imp0(x, 0);
    return *this;
  }

  Deserializer& operator&(u64 &x) {
    memcpy(&x, a_, sizeof(u32));
    a_ = (u32 *)a_ + 1;
    return *this;
  }

  // has .deserialize
  template<class T>
  auto deserialize_imp0(T &x, int) -> decltype(x.deserialize(*this), void()) {
    x.deserialize(*this);
  }
  template<class T>
  void deserialize_imp0(T &x, long) {
    deserialize_imp1(x, 0);
  }

  // has .serialize
  template<class T>
  auto deserialize_imp1(T &x, int) -> decltype(x.serialize(*this), void()) {
    x.serialize(*this);
  }

  // fallback
  template<class T>
  void deserialize_imp1(T &x, long) {
    memcpy(&x, a_, sizeof(T));
    a_ = (T *)a_ + 1;
  }

  void uint64(u64 &x) {
    deserialize_imp1(x, 0);
  }

  template<class S, class T>
  void array(S n, T *a) {
    operator&(n);
    REP(i, n)
      operator&(a[i]);
  }

  template<class S>
  void array(S n, u64 *a) {
    operator&(n);
    REP(i, n)
      uint64(a[i]);
  }

  void align(size_t n) {
    auto o = (uintptr_t)a_ % n;
    if (o)
      a_ = (void*)((uintptr_t)a_+o);
  }

  void skip(size_t n) {
    a_ = (void*)((uintptr_t)a_+n);
  }
};

void print_help(FILE *fh)
{
  fprintf(fh, "Usage: %s [OPTIONS] dir\n", program_invocation_short_name);
  fputs(
        "\n"
        "Options:\n"
        "  index mode:\n"
        "  --autocomplete-length L\n"
        "  --autocomplete-limit C\n"
        "  --fmindex-sample-rate R   sample rate of suffix array (for rank -> pos) used in FM index\n"
        "  --rrr-sample-rate R       R blocks are grouped to a superblock\n"
        "  -o, --oneshot             run only once (no inotify)\n"
        "\n"
        "  server mode:\n"
        "  -c, --request-count       max number of requests (default: -1)\n"
        "  -l, --search-limit        max number of results\n"
        "\n"
        "  others:\n"
        "  -i, --index               index mode. (default: server mode)\n"
        "  -r, --recursive           recursive\n"
        "  -s, --data-suffix         data file suffix. (default: .ap)\n"
        "  -S, --index-suffix        index file suffix. (default: .fm)\n"
        "  -h, --help                display this help and exit\n"
        "\n"
        "Examples:\n"
        "  zsh0: ./indexer -o -i /tmp/ray && ./indexer /tmp/ray # build index oneshot and run server\n"
        "  zsh0: ./indexer -i /tmp/ray # build index and use inotify to watch changes within /tmp/ray, creating indices upon CLOSE_WRITE after CREATE/MODIFY, and MOVED_TO, removing indices upon DELETE and MOVED_FROM\n"
        "  zsh1: print -rn -- $'\\0\\0\\0haystack' | socat -t 60 - /tmp/search.sock # autocomplete\n"
        "  zsh1: print -rn -- $'3\\0\\0\\0haystack' | socat -t 60 - /tmp/search.sock # search, offset=3\n"
        "  zsh1: print -rn -- $'5\\0a\\0b\\0ha\\0stack\\0' | socat -t 60 - /tmp/search.sock # search filenames F satisfying (\"a\" <= F <= \"b\"), offset=5. NUL is allowed in pattern\n"
        , fh);
  exit(fh == stdout ? 0 : EX_USAGE);
}

struct Entry
{
  int data_fd, index_fd, data_size, index_size;
  void *data_mmap, *index_mmap;
  FMIndex *fm;
  ~Entry() {
    delete fm;
    munmap(data_mmap, data_size);
    munmap(index_mmap, index_size);
    close(data_fd);
    close(index_fd);
  }
};

bool is_data(const string &path)
{
  return path.size() >= data_suffix.size() && path.substr(path.size()-data_suffix.size()) == data_suffix;
}

bool is_index(const string &path)
{
  return path.size() >= index_suffix.size() && path.substr(path.size()-index_suffix.size()) == index_suffix;
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

string data_to_index(const string& path)
{
  return path+index_suffix;
}

string index_to_data(const string& path)
{
  return path.substr(0, path.size()-index_suffix.size());
}

template<class Key, class Val>
struct RefCountTreap {
  ~RefCountTreap() { clear(); }

  struct Node {
    Key key;
    Val val;
    Node* c[2] = {};
    int refcnt = 1, pri;
    Node(const Key& key, const Val& val) : key(key), val(val), pri(rand()) {}
    Node(const Node& x) : key(x.key), val(x.val), c{x.c[0], x.c[1]}, pri(x.pri) {
      if (c[0]) c[0]->refcnt++;
      if (c[1]) c[1]->refcnt++;
    }
    void unref() { if (! --refcnt) delete this; }
    ~Node() {
      if (c[0]) c[0]->unref();
      if (c[1]) c[1]->unref();
    }
  } *root = nullptr;
  static vector<Node*> roots;

  void clear() {
    if (root) {
      root->unref();
      root = nullptr;
    }
  }

  Node* find(const Key& key) {
    return find(root, key);
  }
  Node* find(Node* x, const Key& key) {
    for(;;) {
      if (x->key < key) x = x->c[0];
      else if (x->key > key) x = x->c[1];
      else break;
    }
    return x;
  }


  void insert(const Key& key, const Val& val) {
    roots.push_back(root);
    if (root) root->refcnt++;
    insert(root, key, val);
  }
  void insert(Node*& x, const Key& key, const Val& val) {
    if (! x)
      x = new Node(key, val);
    else {
      x->unref();
      x = new Node(*x);
      long d = x->key < key;
      insert(x->c[d], key, val);
      if (x->c[d]->pri < x->pri)
        zag(x, d);
    }
  }

  void erase(const Key& key) {
    roots.push_back(root);
    if (root) root->refcnt++;
    erase(root, key);
  }
  void erase(Node*& x, const Key& key) {
    if (! x) return;
    Node* y = x;
    if (key < x->key)
      x = new Node(*x), y->unref(), erase(x->c[0], key);
    else if (key > x->key)
      x = new Node(*x), y->unref(), erase(x->c[1], key);
    else if (! x->c[0])
      x = x->c[1], y->unref(), x && x->refcnt++;
    else if (! x->c[1])
      x = x->c[0], y->unref(), x && x->refcnt++;
    else if (x->c[0]->key == key)
      x = new Node(*x), y->unref(), erase(x->c[0], key);
    else if (x->c[1]->key == key)
      x = new Node(*x), y->unref(), erase(x->c[1], key);
    else {
      x = new Node(*x);
      y->unref();
      long d = x->c[0]->pri < x->c[1]->pri;
      x->c[d]->unref();
      x->c[d] = new Node(*x->c[d]);
      zag(x, d);
      erase(x->c[d^1], key);
    }
  }
  void zag(Node*& x, long d) {
    Node* y = x->c[d];
    x->c[d] = y->c[d^1];
    y->c[d^1] = x;
    x = y;
  }

  struct Backward {
    vector<Node*> st;
    Node* x;
    Backward(Node* x) : x(x) {}
    void step() {
      for (; x; x = x->c[1])
        st.push_back(x);
      if (st.size()) {
        x = st.back();
        st.pop_back();
      }
    }
    Backward begin() {
      step();
      return *this;
    }
    Backward end() { return Backward(nullptr); }
    bool operator!=(const Backward& o) { return x != o.x; }
    Backward operator++() {
      x = x->c[0];
      step();
      return *this;
    }
    Node& operator*() { return *x; }
  };

  Backward backward(Node* x) { return Backward(x); }
};

template<> vector<RefCountTreap<string, shared_ptr<Entry>>::Node*> RefCountTreap<string, shared_ptr<Entry>>::roots{};

namespace Server
{
  int inotify_fd;
  map<int, string> wd2dir;
  map<string, int> dir2wd;
  set<string> modified;
  RefCountTreap<string, shared_ptr<Entry>> loaded;
  pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
  pthread_cond_t cleaner_cond = PTHREAD_COND_INITIALIZER;
  bool cleaner_quit = false;

  void detached_thread(void* (*start_routine)(void*), void* data) {
    ongoing++;
    pthread_t tid;
    pthread_attr_t attr;
    pthread_attr_init(&attr);
    if (pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED))
      err_exit(EX_OSERR, "pthread_attr_setdetachstate");
    if (pthread_create(&tid, &attr, start_routine, data))
      err_exit(EX_OSERR, "pthread_create");
    pthread_attr_destroy(&attr);
  }

  int inotify_add_dir(const string& dir) {
    int wd = inotify_add_watch(inotify_fd, dir.c_str(), IN_CLOSE_WRITE | IN_CREATE | IN_DELETE | IN_IGNORED | IN_MODIFY | IN_MOVE | IN_MOVE_SELF);
    if (wd < 0) {
      err_msg("failed to inotify_add_watch '%s'", dir.c_str());
      return wd;
    }
    wd2dir[wd] = dir;
    dir2wd[dir] = wd;
    log_action("inotify_add_watch '%s'\n", dir.c_str());
    return wd;
  }

  void rm_data(const string& data_path) {
    string index_path = data_to_index(data_path);
    if (! unlink(index_path.c_str()))
      log_action("unlinked %s\n", index_path.c_str());
    else if (errno != ENOENT)
      err_msg("failed to unlink %s", index_path.c_str());
    if (loaded.find(data_path)) {
      loaded.erase(index_path);
      log_action("unloaded index of %s\n", data_path.c_str());
    }
  }

  void* add_data_worker(void* data_path_) {
    string* data_path = (string*)data_path_;
    string index_path = data_to_index(*data_path);
    int index_fd = -1, data_fd = -1;
    off_t data_size;
    void* data_mmap = MAP_FAILED;
    FILE* fh = NULL;
    errno = 0;
    if ((data_fd = open(data_path->c_str(), O_RDONLY)) < 0)
      goto quit;
    if ((data_size = lseek(data_fd, 0, SEEK_END)) < 0)
      goto quit;
    if ((index_fd = open(index_path.c_str(), O_RDWR | O_CREAT, 0666)) < 0)
      goto quit;
    {
      char buf[8];
      int nread;
      if ((nread = read(index_fd, buf, 8)) < 0)
        goto quit;
      // skip good index file
      if (nread == 0)
       ;
      else if (nread < 4 || memcmp(buf, MAGIC_GOOD, 4))
        log_status("index file %s: bad magic, rebuilding\n", index_path.c_str());
      else if (nread < 8 || ((i32*)buf)[1] != data_size)
        log_status("index file %s: mismatching length of data file, rebuilding\n", index_path.c_str());
      else
        goto quit;
    }
    if (data_size > 0 && (data_mmap = mmap(NULL, data_size, PROT_READ, MAP_SHARED, data_fd, 0)) == MAP_FAILED)
      goto quit;
    if (! (fh = fdopen(index_fd, "w")))
      goto quit;
    if (data_size > 0) {
      StopWatch sw;
      if (fseek(fh, 0, SEEK_SET) < 0)
        err_exit(EX_IOERR, "fseek");
      if (fputs(MAGIC_BAD, fh) < 0)
        err_exit(EX_IOERR, "fputs");
      if (fputs(MAGIC_BAD, fh) < 0) // length of origin
        err_exit(EX_IOERR, "fputs");
      Serializer ar(fh);
      FMIndex fm;
      fm.init(data_size, (const u8 *)data_mmap, fmindex_sample_rate);
      ar & fm;
      long index_size = ftell(fh);
      ftruncate(index_fd, index_size);
      fseek(fh, 0, SEEK_SET);
      fputs(MAGIC_GOOD, fh);
      fwrite(&data_size, 4, 1, fh);
      if (ferror(fh)) {
        unlink(index_path.c_str());
        goto quit;
      }
      log_action("created index of %s. data: %ld, index: %ld, used %.3lf s\n", data_path->c_str(), data_size, index_size, sw.elapsed());
    }
quit:
    if (fh)
      fclose(fh);
    else if (index_fd >= 0)
      close(index_fd);
    if (data_mmap != MAP_FAILED)
      munmap(data_mmap, data_size);
    if (data_fd >= 0)
      close(data_fd);
    delete data_path;
    if (errno)
      err_msg("failed to index %s", data_path->c_str());
    ongoing--;
    return NULL;
  }

  void add_data(const string& data_path) {
    detached_thread(add_data_worker, new string(data_path));
  }

  void rm_index(const string& index_path) {
    string data_path = index_path.substr(index_path.size()-index_suffix.size());
    if (! is_data(data_path)) return;
    if (loaded.find(data_path)) {
      loaded.erase(index_path);
      log_action("unloaded index of %s\n", data_path.c_str());
    }
  }

  void add_index(const string& index_path) {
    string data_path = index_to_data(index_path);
    if (! is_data(data_path)) return;
    auto entry = make_shared<Entry>();
    entry->data_mmap = entry->index_mmap = MAP_FAILED;
    errno = 0;
    if ((entry->data_fd = open(data_path.c_str(), O_RDONLY)) < 0)
      goto quit;
    if ((entry->index_fd = open(index_path.c_str(), O_RDONLY)) < 0) {
      if (errno == ENOENT) {
        errno = 0;
        log_status("skiping %s: no index\n", data_path.c_str());
      }
      goto quit;
    }
    if ((entry->data_size = lseek(entry->data_fd, 0, SEEK_END)) < 0)
      goto quit;
    if ((entry->index_size = lseek(entry->index_fd, 0, SEEK_END)) < 0)
      goto quit;
    if (entry->data_size > 0 && (entry->data_mmap = mmap(NULL, entry->data_size, PROT_READ, MAP_SHARED, entry->data_fd, 0)) == MAP_FAILED)
      goto quit;
    if (entry->index_size > 0 && (entry->index_mmap = mmap(NULL, entry->index_size, PROT_READ, MAP_SHARED, entry->index_fd, 0)) == MAP_FAILED)
      goto quit;
    rm_index(index_path);
    if (entry->index_size < 8) {
      log_status("invalid index file %s: length < 8\n", index_path.c_str());
      goto quit;
    }
    if (memcmp(entry->index_mmap, MAGIC_GOOD, 4)) {
      log_status("index file %s: bad magic\n", index_path.c_str());
      goto quit;
    }
    if (((int*)entry->index_mmap)[1] != entry->data_size) {
      log_status("index file %s: mismatching length of data file\n", index_path.c_str());
      goto quit;
    }
    if (entry->index_size > 0) {
      Deserializer ar((char*)entry->index_mmap+strlen(MAGIC_GOOD)+4);
      entry->fm = new FMIndex;
      ar & *entry->fm;
      pthread_mutex_lock(&mutex);
      loaded.insert(data_path, entry);
      pthread_cond_signal(&cleaner_cond);
      pthread_mutex_unlock(&mutex);
      log_action("loaded index of %s\n", data_path.c_str());
    }
    return;
quit:
    if (entry->data_mmap != MAP_FAILED)
      munmap(entry->data_mmap, entry->data_size);
    if (entry->index_mmap != MAP_FAILED)
      munmap(entry->index_mmap, entry->index_size);
    if (entry->data_fd >= 0)
      close(entry->data_fd);
    if (entry->index_fd >= 0)
      close(entry->index_fd);
    if (errno)
      err_msg("failed to load index file %s", index_path.c_str());
  }

  void walk(long depth, long dir_fd, string path, const char* file) {
    int fd = -1;
    struct stat statbuf;
    if (stat(path.c_str(), &statbuf) < 0)
      err_msg_g("stat");
    if (S_ISREG(statbuf.st_mode)) {
      if (is_data(path)) add_data(path);
      if (is_index(path)) add_index(path);
    } else if (S_ISDIR(statbuf.st_mode)) {
      if (! opt_recursive && depth > 0) goto quit;
      if (inotify_fd >= 0)
        inotify_add_dir(path);
      fd = openat(dir_fd, file, O_RDONLY);
      if (fd < 0)
        err_msg_g("failed to open '%s'", path.c_str());
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

  void process_inotify() {
    char buf[sizeof(inotify_event)+NAME_MAX+1];
    int nread;
    if ((nread = read(inotify_fd, buf, sizeof buf)) <= 0)
      err_exit(EX_OSERR, "failed to read inotify fd");
    errno = 0;
    for (auto *ev = (inotify_event *)buf; (char *)ev < (char *)buf+nread;
         ev = (inotify_event *)((char *)ev + sizeof(inotify_event) + ev->len))
      if (ev->len > 0 || ev->mask & (IN_IGNORED | IN_MOVE_SELF)) {
        const char* dir = wd2dir[ev->wd].c_str();
        bool data = is_data(ev->name), index = is_index(ev->name);
        string path = to_path(dir, ev->name);
        if (ev->mask & (IN_CREATE | IN_MOVED_TO)) {
          if (ev->mask & IN_CREATE)
            log_event("CREATE %s\n", path.c_str());
          else
            log_event("MOVED_TO %s\n", path.c_str());

          if (ev->mask & IN_ISDIR)
            opt_recursive && inotify_add_dir(path.c_str());
          else if (data || index) {
            struct stat statbuf;
            if (lstat(path.c_str(), &statbuf) < 0) continue;
            if (ev->mask & IN_MOVED_TO || S_ISLNK(statbuf.st_mode)) {
              modified.erase(path);
              if (data) add_data(path);
              if (index) add_index(path);
            } else
              modified.insert(path);
          }
        } else if (ev->mask & (IN_DELETE | IN_MOVED_FROM)) {
          if (ev->mask & IN_DELETE)
            log_event("DELETE %s\n", path.c_str());
          else
            log_event("MOVED_FROM %s\n", path.c_str());
          if (! (ev->mask & IN_ISDIR)) {
            modified.erase(path);
            if (data) rm_data(path);
            if (index) rm_index(path);
          }
        } else if (ev->mask & IN_IGNORED) {
          log_event("IGNORED %s\n", dir);
          if (wd2dir.count(ev->wd)) {
            dir2wd.erase(wd2dir[ev->wd]);
            wd2dir.erase(ev->wd);
          }
        } else if (ev->mask & IN_MODIFY) {
          if (data || index)
            modified.insert(path);
        } else if (ev->mask & IN_MOVE_SELF)
          err_exit(EX_OSFILE, "'%s' has been moved", wd2dir[ev->wd].c_str());
        else if (ev->mask & IN_CLOSE_WRITE) {
          if (modified.count(path)) {
            log_event("CLOSE_WRITE after MODIFY %s\n", path.c_str());
            modified.erase(path);
            if (data) add_data(path);
            if (index) add_index(path);
          }
        }
      }
  }

  void* request_worker(void* connfd_) {
    int connfd = intptr_t(connfd_);
    char buf[BUF_SIZE] = {};
    const char *p, *file_begin = buf, *file_end = nullptr;
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
    file_begin = p;
    for (; p < buf+nread && *p; p++);
    if (++p >= buf+nread) goto quit;
    file_end = p;
    for (; p < buf+nread && *p; p++);
    if (++p >= buf+nread) goto quit;

    {
      pthread_mutex_lock(&mutex);
      auto* root = loaded.root;
      if (root) root->refcnt++;
      pthread_mutex_unlock(&mutex);

      u32 len = buf+nread-p, total = 0, t;
      // autocomplete
      if (! buf[0]) {
        typedef tuple<string, u32, string> cand_type;
        u32 skip = 0;
        vector<u32> res;
        vector<cand_type> candidates;
        for (auto& it: loaded.backward(root)) {
          auto entry = it.val;
          if (entry->data_size > 0) {
            auto old_size = res.size();
            string pattern = unescape(len, p);
            entry->fm->locate(pattern.size(), (const u8*)pattern.c_str(), true, autocomplete_limit, skip, res);
            FOR(i, old_size, res.size())
              candidates.emplace_back(it.key, res[i], string((char*)entry->data_mmap+res[i], (char*)entry->data_mmap+min(long(entry->data_size), res[i]+len+autocomplete_length)));
            if (res.size() >= autocomplete_limit) break;
          }
        }
        sort(candidates.begin(), candidates.end());
        candidates.erase(unique(candidates.begin(), candidates.end(), [](const cand_type &x, const cand_type &y) {
                                return get<2>(x) == get<2>(y);
                                }), candidates.end());
        for (auto& cand: candidates)
          if (dprintf(connfd, "%s\t%u\t%s\n", get<0>(cand).c_str(), get<1>(cand), escape(get<2>(cand)).c_str()) < 0)
            goto quit;
      } else {
        char *end;
        errno = 0;
        u32 skip = strtol(buf, &end, 0);
        if (! *end && ! errno) {
          vector<u32> res;
          for (auto& it: loaded.backward(root)) {
            auto entry = it.val;
            if ((! *file_begin || string(file_begin) <= it.key) && (! *file_end || it.key <= string(file_end)) && entry->data_size > 0) {
              auto old_size = res.size();
              string pattern = unescape(len, p);
              total += entry->fm->locate(pattern.size(), (const u8*)pattern.c_str(), false, search_limit, skip, res);
              FOR(i, old_size, res.size())
                if (dprintf(connfd, "%s\t%u\t%u\n", it.key.c_str(), res[i], len) < 0)
                  goto quit;
              if (res.size() >= autocomplete_limit) break;
            }
          }
          dprintf(connfd, "%u\n", total);
        }
      }

      pthread_mutex_lock(&mutex);
      if (root) root->unref();
      pthread_mutex_unlock(&mutex);
    }
quit:
    close(connfd);
    ongoing--;
    return NULL;
  }

  void* cleaner(void*) {
    for(;;) {
      pthread_mutex_lock(&mutex);
      while (! cleaner_quit && loaded.roots.empty())
        pthread_cond_wait(&cleaner_cond, &mutex);
      while (loaded.roots.size()) {
        if (loaded.roots.back())
          loaded.roots.back()->unref();
        loaded.roots.pop_back();
      }
      pthread_mutex_unlock(&mutex);
      if (cleaner_quit) break;
    }
    ongoing--;
    return NULL;
  }

  void run() {
    signal(SIGPIPE, SIG_IGN); // SIGPIPE while writing to clients

    int sockfd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (sockfd < 0)
      err_exit(EX_OSERR, "socket");
    struct sockaddr_un addr = {};
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, listen_path, sizeof(addr.sun_path)-1);
    unlink(addr.sun_path);
    if (bind(sockfd, (struct sockaddr *)&addr, sizeof addr) < 0)
      err_exit(EX_OSERR, "bind");
    if (listen(sockfd, 1) < 0)
      err_exit(EX_OSERR, "listen");

    // load existing
    if (opt_inotify) {
      if ((inotify_fd = inotify_init()) < 0)
        err_exit(EX_OSERR, "inotify_init");
      log_status("start inotify\n");
    }
    for (auto dir: data_dir)
      walk(0, AT_FDCWD, dir, dir);

    while (request_count) {
      struct pollfd fds[3];
      fds[0].fd = log_pipe[0];
      fds[0].events = POLLIN;
      fds[1].fd = sockfd;
      fds[1].events = POLLIN;
      int nfds = 2;
      if (inotify_fd >= 0) {
        fds[2].fd = inotify_fd;
        fds[2].events = POLLIN;
        nfds = 3;
      }
      int ready = poll(fds, nfds, -1);
      if (ready < 0) {
        if (errno == EINTR) continue;
        err_exit(EX_OSERR, "poll");
      }
      if (fds[0].revents & POLLIN) { // log pipe
        char buf[BUF_SIZE];
        ssize_t nread = read(log_pipe[0], buf, sizeof buf);
        if (nread < 0) {
          if (errno != EINTR)
            err_exit(EX_IOERR, "read");
        } else
          write(STDOUT_FILENO, buf, nread);
      }
      if (fds[1].revents & POLLIN) { // socket
        int connfd = accept(sockfd, NULL, NULL);
        if (connfd < 0) err_exit(EX_OSERR, "accept");
        detached_thread(request_worker, (void*)(intptr_t)connfd);
        if (request_count > 0) request_count--;
      }
      if (2 < nfds && fds[2].revents & POLLIN) // inotifyfd
        process_inotify();
    }
    if (inotify_fd >= 0)
      close(inotify_fd);
    close(sockfd);
    cleaner_quit = true;
    pthread_cond_signal(&cleaner_cond);
    // destructors should be called after all readers & writers of RefCountTreap have finished
    while (ongoing.load() > 0)
      usleep(50*1000);
    for (auto x: loaded.roots)
      if (x)
        x->unref();
  }
}

int main(int argc, char *argv[])
{
  bool is_index_mode = false;
  bool opt_inotify = true;

  int opt;
  static struct option long_options[] = {
    {"autocomplete-length", required_argument, 0,   2},
    {"autocomplete-limit",  required_argument, 0,   3},
    {"data-suffix",         required_argument, 0,   's'},
    {"fmindex-sample-rate", required_argument, 0,   'f'},
    {"help",                no_argument,       0,   'h'},
    {"index",               no_argument,       0,   'i'},
    {"index-suffix",        required_argument, 0,   'S'},
    {"oneshot",             no_argument,       0,   'o'},
    {"recursive",           no_argument,       0,   'r'},
    {"request-count",       required_argument, 0,   'c'},
    {"request-timeout",     required_argument, 0,   4},
    {"rrr-sample-rate",     required_argument, 0,   5},
    {0,                     0,                 0,   0},
  };

  while ((opt = getopt_long(argc, argv, "-c:f:hil:op:rs:S:", long_options, NULL)) != -1) {
    switch (opt) {
    case 1: {
      struct stat statbuf;
      if (stat(optarg, &statbuf) < 0)
        err_exit(EX_OSFILE, "stat");
      if (! S_ISDIR(statbuf.st_mode))
        err_exit(EX_USAGE, "%s is not a directory", optarg);
      data_dir.push_back(optarg);
      break;
    }
    case 2:
      autocomplete_length = get_long(optarg);
      break;
    case 3:
      autocomplete_limit = get_long(optarg);
      break;
    case 4:
      request_timeout = get_double(optarg);
      break;
    case 5:
      rrr_sample_rate = get_long(optarg);
      break;
    case 'c':
      request_count = get_long(optarg);
      break;
    case 'f':
      fmindex_sample_rate = get_long(optarg);
      break;
    case 'h':
      print_help(stdout);
      break;
    case 'i':
      is_index_mode = true;
      break;
    case 'l':
      search_limit = get_long(optarg);
      break;
    case 'o':
      opt_inotify = false;
      break;
    case 'p':
      listen_path = optarg;
      break;
    case 'r':
      opt_recursive = true;
      break;
    case 's':
      data_suffix = optarg;
      break;
    case 'S':
      index_suffix = optarg;
      break;
    case '?':
      print_help(stderr);
      break;
    }
  }
  if (data_dir.empty())
    print_help(stderr);

#define D(name) printf("%s: %ld\n", #name, name)

  RRRTable::init();
  if (pipe(log_pipe) < 0)
    err_exit(EX_OSERR, "pipe");

  D(fmindex_sample_rate);
  D(rrr_sample_rate);
  D(autocomplete_length);
  D(autocomplete_limit);
  D(search_limit);
  Server::run();

#undef D
}
