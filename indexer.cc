#ifndef _GNU_SOURCE
# define _GNU_SOURCE
#endif
#include <algorithm>
#include <arpa/inet.h>
#include <cassert>
#include <cctype>
#include <climits>
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
#include <sys/time.h>
#include <sys/un.h>
#include <sysexits.h>
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

const size_t BUF_SIZE = 512;
const char LISTEN_PATH[] = "/tmp/search.sock";
const string PCAP_SUFFIX = ".ap";
const string INDEX_SUFFIX = ".fm";
const int SAMPLE_RATE = 32;
const int SEARCH_LIMIT = 20;
const int AUTOCOMPLETE_LIMIT = 20;
const int AUTOCOMPLETE_LENGTH = 20;
const int CONTEXT_LENGTH = 30;
const long REQUEST_TIMEOUT_MILLI = 1000;

///// log

void log_generic(const char *prefix, const char *format, va_list ap)
{
  char buf[BUF_SIZE];
  timeval tv;
  tm tm;
  gettimeofday(&tv, NULL);
  fputs(prefix, stdout);
  if (localtime_r(&tv.tv_sec, &tm)) {
    strftime(buf, sizeof buf, "%T.%%06u ", &tm);
    printf(buf, tv.tv_usec);
  }
  vprintf(format, ap);
  fputs(SGR0, stdout);
  fflush(stdout);
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

///// common

u32 clog2(u32 x)
{
  return x > 1 ? 32-__builtin_clz(x-1) : 0;
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
        ret += char(from_hex(str[i+2])*16+from_hex(str[i+3]));
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

template<class Fwd>
struct Reverser
{
  const Fwd &fwd_;
  Reverser<Fwd>(const Fwd &fwd): fwd_(fwd) {}
  auto begin() -> decltype(fwd_.rbegin()) const { return fwd_.rbegin(); }
  auto end() -> decltype(fwd_.rend()) const  { return fwd_.rend(); }
};

template<class Fwd>
Reverser<Fwd> make_reverse_iterator(const Fwd &fwd) { return Reverser<Fwd>(fwd); }

///// vector

template<class T>
class SArray
{
  u32 n_ = 0;
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

  void init(u32 n) {
    assert(! a_ && ! is_created_); // not loaded
    is_created_ = true;
    n_ = n;
    a_ = new T[n];
  }

  void init(u32 n, const T &x) {
    init(n);
    fill_n(a_, n, x);
  }

  u32 size() const { return n_; }

  T &operator[](u32 i) { return a_[i]; }

  const T &operator[](u32 i) const { return a_[i]; }

  T *begin() { return a_; }

  T *end() { return a_+n_; }

  template<typename Archive>
  void serialize(Archive &ar) {
    ar.array(n_, a_);
    //if (n_ >= 3000)
    //printf("+ %ld * %d\n", sizeof(T), n_);
  }
};

///// bitset

class BitSet
{
  u32 n_;
  SArray<u64> a_;
public:
  BitSet() {}

  BitSet(u32 n) {
    init(n);
  }

  void init(u32 n) {
    n_ = n;
    a_.init((n-1+64)/64, 0);
  }

  const SArray<u64> &words() const { return a_; }

  void set(u32 x) { set(x, true); }

  void set(u32 x, bool b) {
    if (b)
      a_[x/64] |= 1ull << x%64;
    else
      a_[x/64] &= ~ (1ull << x%64);
  }

  bool operator[](u32 x) const {
    return a_[x/64] & 1ull << x%64;
  }

  u64 get_bits(u32 x, u32 k) const {
    if (x % 64 + k <= 64)
      return (a_[x/64] >> x%64) & (1ull<<k)-1;
    return (a_[x/64] >> x%64 | a_[x/64+1] << 64-x%64) & (1ull<<k)-1;
  }

  u64 block(u32 k, u32 x) const { return get_bits(x*k, k); }

  void set_bits(u32 x, u32 k, u64 v) {
    if (! k) return;
    if (x % 64 + k <= 64) {
      u32 i = x%64;
      a_[x/64] = a_[x/64] & ~ (((1ull<<k)-1) << i) | v << i;
    } else {
      u32 i = x%64;
      a_[x/64] = a_[x/64] & ~ (-1ull<<i) | v << i;
      u32 j = k-(64-i);
      a_[x/64+1] = a_[x/64+1] & (-1ull<<j) | v >> 64-i;
    }
  }

  u32 size() const {
    return n_;
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

  // Juha Kärkkäinen et al.'s Φ permulated LCP construction algorithm
  template<typename T>
  void calc_lcp(T a[], int sa[], int n, int plcp[], int lcp[])
  {
    REP(i, n)
      plcp[sa[i]] = i ? sa[i-1] : -1; // plcp -> phi
    int l = 0;
    REP(i, n) {
      int j = plcp[i];
      if (j != -1)
        for (; a[i+l] == a[j+l]; l++);
      plcp[i] = l;
      l && l--;
    }
    REP(i, n)
      lcp[i] = plcp[sa[i]];
  }

  void calc_child(int lcp[], int n, int child[]) {
    stack<int> st;
    st.push(0);
    int last = -1;
    fill_n(child, n, -1);
    FOR(i, 1, n) {
      while (lcp[i] < lcp[st.top()]) {
        last = st.top();
        st.pop();
        if (lcp[i] <= lcp[st.top()] && lcp[st.top()] != lcp[last])
          child[st.top()] = last;
      }
      if (last != -1) {
        child[i-1] = last;
        last = -1;
      }
      st.push(i);
    }
    while (0 < lcp[st.top()]) {
      last = st.top();
      st.pop();
      if (0 <= lcp[st.top()] && lcp[st.top()] != lcp[last])
        child[st.top()] = last;
    }

    while (! st.empty())
      st.pop();
    st.push(0);
    FOR(i, 1, n) {
      while (lcp[i] < lcp[st.top()])
        st.pop();
      if (lcp[i] == lcp[st.top()]) {
        child[st.top()] = i;
        st.pop();
      }
      st.push(i);
    }
  }

  int get_lcp(int lcp[], int child[], int i, int j)
  {
    if (i == j-1) return lcp[j];
    int k = child[j-1]; // up[j]
    if (i < k && k <= j)
      return lcp[k];
    return child[i] != -1 ? lcp[child[i]] : -1; // down[j]
  }

  void get_child_intervals(int lcp[], int child[], int l, int h)
  {
    printf("(%d %d)\n", l, h);
    if (l >= h-1) return;
    int i = l < child[h-1] && child[h-1] < h ? child[h-1] : child[l];
    get_child_intervals(lcp, child, l, i);
    for (; child[i] > i && lcp[child[i]] == lcp[i]; i = child[i]) // next[i]
      get_child_intervals(lcp, child, i, child[i]);
    get_child_intervals(lcp, child, i, h);
  }

  template<typename T>
  pair<int, int> get_interval(T a[], int sa[], int lcp[], int child[], int n, int l, int h, int d, T c)
  {
    int i = h < n && l < child[h-1] && child[h-1] < h ? child[h-1] : child[l];
    if (sa[l]+d < n && a[sa[l]+d] == c)
      return make_pair(l, i);
    for (; child[i] > i && lcp[child[i]] == lcp[i]; i = child[i]) { // next[i]
      if (a[sa[i]+d] == c)
        return make_pair(i, child[i]);
    }
    if (a[sa[i]+d] == c)
      return make_pair(i, h);
    return make_pair(-1,-1);
  }

  void top_down_traversal(int lcp[], int child[], int n)
  {
    get_child_intervals(lcp, child, 0, n);
  }

  template<typename T>
  pair<int, int> search(T a[], int sa[], int lcp[], int child[], int n, const T s[], int m)
  {
    if (m == 0)
      return make_pair(0, n);
    pair<int, int> sub = get_interval(a, sa, lcp, child, n, 0, n, 0, s[0]);
    int l = sub.first, h = sub.second, i = 1;
    bool found = true;
    while (found && i < m) {
      if (l < h-1) {
        int j = min(get_lcp(lcp, child, l, h), m);
        FOR(k, i, j) {
          if (a[sa[l]+k] != s[k]) {
            found = false;
            break;
          }
        }
        i = j;
        if (i < m) {
          sub = get_interval(a, sa, lcp, child, n, l, h, i, s[i]);
          l = sub.first;
          h = sub.second;
        }
      } else {
        FOR(k, i, m) {
          if (a[sa[l]+k] != s[k]) {
            found = false;
            break;
          }
        }
        i = m;
      }
    }
    return found ? make_pair(l, h) : make_pair(-1, -1);
  }
};

/// RRR

u32 select_in_u16(u16 x, u32 k)
{
  for (; k; k--)
    x &= x - 1;
  return __builtin_ctz(x);
}

u32 select_in_u64(u64 x, i32 k)
{
  u32 c;
  c =  __builtin_popcount(u16(x));
  if (c > k) return select_in_u16(x, k) + 0;
  x >>= 16;
  k -= c;
  c =  __builtin_popcount(u16(x));
  if (c > k) return select_in_u16(x, k) + 16;
  x >>= 16;
  k -= c;
  c =  __builtin_popcount(u16(x));
  if (c > k) return select_in_u16(x, k) + 32;
  x >>= 16;
  k -= c;
  return select_in_u16(x, k) + 48;
}

class RRR
{
  static const int USE_TABLE_THRESHOLD = 15;
  u32 n_, block_len_, sample_len_, rank_sum_;
  u32 nblocks_, nsamples_, klass_bits_, rsample_bits_, osample_bits_;
  u64 **binom_ = nullptr;
  u16 *offset_bits_, *combinations_, *klass_offset_, *offset_pos_;
  BitSet klasses_, offsets_, rank_samples_, offset_samples_;

  u32 block2offset(u32 k, u64 x) const {
    if (block_len_ <= USE_TABLE_THRESHOLD)
      return offset_pos_[x];
    u32 m = block_len_-1, r = 0;
    for (; k; m--)
      if (x & 1ull << m) {
        if (k <= m)
          r += binom_[m][k];
        k--;
      }
    return r;
  }

  u64 offset2block(u32 k, u32 off) const {
    if (block_len_ <= USE_TABLE_THRESHOLD)
      return combinations_[klass_offset_[k]+off];
    u32 m = block_len_-1;
    u64 r = 0;
    for (; k && k <= m; m--)
      if (binom_[m][k] <= off) {
        off -= binom_[m][k--];
        r |= 1ull << m;
      }
    if (k)
      r |= (1ull<<k) - 1;
    return r;
  }
public:
  void init(u32 n, u32 block_len, u32 sample_len, const BitSet &data) {
    n_ = n;
    block_len_ = block_len ? block_len : max(clog2(n), u32(15));
    sample_len_ = sample_len ? sample_len : 8;
    compute_tables();
    build(data);
  }

  void build(const BitSet &data) {
    nblocks_ = (n_-1+block_len_)/block_len_;
    rank_sum_ = 0;
    u32 offset_sum = 0;
    REP(i, nblocks_) {
      u32 klass = __builtin_popcountll(data.block(block_len_, i));
      rank_sum_ += klass;
      offset_sum += offset_bits_[klass];
    }
    nsamples_ = (nblocks_-1+sample_len_)/sample_len_;
    klass_bits_ = clog2(block_len_+1);
    rsample_bits_ = clog2(rank_sum_);
    osample_bits_ = clog2(offset_sum);
    klasses_.init(klass_bits_*nblocks_);
    offsets_.init(offset_sum);
    rank_samples_.init(rsample_bits_*nsamples_);
    offset_samples_.init(osample_bits_*nsamples_);

    rank_sum_ = offset_sum = 0;
    REP(i, nblocks_) {
      if (i % sample_len_ == 0) {
        rank_samples_.set_bits(i/sample_len_*rsample_bits_, rsample_bits_, rank_sum_);
        offset_samples_.set_bits(i/sample_len_*osample_bits_, osample_bits_, offset_sum);
      }
      u32 klass = __builtin_popcountll(data.block(block_len_, i));
      klasses_.set_bits(klass_bits_*i, klass_bits_, klass);
      rank_sum_ += klass;
      offsets_.set_bits(offset_sum, offset_bits_[klass], block2offset(klass, data.block(block_len_, i)));
      offset_sum += offset_bits_[klass];
    }
  }

  void compute_tables() {
    binom_ = new u64*[block_len_+1];
    offset_bits_ = new u16[block_len_+1];
    REP(i, block_len_+1) {
      binom_[i] = new u64[i+1];
      binom_[i][0] = binom_[i][i] = 1;
      FOR(j, 1, i)
        binom_[i][j] = binom_[i-1][j-1]+binom_[i-1][j];
    }
    REP(i, block_len_+1)
      offset_bits_[i] = clog2(binom_[block_len_][i]);
    if (block_len_ <= 15) {
      combinations_ = new u16[1<<block_len_];
      klass_offset_ = new u16[block_len_+1];
      offset_pos_ = new u16[1<<block_len_];
      u32 pcomb = 0;
      REP(klass, block_len_+1) {
        u32 start = (1<<klass)-1, x = start;
        klass_offset_[klass] = pcomb;
        REP(i, binom_[block_len_][klass]) {
          combinations_[pcomb++] = x;
          offset_pos_[x] = i;
          u32 y = x | x-1;
          x = y+1 | (~y&-~y)-1 >> __builtin_ctz(x)+1;
        }
      }
      assert(pcomb == (1 << block_len_));
    }
  }

  ~RRR() {
    REP(i, block_len_+1)
      delete[] binom_[i];
    delete[] binom_;
    delete[] offset_bits_;
    if (block_len_ <= USE_TABLE_THRESHOLD) {
      delete[] combinations_;
      delete[] klass_offset_;
      delete[] offset_pos_;
    }
  }

  u32 zero_bits() const { return n_-rank_sum_; }

  u32 one_bits() const { return rank_sum_; }

  bool operator[](u32 i) const {
    u32 b = i / block_len_,
        bi = i % block_len_,
        s = b / sample_len_,
        j = s * sample_len_,
        o = offset_samples_.block(osample_bits_, s);
    for (; j < b; j++)
      o += offset_bits_[klasses_.block(klass_bits_, j)];
    u32 k = klasses_.block(klass_bits_, j);
    return offset2block(k, offsets_.get_bits(o, offset_bits_[k])) >> bi & 1;
  }

  u32 rank0(u32 i) const { return i-rank1(i); }

  u32 rank1(u32 i) const {
    u32 b = i / block_len_,
        bi = i % block_len_,
        s = b / sample_len_,
        j = s * sample_len_,
        r = rank_samples_.block(rsample_bits_, s),
        o = offset_samples_.block(osample_bits_, s),
        k;
    for (; j < b; j++) {
      k = klasses_.block(klass_bits_, j);
      r += k;
      o += offset_bits_[k];
    }
    k = klasses_.block(klass_bits_, j);
    return r + __builtin_popcountll(offset2block(k, offsets_.get_bits(o, offset_bits_[k])) & (1u<<bi)-1);
  }

  u32 select0(u32 kth) const {
    if (kth >= zero_bits()) return -1u;
    u32 l = 0, h = nsamples_;
    while (l < h) {
      u32 m = l+(h-l)/2, idx = m*sample_len_*block_len_;
      if (idx - rank_samples_.block(rsample_bits_, m) <= kth)
        l = m+1;
      else
        h = m;
    }

    u32 s = l-1,
        b = sample_len_*s,
        r = block_len_*b - rank_samples_.block(rsample_bits_, s),
        o = offset_samples_.block(osample_bits_, s),
        k;
    for (; ; b++) {
      k = klasses_.block(klass_bits_, b);
      if (r+block_len_-k > kth) break;
      r += block_len_-k;
      o += offset_bits_[k];
    }

    o = offsets_.get_bits(o, offset_bits_[k]);
    return block_len_*b + select_in_u64(~ offset2block(k, o), kth-r);
  }

  u32 select1(u32 kth) const {
    if (kth >= rank_sum_) return -1u;
    u32 l = 0, h = nsamples_;
    while (l < h) {
      u32 m = l+(h-l)/2;
      if (rank_samples_.block(rsample_bits_, m) <= kth)
        l = m+1;
      else
        h = m;
    }

    u32 s = l-1,
        b = sample_len_*s,
        r = rank_samples_.block(rsample_bits_, s),
        o = offset_samples_.block(osample_bits_, s),
        k;
    for (; ; b++) {
      k = klasses_.block(klass_bits_, b);
      if (r+k > kth) break;
      r += k;
      o += offset_bits_[k];
    }

    o = offsets_.get_bits(o, offset_bits_[k]);
    return block_len_*b + select_in_u64(offset2block(k, o), kth-r);
  }

  template<class Archive>
  void serialize(Archive &ar) {
    ar & n_ & block_len_ & sample_len_ & rank_sum_ & klasses_ & offsets_ & rank_samples_ & offset_samples_;
  }

  template<class Archive>
  void deserialize(Archive &ar) {
    serialize(ar);
    compute_tables();
    nblocks_ = (n_-1+block_len_)/block_len_;
    nsamples_ = (nblocks_-1+sample_len_)/sample_len_;
    klass_bits_ = clog2(block_len_+1);
    rsample_bits_ = clog2(rank_sum_);
    osample_bits_ = clog2(offsets_.size());
  }
};

// SDArray

const u32 BLOCK_LEN = 1024;
const u32 SUBBLOCK_LEN = 32;
const u32 MAX_IN_BLOCK_OFFSET = 65536; // 2**16 u16

struct identity_getter
{
  u64 operator()(u64 x) { return x; }
};

struct not_getter
{
  u64 operator()(u64 x) { return ~ x; }
};

// ref: Daisuke Okanohara & Kunihiko Sadakane. Practical Entropy-Compressed Rank/Select Dictionary
template<typename WordGetter>
class DArray
{
  SArray<i32> block_;
  SArray<u16> subblock_;
  SArray<u32> overflow_;
  u32 num_ = 0;

  void flush_cur_block(vector<u32> &pos, u32 &pblock, u32 &psubblock, u32 &poverflow) {
    if (pos.back() - pos[0] < MAX_IN_BLOCK_OFFSET) {
      block_[pblock++] = pos[0];
      REPS(i, pos.size(), SUBBLOCK_LEN)
        subblock_[psubblock++] = pos[i] - pos[0];
    } else {
      block_[pblock++] = ~ poverflow;
      for (auto x: pos)
        overflow_[poverflow++] = x;
      REPS(i, pos.size(), SUBBLOCK_LEN)
        subblock_[psubblock++] = -1; // arbitrary
    }
    pos.clear();
  }

  void flush_cur_block_preflight(vector<u32> &pos, u32 &nblock, u32 &nsubblock, u32 &noverflow) {
    nblock++;
    nsubblock += (pos.size()-1)/SUBBLOCK_LEN+1;
    if (pos.back() - pos[0] >= MAX_IN_BLOCK_OFFSET)
      noverflow += pos.size();
    pos.clear();
  }
public:
  void init(const SArray<u64> &bit_vec) {
    vector<u32> pos;
    u32 wlen = bit_vec.size();

    u32 nblock = 0, nsubblock = 0, noverflow = 0;
    REP(w, wlen) {
      u32 i = w * 64;
      u64 word = WordGetter()(bit_vec[w]);
      while (word) {
        int l = __builtin_ctzll(word);
        i += l;
        word >>= l;
        pos.push_back(i);
        i += 1;
        word >>= 1;
        num_++;
        if (pos.size() == BLOCK_LEN)
          flush_cur_block_preflight(pos, nblock, nsubblock, noverflow);
      }
    }
    if (pos.size())
      flush_cur_block_preflight(pos, nblock, nsubblock, noverflow);

    block_.init(nblock);
    subblock_.init(nsubblock);
    overflow_.init(noverflow);

    u32 pblock = 0, psubblock = 0, poverflow = 0;
    REP(w, wlen) {
      u32 i = w * 64;
      u64 word = WordGetter()(bit_vec[w]);
      while (word) {
        int l = __builtin_ctzll(word);
        i += l;
        word >>= l;
        pos.push_back(i);
        i += 1;
        word >>= 1;
        num_++;
        if (pos.size() == BLOCK_LEN)
          flush_cur_block(pos, pblock, psubblock, poverflow);
      }
    }
    if (pos.size())
      flush_cur_block(pos, pblock, psubblock, poverflow);
  }

  size_t space_consumption() const {
    return block_.size()*4 + subblock_.size()*2 + overflow_.size()*4;
  }

  u32 select(const SArray<u64> &bit_vec, u32 idx) const {
    u32 bi = idx / BLOCK_LEN;
    i32 bpos = block_[bi];
    if (bpos < 0)
      return overflow_[~ bpos + idx%BLOCK_LEN];
    u32 sbi = idx / SUBBLOCK_LEN,
        p = bpos + subblock_[sbi],
        rem = idx % SUBBLOCK_LEN,
        wi = p / 64;
    if (! rem)
      return p;
    u64 word = WordGetter()(bit_vec[wi]) & (-1ull << p%64);
    for(;;) {
      u32 pop = __builtin_popcountll(word);
      if (rem < pop) break;
      rem -= pop;
      wi++;
      word = WordGetter()(bit_vec[wi]);
    }
    return wi * 64 + select_in_u64(word, rem);
  }

  template<typename Archive>
  void serialize(Archive &ar) {
    ar & block_ & subblock_ & overflow_;
  }
};

typedef DArray<not_getter> DArray0;
typedef DArray<identity_getter> DArray1;

class EliasFanoBuilder
{
public:
  u32 n_, bound_, l_, num_ = 0, pos_ = 0;
  BitSet lows_, highs_;

  EliasFanoBuilder(u32 n, u32 bound) : EliasFanoBuilder(n, bound, n && n <= bound ? 31 - __builtin_clz(bound / n) : 0) {}

  EliasFanoBuilder(u32 n, u32 bound, u32 l) : n_(n), bound_(bound), l_(l), lows_(l*n), highs_((bound>>l_)+n+1) {}

  void push(u32 x) {
    if (l_) {
      lows_.set_bits(pos_, l_, x & (1<<l_)-1);
      pos_ += l_;
    }
    highs_.set((x>>l_) + num_++);
  }
};

/// limit: n <= 2**30-2 (<-- highs.len() < 2**31)
class EliasFano
{
public:
  u32 n_, bound_, l_;
  BitSet lows_;
  RRR highs_;
public:
  void init(EliasFanoBuilder &b) {
    n_= b.n_;
    bound_ = b.bound_;
    l_ = b.l_;
    lows_ = move(b.lows_);
    highs_.init((bound_>>l_)+n_+1, 0, 0, b.highs_);
  }

  u32 operator[](u32 idx) const {
    u32 ret = highs_.select1(idx) - idx << l_;
    if (l_)
      ret |= lows_.get_bits(l_*idx, l_);
    return ret;
  }

  u32 rank(u32 x) const {
    if (x > bound_) return n_;
    u32 hi = x >> l_, lo = x & (1<<l_)-1;
    u32 i = highs_.select0(hi),
        r = i - hi; // number of elements in highs <= hi
    while (i && highs_[i-1] && (l_ ? lows_.get_bits((r-1)*l_, l_) : 0) >= lo)
      i--, r--;
    return r;
  }

  bool exist(u32 x) const {
    u32 r = rank(x);
    return r < n_ && operator[](r) == x;
  }

  template<typename Archive>
  void serialize(Archive &ar) {
    ar & n_ & bound_ & l_ & lows_ & highs_;
  }
};

///// Wavelet Matrix

class WaveletMatrix
{
  static const int ALPHABET = 1 << CHAR_BIT;
  u32 n_;
  RRR rrr_[CHAR_BIT];
public:
  WaveletMatrix() {}

  ~WaveletMatrix() {}

  void init(u32 n, u8 *text, u8 *tmp) {
    n_ = n;
    BitSet bs(n);
    REP(d, CHAR_BIT) {
      u32 bit = CHAR_BIT-1-d;
      REP(i, n)
        bs.set(i, text[i] >> bit & 1);
      rrr_[d].init(n, 0, 0, bs);
      if (d < CHAR_BIT-1) {
        u32 j = 0;
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

  int operator[](u32 i) const { return at(i); }
  int at(u32 i) const {
    return at(0, 0, ALPHABET, i);
  }
  int at(int d, int l, int h, u32 i) const {
    if (h-l == 1) return l;
    int m = l + (1 << 31-__builtin_clz(h-l-1));
    //return ! (*b_[d])[i]
    return ! rrr_[d][i]
      ? at(d+1, l, m, rrr_[d].rank0(i))
      : at(d+1, m, h, rrr_[d].zero_bits()+rrr_[d].rank1(i));
  }

  // number of occurrences of symbol `x` in [0,i)
  u32 rank(u32 x, u32 i) const {
    return rank(0, 0, ALPHABET, x, i, 0);
  }
  u32 rank(int d, int l, int h, u32 x, u32 i, u32 p) const {
    if (h-l == 1) return i-p;
    int m = l+h >> 1;
    u32 z = rrr_[d].zero_bits();
    return x < m
      ? rank(d+1, l, m, x, rrr_[d].rank0(i), rrr_[d].rank0(p))
      : rank(d+1, m, h, x, z+rrr_[d].rank1(i), z+rrr_[d].rank1(p));
  }
  // position of `k`-th occurrence of symbol `x`
  u32 select(u32 x, u32 k) const {
    return select(0, 0, ALPHABET, x, k, 0);
  }
  u32 select(int d, int l, int h, u32 x, u32 k, u32 p) const {
    if (l == h-1) return p+k;
    int m = l + (1 << 31-__builtin_clz(h-l-1));
    u32 z = rrr_[d].zero_bits();
    return x < m
      ? rrr_[d].select0(select(d+1, l, m, x, k, rrr_[d].rank0(p)))
      : rrr_[d].select1(select(d+1, m, h, x, k, z+rrr_[d].rank1(p)) - z);
  }

  template<typename Archive>
  void serialize(Archive &ar) {
    ar & n_;
    REP(i, CHAR_BIT)
      ar & rrr_[i];
  }
};

///// FM-index

class FMIndex
{
  u32 n_, samplerate_, initial_;
  u32 cnt_lt_[257];
  EliasFano sampled_ef_;
  SArray<u32> ssa_;
  WaveletMatrix bwt_wm_;
public:
  void init(u32 n, const u8 *text, u32 samplerate) {
    samplerate_ = samplerate;
    n_ = n;

    u32 cnt = 0;
    fill_n(cnt_lt_, 256, 0);
    REP(i, n)
      cnt_lt_[text[i]]++;
    REP(i, 256) {
      u32 t = cnt_lt_[i];
      cnt_lt_[i] = cnt;
      cnt += t;
    }
    cnt_lt_[256] = cnt;

    int *sa = new int[n];
    int *tmp = new int[max(n, u32(256))];
    u32 sampled_n = (n-1+samplerate)/samplerate;
    EliasFanoBuilder efb(sampled_n, n-1);
    ssa_.init(sampled_n);

    u32 nn = 0;
    KoAluru::main(text, sa, tmp, n, 256);
    REP(i, n)
      if (sa[i] % samplerate == 0) {
        ssa_[nn++] = sa[i];
        efb.push(i);
      }
    sampled_ef_.init(efb);

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
  auto operator&(T &x) -> decltype(serialize_imp(x, 0), *this) {
    serialize_imp(x, 0);
    return *this;
  }

  template<class S, class T>
  void array(S n, T *a) {
    operator&(n);
    REP(i, n)
      operator&(a[i]);
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
    x = *(T *)a_;
    a_ = (void *)((T *)a_ + 1);
  }

  template<class S, class T>
  void array(S &n, T *&a) {
    operator&(n);
    a = (T *)a_;
    a_ = (void *)((T *)a_ + n);
  }
};

int main2()
{
  /*
  vector<u32> a{1,1,3,4,4,6,100,2000,3000,2147483647};
  EliasFanoBuilder efb(a.size(), a.back());
  for (auto x: a) efb.push(x);
  EliasFano ef(efb);
  printf("l: %d\n", ef.l_);
  printf("n highs: %zd\n", ef.highs_.size());
  printf("space: %zd\n", ef.space_consumption());
  REP(i, a.size())
    printf("%zd: %u\n", i, ef[i]);
    */

  /*
  const char c_text[] = "aabababa";
  u8 *text = (u8*)c_text;
  u32 n = sizeof(c_text)-1;

  u8 buf[99];
  auto fm = new FMIndex(n, text, 10);
  while (gets((char*)buf)) {
    u32 n = strlen((char*)buf);
    printf("= %zd\n", fm->count(n, buf));
    auto xs = fm->locate(n, buf, 100);
    printf("= %zd\n", xs.size());
    for (auto x:xs)printf("%d ",x);
    puts("");
  }
  delete fm;
  */

  // serialization
  /*
  int n = 100000;
  int *xs = new int[n];
  REP(i,n)xs[i] = i&255;
  WaveletMatrix x(n, xs);
  //REP(i,n)
  //  printf("%d: %d\n", i, x.at(i));
  delete[] xs;

  char *buf;
  size_t size;
  FILE *fh = open_memstream(&buf, &size);
  Serializer se(fh);

  se & x;
  fflush(fh);
  fclose(fh);

  WaveletMatrix y;
  int seven;
  fseek(fh, 0, SEEK_SET);
  Deserializer de(buf);

  de & y;
  REP(i,n)
    assert(y.at(i) == (i&255));
  //de & seven;
  //REP(i, n)
  //assert(seven == 7);
  */

}

void print_help(FILE *fh)
{
  fprintf(fh, "Usage: %s [OPTIONS]\n", program_invocation_short_name);
  exit(fh == stdout ? 0 : EX_USAGE);
}

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

jmp_buf jmpbuf;

struct Entry
{
  bool valid;
  int fd, index_fd;
  int size, index_size;
  void *mmap, *index_mmap;
  FMIndex *fm;
};

bool is_pcap(const string &name)
{
  return name.size() >= PCAP_SUFFIX.size() && name.substr(name.size()-PCAP_SUFFIX.size()) == PCAP_SUFFIX;
}

void process_dir(const string &pcap_dir, bool do_inotify, int &inotify_fd, function<void(string)> fn)
{
  if (do_inotify) {
    if ((inotify_fd = inotify_init()) < 0)
      err_exit(EX_USAGE, "inotify_init");
    if (inotify_add_watch(inotify_fd, pcap_dir.c_str(), IN_CLOSE_WRITE | IN_CREATE | IN_DELETE | IN_MODIFY | IN_MOVE) < 0)
      err_exit(EX_USAGE, "inotify_add_watch");
  }
  DIR *dir = opendir(pcap_dir.c_str());
  if (! dir)
    err_exit(EX_OSERR, "opendir");
  struct dirent dirent, *res;
  while (readdir_r(dir, &dirent, &res) == 0 && res) {
    string name = dirent.d_name;
    if (is_pcap(name))
      fn(name);
  }
  closedir(dir);
}

void process_inotify(const string &pcap_dir, int inotify_fd, set<string> &modified, function<void(string)> add_fn, function<void(string)> rm_fn)
{
  char buf[sizeof(inotify_event)+NAME_MAX+1];
  int nread;
  if ((nread = read(inotify_fd, buf, sizeof buf)) <= 0)
    err_exit(EX_OSERR, "failed to read inotify fd");
  for (auto *ev = (inotify_event *)buf; (char *)ev < (char *)buf+nread;
       ev = (inotify_event *)((char *)ev + sizeof(inotify_event) + ev->len))
    if (ev->len > 0 && is_pcap(ev->name)) {
      if (ev->mask & IN_CREATE) {
        log_event("CREATE %s\n", ev->name);
        modified.insert(ev->name);
      } else if (ev->mask & IN_DELETE) {
        log_event("DELETE %s\n", ev->name);
        modified.erase(ev->name);
        rm_fn(ev->name);
      } else if (ev->mask & IN_MOVED_FROM) {
        log_event("MOVED_FROM %s\n", ev->name);
        modified.erase(ev->name);
        rm_fn(ev->name);
      } else if (ev->mask & IN_MOVED_TO) {
        log_event("MOVED_TO %s\n", ev->name);
        add_fn(ev->name);
      } else if (ev->mask & IN_MODIFY)
        modified.insert(ev->name);
      else if (ev->mask & IN_CLOSE_WRITE) {
        if (modified.count(ev->name)) {
          modified.erase(ev->name);
          log_event("MODIFY then CLOSE_WRITE %s\n", ev->name);
          add_fn(ev->name);
        }
      }
    }
}

struct Worker
{
  int clifd;
  map<string, shared_ptr<Entry>> name2entry;
  u32 search_limit;
};

//void *serve_client(int clifd, const map<string, Entry> *name2entry, u32 search_limit)
void *serve_client(Worker *data)
//int clifd, const map<string, Entry> *name2entry, u32 search_limit)
{
  char buf[BUF_SIZE];
  const char *p, *search_type = buf, *file_begin = buf, *file_end = nullptr;
  int nread = 0;
  timeval timeout;
  timeout.tv_sec = REQUEST_TIMEOUT_MILLI/1000;
  timeout.tv_usec = REQUEST_TIMEOUT_MILLI%1000*1000;

  for(;;) {
    fd_set rfds;
    FD_ZERO(&rfds);
    FD_SET(data->clifd, &rfds);
    int res = select(data->clifd+1, &rfds, NULL, NULL, &timeout); // Linux modifies timeout
    if (res < 0) {
      if (errno == EINTR) continue;
      goto quit;
    }
    if (! res) // timeout
      goto quit;
    int t = read(data->clifd, buf+nread, sizeof buf-nread);
    if (t < 0) goto quit;
    if (! t) break;
    nread += t;
  }

  for (p = buf; p < buf+sizeof(buf) && *p; p++);
  if (++p >= buf+sizeof(buf))
    goto quit;
  file_begin = p;
  for (; p < buf+sizeof(buf) && *p; p++);
  if (++p >= buf+sizeof(buf))
    goto quit;
  file_end = p;
  for (; p < buf+sizeof(buf) && *p; p++);
  if (++p >= buf+sizeof(buf))
    goto quit;

  {
    bool autocomplete = *search_type == '\0';
    u32 len = buf+nread-p, total = 0, t;
    if (autocomplete) {
      u32 skip = 0;
      vector<u32> res;
      vector<string> candidates;
      for (auto &ne: make_reverse_iterator(data->name2entry)) {
        const string &name = ne.first;
        auto entry = ne.second;
        if (entry->valid && entry->size > 0) {
          auto old_size = res.size();
          string pattern = unescape(len, p);
          entry->fm->locate(pattern.size(), (const u8*)pattern.c_str(), true, AUTOCOMPLETE_LIMIT, skip, res);
          FOR(i, old_size, res.size())
            candidates.emplace_back((char*)entry->mmap+res[i], (char*)entry->mmap+min(entry->size, int(res[i])+AUTOCOMPLETE_LENGTH));
          if (res.size() >= AUTOCOMPLETE_LIMIT) break;
        }
      }
      sort(candidates.begin(), candidates.end());
      candidates.erase(unique(candidates.begin(), candidates.end()), candidates.end());
      for (auto &cand: candidates)
        dprintf(data->clifd, "%s\n", escape(cand).c_str()); // may SIGPIPE
    } else {
      char *end;
      errno = 0;
      u32 skip = strtol(search_type, &end, 0);
      if (! *end && ! errno) {
        vector<u32> res;
        for (auto &ne: make_reverse_iterator(data->name2entry)) {
          const string &name = ne.first;
          auto entry = ne.second;
          if (entry->valid && (! *file_begin || string(file_begin) <= name) && (! *file_end || name <= string(file_end)) && entry->size > 0) {
            auto old_size = res.size();
            string pattern = unescape(len, p);
            total += entry->fm->locate(pattern.size(), (const u8*)pattern.c_str(), false, data->search_limit, skip, res);
            FOR(i, old_size, res.size()) {
              dprintf(data->clifd, "%s\t%u\t%s\n", name.c_str(), res[i],
                      escape(string((char*)entry->mmap+max(int(res[i])-CONTEXT_LENGTH, 0), (char*)entry->mmap+min(entry->size, int(res[i])+CONTEXT_LENGTH))).c_str());
            }
            if (res.size() >= AUTOCOMPLETE_LIMIT) break;
          }
        }
        dprintf(data->clifd, "%u\n", total);
      }
    }
  }
quit:
  close(data->clifd);
  free(data);
  return NULL;
}

void server_mode(const string &pcap_dir, u32 search_limit)
{
  signal(SIGPIPE, SIG_IGN);

  int inotify_fd;
  map<string, shared_ptr<Entry>> name2entry;

  auto rm_fn = [&](string name) {
    if (name2entry.count(name)) { // already exists
      auto old = name2entry[name];
      old->valid = false;
      delete old->fm;
      munmap(old->mmap, old->size);
      munmap(old->index_mmap, old->index_size);
      close(old->fd);
      close(old->index_fd);
    }
  };

  auto add_fn = [&](string name) {
    string index_name = name+INDEX_SUFFIX;
    auto entry = make_shared<Entry>();
    entry->valid = true;
    entry->mmap = MAP_FAILED;
    entry->index_mmap = MAP_FAILED;
    errno = 0;
    if ((entry->fd = open((pcap_dir+"/"+name).c_str(), O_RDONLY)) < 0)
      goto quit;
    if ((entry->index_fd = open((pcap_dir+"/"+index_name).c_str(), O_RDONLY)) < 0) {
      if (errno == ENOENT)
        errno = 0;
      goto quit;
    }
    if ((entry->size = lseek(entry->fd, 0, SEEK_END)) < 0)
      goto quit;
    if ((entry->index_size = lseek(entry->index_fd, 0, SEEK_END)) < 0)
      goto quit;
    if (entry->size > 0 && (entry->mmap = mmap(NULL, entry->size, PROT_READ, MAP_SHARED, entry->fd, 0)) == MAP_FAILED)
      goto quit;
    if (entry->index_size > 0 && (entry->index_mmap = mmap(NULL, entry->index_size, PROT_READ, MAP_SHARED, entry->index_fd, 0)) == MAP_FAILED)
      goto quit;
    rm_fn(name);
    if (entry->index_size < 8) {
      log_status("invalid index file %s\n", index_name.c_str());
      goto quit;
    }
    if (memcmp(entry->index_mmap, MAGIC_GOOD, 4)) {
      log_status("index file %s: bad magic\n", index_name.c_str());
      goto quit;
    }
    if (*((int*)entry->index_mmap+1) != entry->size) {
      log_status("index file %s: wrong length\n", index_name.c_str());
      goto quit;
    }
    if (entry->index_size > 0) {
      Deserializer ar((char*)entry->index_mmap+strlen(MAGIC_GOOD)+4);
      entry->fm = new FMIndex;
      ar & *entry->fm;
      name2entry[name] = entry;
      log_action("loaded index for %s\n", name.c_str());
    }
    return;
quit:
    if (entry->index_mmap != MAP_FAILED)
      munmap(entry->index_mmap, entry->index_size);
    if (entry->mmap != MAP_FAILED)
      munmap(entry->mmap, entry->size);
    if (entry->index_fd >= 0)
      close(entry->index_fd);
    if (entry->fd >= 0)
      close(entry->fd);
    if (errno)
      err_msg("processing index file %s", index_name.c_str());
  };

  process_dir(pcap_dir, true, inotify_fd, add_fn);
  log_status("start inotify\n");

  int sockfd = socket(AF_UNIX, SOCK_STREAM, 0);
  if (sockfd < 0)
    err_exit(EX_OSERR, "socket");
  struct sockaddr_un addr = {};
  addr.sun_family = AF_UNIX;
  strncpy(addr.sun_path, LISTEN_PATH, sizeof(addr.sun_path)-1);
  unlink(addr.sun_path);
  if (bind(sockfd, (struct sockaddr *)&addr, sizeof addr) < 0)
    err_exit(EX_OSERR, "bind");
  if (listen(sockfd, 1) < 0)
    err_exit(EX_OSERR, "listen");

  set<string> modified;
  for(;;) {
    fd_set rfds;
    FD_ZERO(&rfds);
    FD_SET(inotify_fd, &rfds);
    FD_SET(sockfd, &rfds);
    int res = select(max(sockfd, inotify_fd)+1, &rfds, NULL, NULL, NULL);
    if (res < 0) {
      if (errno == EINTR) continue;
      err_exit(EX_OSERR, "select");
    }
    if (FD_ISSET(inotify_fd, &rfds))
      process_inotify(pcap_dir, inotify_fd, modified, add_fn, rm_fn);
    if (FD_ISSET(sockfd, &rfds)) {
      int clifd = accept(sockfd, NULL, NULL);
      if (clifd < 0)
        err_exit(EX_OSERR, "accept");
      pthread_t tid;
      pthread_attr_t attr;
      pthread_attr_init(&attr);
      if (pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED))
        err_exit(EX_OSERR, "pthread_attr_setdetachstate");
      auto worker = new Worker;
      worker->clifd = clifd;
      worker->name2entry = name2entry; // make a copy of name2entry to prevent race condition
      worker->search_limit = search_limit;
      pthread_create(&tid, &attr, (void*(*)(void*))serve_client, worker);
      pthread_attr_destroy(&attr);
    }
  }
}

void index_mode(const string &pcap_dir, bool do_inotify)
{
  int inotify_fd;

  auto add_fn = [&](string name) {
    string index_name = name+INDEX_SUFFIX;
    int index_fd = -1, pcap_fd = -1;
    off_t pcap_size;
    void *pcap_content = MAP_FAILED;
    FILE *fh = NULL;
    errno = 0;
    if ((pcap_fd = open((pcap_dir+"/"+name).c_str(), O_RDONLY)) < 0)
      goto quit;
    if ((pcap_size = lseek(pcap_fd, 0, SEEK_END)) < 0)
      goto quit;
    if ((index_fd = open((pcap_dir+"/"+index_name).c_str(), O_RDWR | O_CREAT, 0666)) < 0)
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
        log_status("index file %s: bad magic. rebuilding\n", index_name.c_str());
      else if (nread < 8 || *((int*)buf+1) != pcap_size)
        log_status("index file %s: wrong length. rebuilding\n", index_name.c_str());
      else
        goto quit;
    }
    if (pcap_size > 0 && (pcap_content = mmap(NULL, pcap_size, PROT_READ, MAP_SHARED, pcap_fd, 0)) == MAP_FAILED)
      goto quit;
    if (! (fh = fdopen(index_fd, "w")))
      goto quit;
    if (pcap_size > 0) {
      StopWatch sw;
      if (fseek(fh, 0, SEEK_SET) < 0)
        err_exit(EX_IOERR, "fseek");
      if (fputs(MAGIC_BAD, fh) < 0)
        err_exit(EX_IOERR, "fputs");
      if (fputs(MAGIC_BAD, fh) < 0) // length of origin
        err_exit(EX_IOERR, "fputs");
      Serializer ar(fh);
      FMIndex fm;
      fm.init(pcap_size, (const u8 *)pcap_content, SAMPLE_RATE);
      ar & fm;
      long index_size = ftell(fh);
      ftruncate(index_fd, index_size);
      fseek(fh, 0, SEEK_SET);
      fputs(MAGIC_GOOD, fh);
      fwrite(&pcap_size, 4, 1, fh);
      if (ferror(fh)) {
        unlink((pcap_dir+"/"+index_name).c_str());
        err_exit(EX_IOERR, "failed to process pcap file %s", name.c_str());
      }
      log_action("created index for %s. origin: %ld, index: %ld, used %.3lf s\n", name.c_str(), pcap_size, index_size, sw.elapsed());
    }
quit:
    if (fh)
      fclose(fh);
    else if (index_fd >= 0)
      close(index_fd);
    if (pcap_content != MAP_FAILED)
      munmap(pcap_content, pcap_size);
    if (pcap_fd >= 0)
      close(pcap_fd);
    if (errno)
      err_msg("failed to process pcap file %s", name.c_str());
  };

  auto rm_fn = [&](string name) {
    string path = pcap_dir+"/"+name+INDEX_SUFFIX;
    unlink(path.c_str());
    log_action("unlinked %s\n", path.c_str());
  };

  process_dir(pcap_dir, do_inotify, inotify_fd, add_fn);

  set<string> modified;
  if (do_inotify) {
    log_status("start inotify\n");
    fd_set rfds;
    for(;;) {
      FD_ZERO(&rfds);
      FD_SET(inotify_fd, &rfds);
      int res = select(inotify_fd+1, &rfds, NULL, NULL, NULL);
      if (res < 0) {
        if (errno == EINTR) continue;
        err_exit(EX_OSERR, "select");
      }
      process_inotify(pcap_dir, inotify_fd, modified, add_fn, rm_fn);
    }
  }
}

//#define DEBUG
int main(int argc, char *argv[])
{
#ifdef DEBUG

  /*
  BitSet bs(20);
  bs.set_bits(0, 20, 0xd3d3);
  RRR rrr(20, 2, 2, bs);

  puts("-- at");
  FOR(i, 0, 20)
    printf("%d ",  rrr[i]);
  puts("");

  puts("-- rank0");
  FOR(i, 0, 21) printf("%d ", rrr.rank0(i));
  puts("");

  puts("-- select0");
  FOR(i, 0, rrr.zero_bits()) printf("%d ", rrr.select0(i));
  puts("");

  puts("-- select1");
  FOR(i, 0, rrr.one_bits()) printf("%d ", rrr.select1(i));
  puts("");

  return 0;
  */

# if 1
  int m = 100000;
  char *c_text = new char[m];
  REP(i,m)c_text[i] = i;
  u8 *text = (u8*)c_text;

  FMIndex x;
  x.init(m, text, 16);
  delete[] c_text;
  //REP(i,n)
  //  printf("%d: %d\n", i, x.at(i));

  char *buf;
  size_t size;
  FILE *fh = open_memstream(&buf, &size);
  Serializer se(fh);
  se & x;
  fflush(fh);
  fclose(fh);

  FMIndex y;
  Deserializer de(buf);

  de & y;

  u8 line[99];
  u32 t;
  while (gets((char*)line)) {
    u32 n = strlen((char*)line);
    printf("= %zd\n", y.count(n, line));
    auto xs = y.locate(n, line, 100, t);
    printf("= %zd\n", xs.size());
    for (auto x:xs)printf("%d ",x);
    puts("");
  }

  printf("buf: %p\nsize: %zd\n", buf, size);

  free(buf);
  return 0;
# endif
#endif

  bool is_index_mode = false;
  bool do_inotify = true;
  u32 search_limit = SEARCH_LIMIT;

  int opt;
  static struct option long_options[] = {
    {"oneshot",     no_argument, 0,   'o'},
    {"limit",       required_argument, 0,   'l'},
    {"index",       no_argument, 0,   'i'},
    {"help",        no_argument, 0,   'h'},
    {0,             0,           0,   0}
  };

  while ((opt = getopt_long(argc, argv, "hil:o", long_options, NULL)) != -1) {
    switch (opt) {
    case 'h':
      print_help(stdout);
      break;
    case 'i':
      is_index_mode = true;
      break;
    case 'l': {
      char *end;
      errno = 0;
      long t = strtol(optarg, &end, 0);
      if (errno)
        err_exit(EX_USAGE, "limit is too large");
      if (*end || t < 0 || t > UINT32_MAX)
        err_exit(EX_USAGE, "invalid limit");
      search_limit = t;
      break;
    }
    case 'o':
      do_inotify = false;
      break;
    case '?':
      print_help(stderr);
      break;
    }
  }
  if (optind+1 != argc)
    err_exit(EX_USAGE, "one argument");
  const char *pcap_dir = argv[optind];

  if (is_index_mode) {
    log_status("index mode\n");
    index_mode(pcap_dir, do_inotify);
  } else {
    log_status("server mode\n");
    server_mode(pcap_dir, search_limit);
  }
}
