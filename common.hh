#ifndef _GNU_SOURCE
# define _GNU_SOURCE
#endif
#include <algorithm>
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
#include <cinttypes>
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
typedef unsigned long ulong;

#define LEN_OF(x) (sizeof(x)/sizeof(*x))
#define REP(i, n) FOR(i, 0, n)
#define FOR(i, a, b) for (typename std::remove_cv<typename std::remove_reference<decltype(b)>::type>::type i = (a); i < (b); i++)
#define ROF(i, a, b) for (typename std::remove_cv<typename std::remove_reference<decltype(b)>::type>::type i = (b); --i >= (a); )

#define SGR0 "\x1b[m"
#define RED "\x1b[31m"
#define GREEN "\x1b[32m"
#define YELLOW "\x1b[33m"
#define BLUE "\x1b[34m"
#define MAGENTA "\x1b[35m"
#define CYAN "\x1b[36m"
#define BOLD_CYAN "\x1b[1;36m"

const size_t BUF_SIZE = 512;

///// log

void log_generic(const char *prefix, const char *format, va_list ap)
{
  int fd = STDOUT_FILENO;
  char buf[BUF_SIZE], tim[BUF_SIZE], body[BUF_SIZE];
  timeval tv;
  tm tm;
  gettimeofday(&tv, NULL);
  write(fd, prefix, strlen(prefix));
  if (localtime_r(&tv.tv_sec, &tm))
    strftime(tim, sizeof tim, "%T", &tm);
  else
    tim[0] = '\0';
  vsnprintf(body, sizeof body, format, ap);
  snprintf(buf, sizeof buf, "%s%s.%06lu %s" SGR0 "\n", prefix, tim, tv.tv_usec, body);
  write(fd, buf, strlen(buf));
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
    i += sprintf(buf+i, " %#lx", (ulong)bt[j++]);
  strcat(buf, ">&2");
  fputs("\n", stderr);
  system(buf);
  //backtrace_symbols_fd(buf, nptrs, STDERR_FILENO);
  exit(exitno);
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
    while (x) {
      if (key < x->key) x = x->c[0];
      else if (key > x->key) x = x->c[1];
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
      Node* y = x;
      x = new Node(*x);
      y->unref();
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
    Node* x;
    vector<Node*> st;
    void weave() {
      for (; x; x = x->c[1])
        st.push_back(x);
      if (st.size()) {
        x = st.back();
        st.pop_back();
      }
    }
    Backward begin() {
      weave();
      return *this;
    }
    Backward end() { return Backward{nullptr}; }
    bool operator!=(const Backward& o) { return x != o.x; }
    Backward operator++() { x = x->c[0]; weave(); return *this; }
    Node& operator*() { return *x; }
  };

  Backward backward(Node* x) { return Backward{x}; }

  struct RangeBackward {
    Node* x;
    Key l, h, min, max;
    vector<tuple<Node*, Key, Key>> st;
    void step() {
      if ((h = x->key) < min)
        x = nullptr;
      else
        x = x->c[0];
    }
    void weave() {
      for(;;) {
        for (; x && l <= max; x = x->c[1]) {
          st.emplace_back(x, l, h);
          l = x->key;
        }
        if (st.empty()) {
          x = nullptr;
          return;
        }
        tie(x, l, h) = st.back();
        st.pop_back();
        if (min <= x->key && x->key <= max) return;
        step();
      }
    }
    RangeBackward begin() { weave(); return *this; }
    RangeBackward end() { return RangeBackward{nullptr, l, h, min, max}; }
    bool operator!=(const RangeBackward& o) { return x != o.x; }
    RangeBackward operator++() { step(); weave(); return *this; }
    Node& operator*() { return *x; }
  };

  RangeBackward range_backward(Node* x, Key l, Key h, Key min, Key max) { return RangeBackward{x, l, h, min, max}; }
};
