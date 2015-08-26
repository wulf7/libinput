#include "config.h"
#include "udev-stubs.h"

#include <sys/types.h>
#include <sys/queue.h>
#include <sys/stat.h>

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <libevdev/libevdev.h>

#ifdef HAVE_LIBPROCSTAT_H
#include <sys/sysctl.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <kvm.h>
#include <libprocstat.h>
#endif

#ifdef HAVE_LIBDEVQ
#include <libdevq.h>
#include <pthread.h>
#include <sys/event.h>
#endif

#include "libinput-util.h"

struct udev_device;
void create_evdev_handler(struct udev_device *udev_device);

struct subsystem_config {
  char *subsystem;
  char *syspath;
  void (*create_handler)(struct udev_device *udev_device);
};

struct subsystem_config subsystems[] = {
  { "input", "/dev/input/event", create_evdev_handler },
};

#define	UNKNOWN_SUBSYSTEM	"#"

/* udev_device flags */
#define	UDF_ACTION_MASK		0x00000003 /* Should be in range 0x00 - 0xFF */
#define	UDF_ACTION_NONE		0x00000000
#define	UDF_ACTION_ADD		0x00000001
#define	UDF_ACTION_REMOVE	0x00000002

struct udev_list_entry {
  char name[32];
  char value[32];
  STAILQ_ENTRY(udev_list_entry) next;
};
STAILQ_HEAD(udev_list_head, udev_list_entry);
static int insert_list_entry(
   struct udev_list_head *lhp, char const *name, char const *value);
static void free_dev_list(struct udev_list_head *head);

struct udev_device {
  int refcount;
  char syspath[32];
  uint32_t flags;
  struct udev_list_head prop_list;
};

struct udev {
  int refcount;
};

enum {
  UDEV_FILTER_TYPE_SUBSYSTEM,
};

struct udev_filter_entry {
  int type;
  int neg;
  char expr[32];
  STAILQ_ENTRY(udev_filter_entry) next;
};
STAILQ_HEAD(udev_filter_head, udev_filter_entry);

struct udev_monitor {
  int refcount;
#ifdef HAVE_LIBDEVQ
  pthread_t thread;
  struct devq_evmon *evm;
#endif
  int fake_fds[2];
  struct udev_filter_head filters;
};

struct udev_enumerate {
  int refcount;
  struct udev_filter_head filters;
  struct udev_list_head dev_list;
};


LIBINPUT_EXPORT
struct udev_device *udev_device_new_from_devnum(struct udev *udev, char type,
                                                dev_t devnum) {
  fprintf(stderr, "udev_device_new_from_devnum %d\n", (int) devnum);

  char path[32] = "/dev/";
  struct stat st;

  devname_r(devnum, S_IFCHR, path + 5, sizeof(path) - 5);

  fprintf(stderr, "path: %s\n", path);

  /* Recheck path as devname_r returns zero-terminated garbage on error */
  if (stat(path, &st) == 0 && st.st_rdev == devnum) {
    fprintf(stderr, "  %s\n", path + 11);
    return udev_device_new_from_syspath(udev, path);
  }

  return NULL;
}

LIBINPUT_EXPORT
char const *udev_device_get_devnode(struct udev_device *udev_device) {
  fprintf(stderr, "udev_device_get_devnode return %s\n", udev_device->syspath);
  return udev_device->syspath;
}

/*
 * dirname_r implementation. Stolen here:
 * https://android.googlesource.com/platform/bionic.git/+/gingerbread/libc/bionic/dirname_r.c
 */
static int
dirname_r(const char *path, char *buffer, size_t bufflen)
{
  const char *endp;
  int result, len;
  /* Empty or NULL string gets treated as "." */
  if (path == NULL || *path == '\0') {
    path = ".";
    len  = 1;
    goto Exit;
  }
  /* Strip trailing slashes */
  endp = path + strlen(path) - 1;
  while (endp > path && *endp == '/')
    endp--;
  /* Find the start of the dir */
  while (endp > path && *endp != '/')
    endp--;
  /* Either the dir is "/" or there are no slashes */
  if (endp == path) {
    path = (*endp == '/') ? "/" : ".";
    len  = 1;
    goto Exit;
  }
  do {
    endp--;
  } while (endp > path && *endp == '/');
  len = endp - path +1;

Exit:
  result = len;
  if (len+1 > MAXPATHLEN) {
    errno = ENAMETOOLONG;
    return -1;
  }
  if (buffer == NULL)
    return result;
  if (len > (int)bufflen-1) {
    len    = (int)bufflen-1;
    result = -1;
    errno  = ERANGE;
  }
  if (len >= 0) {
    memcpy(buffer, path, len);
    buffer[len] = 0;
  }
  return result;
}

/*
 * locates the occurrence of last component of the pathname
 * pointed to by path
 */
static char *strbase(const char *path) {
  char *base;

  base = strrchr(path, '/');
  if (base != NULL)
    base++;

  return base;
}

/*
 */
static size_t
syspathlen_wo_units(const char *path) {
  size_t len;

  len = strlen(path);
  while (len > 0) {
    if (!((path[len-1] >= '0' && path[len-1] <= '9') || path[len-1] == '.'))
      break;
    --len;
  }

  return len;
}

static struct subsystem_config *
get_subsystem_config_by_syspath(const char *path) {
  size_t len, i;

  len = syspathlen_wo_units(path);

  for (i = 0; i < nitems(subsystems); i++)
    if (len == strlen(subsystems[i].syspath) &&
        strncmp(path, subsystems[i].syspath, len) == 0)
      return &subsystems[i];

  return NULL;
}

static char *
get_subsystem_by_syspath(const char *path) {
  struct subsystem_config *sc;

  sc = get_subsystem_config_by_syspath(path);
  return sc == NULL ? UNKNOWN_SUBSYSTEM : sc->subsystem;
}

static int
path_to_fd(const char *path) {
  int fd = -1;

#ifdef HAVE_LIBPROCSTAT_H
  struct procstat *procstat;
  struct kinfo_proc *kip;
  struct filestat_list *head = NULL;
  struct filestat *fst;
  unsigned int count;

  procstat = procstat_open_sysctl();
  if (procstat == NULL)
    return -1;

  count = 0;
  kip = procstat_getprocs(procstat, KERN_PROC_PID, getpid(), &count);
  if (kip == NULL || count != 1)
    goto out;

  head = procstat_getfiles(procstat, kip, 0);
  if (head == NULL)
    goto out;

  STAILQ_FOREACH(fst, head, next) {
    if (fst->fs_uflags == 0 &&
        fst->fs_type == PS_FST_TYPE_VNODE &&
        fst->fs_path != NULL &&
        strcmp(fst->fs_path, path) == 0) {
      fd = fst->fs_fd;
      break;
    }
  }

out:
  if (head != NULL)
    procstat_freefiles(procstat, head);
  if (kip != NULL)
    procstat_freeprocs(procstat, kip);
  procstat_close(procstat);
#else
  struct stat st;
  if (stat(path, &st) != 0) {
    return -1;
  }

  int max_fd = 128;
  for (fd = 0; fd < max_fd; ++fd) {
    struct stat fst;
    if (fstat(fd, &fst) != 0) {
      if (errno != EBADF) {
        perror("fstat");
        return -1;
      } else {
        continue;
      }
    }

    // fprintf(stderr, "stats fd %d: %d %d\n", fd, (int) fst.st_rdev, (int) st.st_rdev);

    if (fst.st_rdev == st.st_rdev) {
      break;
    }
  }

  if (fd == max_fd) {
    // fprintf(stderr, "udev_device_get_property_value: MAX fd reached\n");
    return -1;
  }
#endif
  return fd;
}

void
create_evdev_handler(struct udev_device *dev) {
  int opened = 0;
  fprintf(stderr, "create_evdev_handler invoked on %p\n", dev);

  insert_list_entry(&dev->prop_list, "ID_INPUT", "1");

  int fd = path_to_fd(dev->syspath);
  if (fd == -1) {
    fd = open(dev->syspath, O_RDONLY | O_CLOEXEC);
    opened = 1;
  }
  if (fd == -1)
    return;

  struct libevdev *evdev = NULL;
  if (libevdev_new_from_fd(fd, &evdev) != 0) {
    fprintf(stderr,
            "udev_device_get_property_value: could not create evdev\n");
    return;
  }

  if (libevdev_has_event_code(evdev, EV_ABS, ABS_X) &&
      libevdev_has_event_code(evdev, EV_ABS, ABS_Y) &&
      libevdev_has_event_code(evdev, EV_KEY, BTN_TOOL_FINGER) &&
      !libevdev_has_event_code(evdev, EV_KEY, BTN_STYLUS) &&
      !libevdev_has_event_code(evdev, EV_KEY, BTN_TOOL_PEN)) {
    insert_list_entry(&dev->prop_list, "ID_INPUT_TOUCHPAD", "1");
  } else
    /* Its not rule of thumb but quite common that
     * touchscreens do not advertise BTN_TOOL_FINGER event */
    if (libevdev_has_event_code(evdev, EV_ABS, ABS_X) &&
        libevdev_has_event_code(evdev, EV_ABS, ABS_Y) &&
        libevdev_has_event_code(evdev, EV_KEY, BTN_TOUCH) &&
        !libevdev_has_event_code(evdev, EV_KEY, BTN_TOOL_FINGER) &&
        !libevdev_has_event_code(evdev, EV_KEY, BTN_STYLUS) &&
        !libevdev_has_event_code(evdev, EV_KEY, BTN_TOOL_PEN)) {
      insert_list_entry(&dev->prop_list, "ID_INPUT_TOUCHSCREEN", "1");
  } else
    if (libevdev_has_event_code(evdev, EV_REL, REL_X) &&
        libevdev_has_event_code(evdev, EV_REL, REL_Y) &&
        libevdev_has_event_code(evdev, EV_KEY, BTN_MOUSE)) {
      insert_list_entry(&dev->prop_list, "ID_INPUT_MOUSE", "1");
  } else
    if (libevdev_has_event_code(evdev, EV_ABS, ABS_X) &&
        libevdev_has_event_code(evdev, EV_ABS, ABS_Y) &&
        !libevdev_has_event_code(evdev, EV_KEY, BTN_TOOL_FINGER) &&
        !libevdev_has_event_code(evdev, EV_KEY, BTN_STYLUS) &&
        !libevdev_has_event_code(evdev, EV_KEY, BTN_TOOL_PEN) &&
        libevdev_has_event_code(evdev, EV_KEY, BTN_MOUSE)) {
      insert_list_entry(&dev->prop_list, "ID_INPUT_MOUSE", "1");
  } else {
    bool is_keyboard = true;
    for (int i = KEY_ESC; i <= KEY_D; ++i) {
      if (!libevdev_has_event_code(evdev, EV_KEY, i)) {
        is_keyboard = false;
        break;
      }
    }
    if (is_keyboard)
      insert_list_entry(&dev->prop_list, "ID_INPUT_KEYBOARD", "1");
  }

  libevdev_free(evdev);

  if (opened)
    close(fd);
}

static void
invoke_create_handler(struct udev_device *udev_device) {
  const char *path;
  struct subsystem_config *sc;

  path = udev_device_get_syspath(udev_device);
  sc = get_subsystem_config_by_syspath(path);

  if (sc != NULL && sc->create_handler != NULL)
    sc->create_handler(udev_device);

  return;
}

LIBINPUT_EXPORT
char const *udev_device_get_property_value(struct udev_device *dev,
                                           char const *property) {
  char const *key, *value;
  struct udev_list_entry *entry;

  udev_list_entry_foreach(entry, udev_device_get_properties_list_entry(dev)) {
    key = udev_list_entry_get_name(entry);
    if (!key)
      continue;
    if (strcmp(key, property) == 0) {
      value = udev_list_entry_get_value(entry);
      fprintf
        (stderr, "udev_device_get_property_value %s:%s\n", property, value);
      return value;
    }
  }

  fprintf(stderr, "udev_device_get_property_value %s:NULL\n", property);

  return NULL;
}

LIBINPUT_EXPORT
struct udev_list_entry * udev_device_get_properties_list_entry(
    struct udev_device *udev_device) {
  return STAILQ_FIRST(&udev_device->prop_list);
}

LIBINPUT_EXPORT
struct udev *udev_device_get_udev(struct udev_device *dummy __unused) {
  fprintf(stderr, "stub: udev_device_get_udev\n");
  return NULL;
}

LIBINPUT_EXPORT
struct udev_device *udev_device_new_from_syspath(struct udev *udev,
                                                        const char *syspath) {
  fprintf(stderr, "stub: udev_device_new_from_syspath %s\n", syspath);
  struct udev_device *u = calloc(1, sizeof(struct udev_device));
  if (u) {
    u->refcount = 1;
    snprintf(u->syspath, sizeof(u->syspath), "%s", syspath);
    u->flags = UDF_ACTION_NONE;
    STAILQ_INIT(&u->prop_list);
    invoke_create_handler(u);
    return u;
  }
  return NULL;
}

LIBINPUT_EXPORT
const char *udev_device_get_syspath(struct udev_device *udev_device) {
  fprintf(stderr, "udev_device_get_syspath\n");
  return udev_device->syspath;
}

LIBINPUT_EXPORT
const char *udev_device_get_sysname(struct udev_device *udev_device) {
  fprintf(stderr, "udev_device_get_sysname return %s\n",
          strbase(udev_device->syspath));
  return strbase(udev_device->syspath);
}

LIBINPUT_EXPORT
struct udev_device *udev_device_ref(struct udev_device *udev_device) {
  fprintf(stderr, "udev_device_ref\n");
  ++udev_device->refcount;
  return udev_device;
}

LIBINPUT_EXPORT
void udev_device_unref(struct udev_device *udev_device) {
  fprintf(stderr, "udev_device_unref %p %d\n", udev_device,
          udev_device->refcount);

  --udev_device->refcount;
  if (udev_device->refcount == 0) {
    free_dev_list(&udev_device->prop_list);
    free(udev_device);
  }
}

LIBINPUT_EXPORT
struct udev_device *udev_device_get_parent(struct udev_device *udev_device) {
  fprintf(stderr, "udev_device_get_parent %p %d\n", udev_device,
          udev_device->refcount);
  return NULL;
}

LIBINPUT_EXPORT
int udev_device_get_is_initialized(struct udev_device *udev_device) {
  fprintf(stderr, "udev_device_get_is_initialized %p %d\n", udev_device,
          udev_device->refcount);
  return 1;
}

LIBINPUT_EXPORT
struct udev *udev_ref(struct udev *udev) {
  fprintf(stderr, "udev_ref\n");
  ++udev->refcount;
  return udev;
}

LIBINPUT_EXPORT
void udev_unref(struct udev *udev) {
  fprintf(stderr, "udev_unref\n");
  --udev->refcount;
  if (udev->refcount == 0) {
    free(udev);
  }
}

LIBINPUT_EXPORT
struct udev *udev_new(void) {
  fprintf(stderr, "udev_new\n");
  struct udev *u = calloc(1, sizeof(struct udev));
  if (u) {
    u->refcount = 1;
    return u;
  }
  return NULL;
}

LIBINPUT_EXPORT
struct udev_enumerate *udev_enumerate_new(struct udev *udev) {
  fprintf(stderr, "udev_enumerate_new\n");
  struct udev_enumerate *u = calloc(1, sizeof(struct udev_enumerate));
  STAILQ_INIT(&u->filters);
  STAILQ_INIT(&u->dev_list);
  if (u) {
    u->refcount = 1;
    return u;
  }
  return NULL;
}

LIBINPUT_EXPORT
int udev_enumerate_add_match_subsystem(
    struct udev_enumerate *udev_enumerate, const char *subsystem) {
  fprintf(stderr, "stub: udev_enumerate_add_match_subsystem\n");
  struct udev_filter_entry *fe = calloc(1, sizeof(struct udev_filter_entry));
  if (fe == NULL)
    return -1;

  fe->type = UDEV_FILTER_TYPE_SUBSYSTEM;
  fe->neg = 0;
  snprintf(fe->expr, sizeof(fe->expr), "%s", subsystem);
  STAILQ_INSERT_TAIL(&udev_enumerate->filters, fe, next);
  return 0;
}

static int insert_list_entry(
    struct udev_list_head *lhp, char const *name, char const *value) {
  struct udev_list_entry *le = calloc(1, sizeof(struct udev_list_entry));
  if (!le)
    return -1;
  snprintf(le->name, sizeof(le->name), "%s", name);
  if (value != NULL)
    snprintf(le->value, sizeof(le->value), "%s", value);
  STAILQ_INSERT_TAIL(lhp, le, next);
  return 0;
}

static void free_filters(struct udev_filter_head *head) {
  struct udev_filter_entry *fe1, *fe2;

  fe1 = STAILQ_FIRST(head);
  while (fe1 != NULL) {
    fe2 = STAILQ_NEXT(fe1, next);
    free(fe1);
    fe1 = fe2;
  }
  STAILQ_INIT(head);
}

static void free_dev_list(struct udev_list_head *head) {
  struct udev_list_entry *le1, *le2;

  le1 = STAILQ_FIRST(head);
  while (le1 != NULL) {
    le2 = STAILQ_NEXT(le1, next);
    free(le1);
    le1 = le2;
  }
  STAILQ_INIT(head);
}

static int enumerate_devices_by_syspath(struct udev_list_head *lhp,
                                        const char *syspath) {

  DIR *dir;
  struct dirent *ent;
  char path[32], dirname[32], *basename;
  size_t basename_len;

  if (dirname_r(syspath, dirname, sizeof(dirname)) < 4 ||
      strncmp(dirname, "/dev", 4) != 0)
    return -1;

  basename = strbase(syspath);
  if (basename == NULL)
    return -1;
  basename_len = strlen(basename);

  dir = opendir(dirname);
  if (dir == NULL)
    return errno == ENOENT ? 0 : -1;

  while ((ent = readdir(dir)) != NULL) {
    if (!strcmp(ent->d_name, ".") || !strcmp(ent->d_name, "..") ||
        ent->d_type != DT_CHR ||
        syspathlen_wo_units(ent->d_name) != basename_len ||
        strncmp(ent->d_name, basename, basename_len) != 0) {
      continue;
    }

    snprintf(path, sizeof(path), "%s/%s", dirname, ent->d_name);

    if (insert_list_entry(lhp, path, NULL) == -1) {
      closedir(dir);
      return -1;
    }
  }

  closedir(dir);
  return 0;
}

static int enumerate_devices_by_subsystem(struct udev_list_head *lhp,
                                       char *subsystem) {
  size_t i;

  for (i = 0; i < nitems(subsystems); i++)
    if (strcmp(subsystems[i].subsystem, subsystem) == 0)
      if (enumerate_devices_by_syspath(lhp, subsystems[i].syspath) == -1)
        return -1;

  return 0;
}

LIBINPUT_EXPORT
int udev_enumerate_scan_devices(struct udev_enumerate *udev_enumerate) {
  struct udev_filter_entry *fe;
  struct udev_list_head lh = STAILQ_HEAD_INITIALIZER(lh);

  fprintf(stderr, "udev_enumerate_scan_devices\n");

  free_dev_list(&udev_enumerate->dev_list);
  STAILQ_FOREACH(fe, &udev_enumerate->filters, next) {
    if (fe->type == UDEV_FILTER_TYPE_SUBSYSTEM && fe->neg == 0) {
      if (enumerate_devices_by_subsystem(&lh, fe->expr) != 0)
        goto error;
      STAILQ_CONCAT(&udev_enumerate->dev_list, &lh);
    }
  }
  return 0;

error:
  free_dev_list(&lh);
  free_dev_list(&udev_enumerate->dev_list);
  return -1;
}

LIBINPUT_EXPORT
struct udev_list_entry *udev_enumerate_get_list_entry(
    struct udev_enumerate *udev_enumerate) {
  return STAILQ_FIRST(&udev_enumerate->dev_list);
}

LIBINPUT_EXPORT
struct udev_list_entry *udev_list_entry_get_next(
    struct udev_list_entry *list_entry) {
  return STAILQ_NEXT(list_entry, next);
}

LIBINPUT_EXPORT
const char *udev_list_entry_get_name(
    struct udev_list_entry *list_entry) {
//  fprintf(stderr, "udev_list_entry_get_name\n");
  return list_entry->name;
}

LIBINPUT_EXPORT
const char *udev_list_entry_get_value(
    struct udev_list_entry *list_entry) {
//  fprintf(stderr, "udev_list_entry_get_value\n");
  return list_entry->value;
}

LIBINPUT_EXPORT
void udev_enumerate_unref(struct udev_enumerate *udev_enumerate) {
  fprintf(stderr, "udev_enumerate_unref\n");
  --udev_enumerate->refcount;
  if (udev_enumerate->refcount == 0) {
    free_filters(&udev_enumerate->filters);
    free_dev_list(&udev_enumerate->dev_list);
    free(udev_enumerate);
  }
}

#ifdef HAVE_LIBDEVQ
static char *
get_devq_event_prop_value(struct devq_event *ev, const char *prop, size_t *len)
{
  const char *ev_dump;
  char *prop_pos;
  size_t prop_len;

  prop_len = strlen(prop);
  ev_dump = devq_event_dump(ev);
  prop_pos = strstr(ev_dump, prop);
  if (prop_pos == NULL ||
      (prop_pos != ev_dump + 1 && prop_pos[-1] != ' ') ||
      prop_pos[prop_len] != '=')
    return NULL;

  *len = strchrnul(prop_pos + prop_len + 1, ' ') - prop_pos - prop_len - 1;
  return prop_pos + prop_len + 1;
}

static int
devq_event_match_value(struct devq_event *ev, const char *prop, const char *match_value) {
  const char *value;
  size_t len;

  value = get_devq_event_prop_value(ev, prop, &len);
  if (value != NULL &&
      len == strlen(match_value) &&
      strncmp(value, match_value, len) == 0)
    return 1;

  return 0;
}

static int
udev_monitor_send_device(struct udev_monitor *udev_monitor,
                         const char *syspath, uint32_t flags) {
  struct udev_device udev_device;

  udev_device.refcount = 1;
  udev_device.flags = flags;
  snprintf(udev_device.syspath, sizeof(udev_device.syspath), "%s", syspath);
  return (write(udev_monitor->fake_fds[1], &udev_device, sizeof(udev_device)));
}

static void *
udev_monitor_thread(void *args) {
  struct udev_monitor *udev_monitor = args;
  struct udev_filter_entry *fe;
  struct devq_event *ev;
  const char *type, *dev_name, *subsystem;
  uint32_t flags;
  char syspath[sizeof(((struct udev_device *)0)->syspath)];
  size_t type_len, dev_len;
  int kq;
  struct kevent ke;

  kq = devq_event_monitor_get_fd(udev_monitor->evm);
  if (kq == -1)
    return NULL;

  while (kevent(kq, NULL, 0, &ke, 1, NULL) > 0) {
    if (ke.filter == EVFILT_USER || ke.flags & EV_EOF)
      break;
    ev = devq_event_monitor_read(udev_monitor->evm);
    if (ev == NULL)
      break;

    switch (devq_event_get_type(ev)) {
    case DEVQ_ATTACHED:
      break;
    case DEVQ_DETACHED:
      break;
    case DEVQ_NOTICE:
      if (!devq_event_match_value(ev, "system", "DEVFS"))
        break;
      if (!devq_event_match_value(ev, "subsystem", "CDEV"))
        break;
      type = get_devq_event_prop_value(ev, "type", &type_len);
      dev_name = get_devq_event_prop_value(ev, "cdev", &dev_len);
      if (type == NULL || dev_name == NULL || dev_len > (sizeof(syspath) - 6))
        break;
      if (type_len == 6 && strncmp(type, "CREATE", type_len) == 0)
        flags = UDF_ACTION_ADD;
      else if (type_len == 7 && strncmp(type, "DESTROY", type_len) == 0)
        flags = UDF_ACTION_REMOVE;
      else
        break;
      memcpy(syspath, "/dev/", 5);
      memcpy(syspath + 5, dev_name, dev_len);
      syspath[dev_len + 5] = 0;
      subsystem = get_subsystem_by_syspath(syspath);
      if (strcmp(subsystem, UNKNOWN_SUBSYSTEM) == 0)
        break;

      STAILQ_FOREACH(fe, &udev_monitor->filters, next)
        if (fe->type == UDEV_FILTER_TYPE_SUBSYSTEM &&
            fe->neg == 0 &&
            strcmp(fe->expr, subsystem) == 0)
          udev_monitor_send_device(udev_monitor, syspath, flags);

      break;
    case DEVQ_UNKNOWN:
      break;
    }

    devq_event_free(ev);
  }

  return NULL;
}
#endif

LIBINPUT_EXPORT
struct udev_monitor *udev_monitor_new_from_netlink(struct udev *udev,
                                                          const char *name) {
  fprintf(stderr, "udev_monitor_new_from_netlink %p\n", udev);

  struct udev_monitor *u = calloc(1, sizeof(struct udev_monitor));
  if (!u) {
    return NULL;
  }

  if (pipe2(u->fake_fds, O_CLOEXEC) == -1) {
    free(u);
    return NULL;
  }

  u->refcount = 1;
  STAILQ_INIT(&u->filters);

  return u;
}

LIBINPUT_EXPORT
int udev_monitor_filter_add_match_subsystem_devtype(
    struct udev_monitor *udev_monitor, const char *subsystem,
    const char *devtype) {
  fprintf(stderr, "stub: udev_monitor_filter_add_match_subsystem_devtype\n");
  struct udev_filter_entry *fe = calloc(1, sizeof(struct udev_filter_entry));
  if (fe == NULL)
    return -1;

  fe->type = UDEV_FILTER_TYPE_SUBSYSTEM;
  fe->neg = 0;
  snprintf(fe->expr, sizeof(fe->expr), "%s", subsystem);
  STAILQ_INSERT_TAIL(&udev_monitor->filters, fe, next);
  return 0;
}

LIBINPUT_EXPORT
int udev_monitor_enable_receiving(struct udev_monitor *udev_monitor) {
  fprintf(stderr, "stub: udev_monitor_enable_receiving\n");
#ifdef HAVE_LIBDEVQ
  struct kevent ev;
  udev_monitor->evm = devq_event_monitor_init();
  if (udev_monitor->evm == NULL)
    return -1;
  if (pthread_create(&udev_monitor->thread, NULL, udev_monitor_thread,
      udev_monitor) != 0) {
    devq_event_monitor_fini(udev_monitor->evm);
    return -1;
  }
  EV_SET(&ev, 1, EVFILT_USER, EV_ADD | EV_ENABLE | EV_CLEAR, 0, 0, 0);
  kevent(devq_event_monitor_get_fd(udev_monitor->evm), &ev, 1, NULL, 0, NULL);
#endif
  return 0;
}

LIBINPUT_EXPORT
int udev_monitor_get_fd(struct udev_monitor *udev_monitor) {
  fprintf(stderr, "udev_monitor_get_fd\n");
  return udev_monitor->fake_fds[0];
}

LIBINPUT_EXPORT
struct udev_device *udev_monitor_receive_device(
    struct udev_monitor *udev_monitor) {
  fprintf(stderr, "udev_monitor_receive_device");
  struct udev_device *udev_device = calloc(1, sizeof(*udev_device));
  if (read(udev_monitor->fake_fds[0], udev_device, sizeof(*udev_device)) > 0) {
    fprintf(stderr, " %s\n", udev_device->syspath);
    STAILQ_INIT(&udev_device->prop_list);
    invoke_create_handler(udev_device);
    return udev_device;
  }
  fprintf(stderr, "\n");
  free(udev_device);
  return NULL;
}

LIBINPUT_EXPORT
const char *udev_device_get_action(struct udev_device *udev_device) {
  const char *action;
  switch(udev_device->flags & UDF_ACTION_MASK) {
  case UDF_ACTION_NONE:
    action = "none";
    break;
  case UDF_ACTION_ADD:
    action = "add";
    break;
  case UDF_ACTION_REMOVE:
    action = "remove";
    break;
  default:
    action = "unknown";
  }
  fprintf(stderr, "udev_device_get_action return %s\n", action);
  return action;
}

LIBINPUT_EXPORT
void udev_monitor_unref(struct udev_monitor *udev_monitor) {
  fprintf(stderr, "stub: udev_monitor_unref\n");
  --udev_monitor->refcount;
  if (udev_monitor->refcount == 0) {
#ifdef HAVE_LIBDEVQ
    struct kevent ev;
    int kq = devq_event_monitor_get_fd(udev_monitor->evm);
    EV_SET(&ev, 1, EVFILT_USER, 0, NOTE_TRIGGER, 0, 0);
    kevent(kq, &ev, 1, NULL, 0, NULL);
    pthread_join(udev_monitor->thread, NULL);
    devq_event_monitor_fini(udev_monitor->evm);
    close(kq);
    fprintf(stderr, "stub: udev_monitor_thread_joined\n");
#endif
    close(udev_monitor->fake_fds[0]);
    close(udev_monitor->fake_fds[1]);
    free_filters(&udev_monitor->filters);
    free(udev_monitor);
  }
}
