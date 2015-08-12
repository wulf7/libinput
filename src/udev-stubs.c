#include "config.h"
#include "udev-stubs.h"

#include <dirent.h>
#include <errno.h>
#include <stdbool.h>
#include <libevdev/libevdev.h>

#ifdef HAVE_LIBPROCSTAT_H
#include <sys/sysctl.h>
#include <sys/param.h>
#include <sys/queue.h>
#include <sys/socket.h>
#include <kvm.h>
#include <libprocstat.h>
#endif

#ifdef HAVE_LIBDEVQ
#include <libdevq.h>
#include <sys/types.h>
#include <sys/event.h>
#endif

#include "libinput-util.h"


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

LIBINPUT_EXPORT
char const *udev_device_get_property_value(struct udev_device *dev,
                                           char const *property) {
  fprintf(stderr, "stub: udev_device_get_property_value %s\n", property);

  if (strcmp("ID_INPUT", property) == 0) {
    fprintf(stderr, "udev_device_get_property_value return 1\n");
    return (char const *)1;
  }

  int fd = path_to_fd(dev->syspath);
  if (fd == -1)
    return NULL;

  char const *retval = NULL;

  struct libevdev *evdev = NULL;
  if (libevdev_new_from_fd(fd, &evdev) != 0) {
    fprintf(stderr,
            "udev_device_get_property_value: could not create evdev\n");
    return NULL;
  }

  if (strcmp("ID_INPUT_TOUCHPAD", property) == 0) {
    if (libevdev_has_event_code(evdev, EV_ABS, ABS_X) &&
        libevdev_has_event_code(evdev, EV_ABS, ABS_Y) &&
        libevdev_has_event_code(evdev, EV_KEY, BTN_TOOL_FINGER) &&
        !libevdev_has_event_code(evdev, EV_KEY, BTN_STYLUS) &&
        !libevdev_has_event_code(evdev, EV_KEY, BTN_TOOL_PEN)) {
      retval = (char const *)1;
    }
  } else if (strcmp("ID_INPUT_TOUCHSCREEN", property) == 0) {
    /* Its not rule of thumb but quite common that
     * touchscreens do not advertise BTN_TOOL_FINGER event */
    if (libevdev_has_event_code(evdev, EV_ABS, ABS_X) &&
        libevdev_has_event_code(evdev, EV_ABS, ABS_Y) &&
        libevdev_has_event_code(evdev, EV_KEY, BTN_TOUCH) &&
        !libevdev_has_event_code(evdev, EV_KEY, BTN_TOOL_FINGER) &&
        !libevdev_has_event_code(evdev, EV_KEY, BTN_STYLUS) &&
        !libevdev_has_event_code(evdev, EV_KEY, BTN_TOOL_PEN)) {
      retval = (char const *)1;
    }
  } else if (strcmp("ID_INPUT_MOUSE", property) == 0) {
    if (libevdev_has_event_code(evdev, EV_REL, REL_X) &&
        libevdev_has_event_code(evdev, EV_REL, REL_Y) &&
        libevdev_has_event_code(evdev, EV_KEY, BTN_MOUSE)) {
      retval = (char const *)1;
    }
    if (libevdev_has_event_code(evdev, EV_ABS, ABS_X) &&
        libevdev_has_event_code(evdev, EV_ABS, ABS_Y) &&
        !libevdev_has_event_code(evdev, EV_KEY, BTN_TOOL_FINGER) &&
        !libevdev_has_event_code(evdev, EV_KEY, BTN_STYLUS) &&
        !libevdev_has_event_code(evdev, EV_KEY, BTN_TOOL_PEN) &&
        libevdev_has_event_code(evdev, EV_KEY, BTN_MOUSE)) {
      retval = (char const *)1;
    }
  } else if (strcmp("ID_INPUT_KEYBOARD", property) == 0) {
    bool is_keyboard = true;
    for (int i = KEY_ESC; i <= KEY_D; ++i) {
      if (!libevdev_has_event_code(evdev, EV_KEY, i)) {
        is_keyboard = false;
        break;
      }
    }
    if (is_keyboard)
      retval = (char const *)1;
  }

  libevdev_free(evdev);

  fprintf(stderr, "udev_device_get_property_value return %p\n",
          (void *)retval);

  return retval;
}

LIBINPUT_EXPORT
struct udev *udev_device_get_udev(struct udev_device *dummy __unused) {
  fprintf(stderr, "stub: udev_device_get_udev\n");
  return NULL;
}

LIBINPUT_EXPORT
struct udev_device *udev_device_new_from_syspath(struct udev *udev,
                                                        const char *syspath) {
  fprintf(stderr, "stub: udev_list_entry_get_name\n");
  struct udev_device *u = calloc(1, sizeof(struct udev_device));
  if (u) {
    u->refcount = 1;
    snprintf(u->syspath, sizeof(u->syspath), "%s", syspath);
    snprintf(u->action, sizeof(u->action), "none");
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
          udev_device->syspath + 11);
  return udev_device->syspath + 11;
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
  return 0;
}

static struct udev_list_entry *create_list_entry(char const *path) {
  struct udev_list_entry *le = calloc(1, sizeof(struct udev_list_entry));
  if (!le)
    return NULL;
  snprintf(le->path, sizeof(le->path), "%s", path);
  return le;
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

LIBINPUT_EXPORT
int udev_enumerate_scan_devices(struct udev_enumerate *udev_enumerate) {
  fprintf(stderr, "udev_enumerate_scan_devices\n");

  DIR *dir;
  struct dirent *ent;
  char path[32];

  dir = opendir("/dev/input");
  if (dir == NULL) {
    return -1;
  }
  while ((ent = readdir(dir)) != NULL) {
    if (!strcmp(ent->d_name, ".") || !strcmp(ent->d_name, "..") ||
        ent->d_type != DT_CHR || strncmp(ent->d_name, "event", 5) != 0) {
      continue;
    }

    snprintf(path, sizeof(path), "/dev/input/%s", ent->d_name);

    struct udev_list_entry *le = create_list_entry(path);
    if (!le) {
      free_dev_list(&udev_enumerate->dev_list);
      closedir(dir);
      return -1;
    }

    STAILQ_INSERT_TAIL(&udev_enumerate->dev_list, le, next);
  }

  closedir(dir);
  return 0;
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
  fprintf(stderr, "udev_list_entry_get_name\n");
  return list_entry->path;
}

LIBINPUT_EXPORT
void udev_enumerate_unref(struct udev_enumerate *udev_enumerate) {
  fprintf(stderr, "udev_enumerate_unref\n");
  --udev_enumerate->refcount;
  if (udev_enumerate->refcount == 0) {
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

static void *
udev_monitor_thread(void *args) {
  struct udev_monitor *udev_monitor = args;
  struct udev_device udev_device;
  struct devq_event *ev;
  const char *type, *dev_name;
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
      if (type == NULL || dev_name == NULL || dev_len > 26)
        break;
      if (type_len == 6 && strncmp(type, "CREATE", type_len) == 0)
        sprintf(udev_device.action, "add");
      else if (type_len == 7 && strncmp(type, "DESTROY", type_len) == 0)
        sprintf(udev_device.action, "remove");
      else
        break;
      udev_device.refcount = 1;
      memcpy(udev_device.syspath, "/dev/", 5);
      memcpy(udev_device.syspath + 5, dev_name, dev_len);
      udev_device.syspath[dev_len + 5] = 0;
      if (strncmp(udev_device.syspath, "/dev/input/event", 16) != 0)
        break;
printf("%s %s\n", udev_device.action, udev_device.syspath);
      write(udev_monitor->fake_fds[1], &udev_device, sizeof(udev_device));
      break;
    case DEVQ_UNKNOWN:
      break;
    }

    devq_event_free(ev);
  }

  printf("thr exit\n");
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

  return u;
}

LIBINPUT_EXPORT
int udev_monitor_filter_add_match_subsystem_devtype(
    struct udev_monitor *udev_monitor, const char *subsystem,
    const char *devtype) {
  fprintf(stderr, "stub: udev_monitor_filter_add_match_subsystem_devtype\n");
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
    return udev_device;
  }
  fprintf(stderr, "\n");
  free(udev_device);
  return NULL;
}

LIBINPUT_EXPORT
const char *udev_device_get_action(struct udev_device *udev_device) {
  fprintf(stderr, "udev_device_get_action return %s\n", udev_device->action);
  return udev_device->action;
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
    free(udev_monitor);
  }
}
