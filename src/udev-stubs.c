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
  fprintf(stderr, "udev_device_get_devnode\n");
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
    u->sysname = (char const *)u->syspath + 11;
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
  fprintf(stderr, "stub: udev_device_get_sysname\n");
  return udev_device->sysname;
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

LIBINPUT_EXPORT
void free_dev_list(struct udev_list_entry **list) {
  if (!*list)
    return;

  if ((*list)->next)
    free_dev_list(&(*list)->next);

  free(*list);
  *list = NULL;
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

    struct udev_list_entry **list_end = &udev_enumerate->dev_list;
    while (*list_end) {
      list_end = &((*list_end)->next);
    }

    *list_end = le;
  }

  closedir(dir);
  return 0;
}

LIBINPUT_EXPORT
struct udev_list_entry *udev_enumerate_get_list_entry(
    struct udev_enumerate *udev_enumerate) {
  return udev_enumerate->dev_list;
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
  fprintf(stderr, "stub: udev_monitor_receive_device\n");
  return NULL;
}

LIBINPUT_EXPORT
const char *udev_device_get_action(struct udev_device *udev_device) {
  fprintf(stderr, "stub: udev_device_get_action\n");
  return NULL;
}

LIBINPUT_EXPORT
void udev_monitor_unref(struct udev_monitor *udev_monitor) {
  fprintf(stderr, "stub: udev_monitor_unref\n");
}
