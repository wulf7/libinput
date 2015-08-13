#ifndef UDEV_STUBS_H_
#define UDEV_STUBS_H_

#include <sys/types.h>

struct udev_device;
struct udev;
struct udev_list_entry;
struct udev_monitor;
struct udev_enumerate;

#define udev_list_entry_foreach(list_entry, first_entry)                      \
  for(list_entry = first_entry;                                               \
      list_entry != NULL;                                                     \
      list_entry = udev_list_entry_get_next(list_entry))

char const *udev_device_get_devnode(struct udev_device *udev_device);
char const *udev_device_get_property_value(struct udev_device *dummy __unused, char const *property);
struct udev *udev_device_get_udev(struct udev_device *dummy __unused);
struct udev_device *udev_device_new_from_syspath(struct udev *udev,
                                                        const char *syspath);
struct udev_device *udev_device_new_from_devnum(struct udev *udev,
                                                       char type,
                                                       dev_t devnum);

struct udev *udev_new(void);
void udev_unref(struct udev *udev);

const char *udev_device_get_syspath(struct udev_device *udev_device);
const char *udev_device_get_sysname(struct udev_device *udev_device);
struct udev_device *udev_device_ref(struct udev_device *udev_device);
void udev_device_unref(struct udev_device *udev_device);
struct udev_device *udev_device_get_parent(struct udev_device *udev_device);
int udev_device_get_is_initialized(struct udev_device *udev_device);
struct udev *udev_ref(struct udev *udev);
struct udev_enumerate *udev_enumerate_new(struct udev *udev);
int udev_enumerate_add_match_subsystem(
    struct udev_enumerate *udev_enumerate, const char *subsystem);
int udev_enumerate_scan_devices(struct udev_enumerate *udev_enumerate);
struct udev_list_entry *udev_enumerate_get_list_entry(
    struct udev_enumerate *udev_enumerate);
struct udev_list_entry *udev_list_entry_get_next(
    struct udev_list_entry *list_entry);
const char *udev_list_entry_get_name(
    struct udev_list_entry *list_entry);
void udev_enumerate_unref(struct udev_enumerate *udev_enumerate);
struct udev_monitor *udev_monitor_new_from_netlink(struct udev *udev,
                                                          const char *name);
int udev_monitor_filter_add_match_subsystem_devtype(
    struct udev_monitor *udev_monitor, const char *subsystem,
    const char *devtype);
int udev_monitor_enable_receiving(struct udev_monitor *udev_monitor);
int udev_monitor_get_fd(struct udev_monitor *udev_monitor);
struct udev_device *udev_monitor_receive_device(
    struct udev_monitor *udev_monitor);
const char *udev_device_get_action(struct udev_device *udev_device);
void udev_monitor_unref(struct udev_monitor *udev_monitor);

#endif
