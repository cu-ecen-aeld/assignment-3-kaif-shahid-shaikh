#ifndef AESD_CHAR_DRIVER_AESDCHAR_H_
#define AESD_CHAR_DRIVER_AESDCHAR_H_

#include <linux/types.h>
#include <linux/cdev.h>
#include <linux/mutex.h>
#include <linux/printk.h>
#include "aesd-circular-buffer.h"

#define AESD_DEBUG 1

#undef PDEBUG
#ifdef AESD_DEBUG
#  define PDEBUG(fmt, args...) printk(KERN_DEBUG "aesdchar: " fmt, ##args)
#else
#  define PDEBUG(fmt, args...) /* no debug */
#endif

struct aesd_dev {
    struct cdev cdev;                      /* Char device structure */
    struct aesd_circular_buffer circ; /* ring of last 10 commands */
    struct mutex lock;                     /* protects circ + partial */
    char   *partial_write;                 /* accumulating until '\n' */
    size_t  partial_size;                  /* bytes in partial_write */
};

/* Prototypes */
int     aesd_open(struct inode *inode, struct file *filp);
int     aesd_release(struct inode *inode, struct file *filp);
ssize_t aesd_read(struct file *filp, char __user *buf, size_t count, loff_t *f_pos);
ssize_t aesd_write(struct file *filp, const char __user *buf, size_t count, loff_t *f_pos);
int     aesd_init_module(void);
void    aesd_cleanup_module(void);

#endif /* AESD_CHAR_DRIVER_AESDCHAR_H_ */
