/**
 * @file aesdchar.c
 * @brief Functions and data related to the AESD char driver implementation
 *
 * Based on the implementation of the "scull" device driver, found in
 * Linux Device Drivers example code.
 *
 * @author Dan Walkes
 * @date 2019-10-22
 * @copyright Copyright (c) 2019
 *
 */

#include <linux/module.h>
#include <linux/init.h>
#include <linux/printk.h>
#include <linux/types.h>
#include <linux/cdev.h>
#include <linux/fs.h> // file_operations
#include "aesdchar.h"

#include "aesd-circular-buffer.h"
#include <linux/slab.h>        // kmalloc/krealloc/kfree
#include <linux/uaccess.h>     // copy_to_user/copy_from_user
#include <linux/mutex.h>
#include <linux/string.h>

int aesd_major =   0; // use dynamic major
int aesd_minor =   0;

MODULE_AUTHOR("Kaif Shahid Shaikh"); /** TODO: fill in your name **/
MODULE_LICENSE("Dual BSD/GPL");

struct aesd_dev aesd_device;

int aesd_open(struct inode *inode, struct file *filp)
{
    PDEBUG("open");
    /**
     * TODO: handle open
     */
    filp->private_data = container_of(inode->i_cdev, struct aesd_dev, cdev);
    return 0;
}

int aesd_release(struct inode *inode, struct file *filp)
{
    PDEBUG("release");
    /**
     * TODO: handle release
     */
    return 0;
}

ssize_t aesd_read(struct file *filp, char __user *buf, size_t count,
                loff_t *f_pos)
{
    struct aesd_dev *dev = filp->private_data;
    ssize_t retval = 0;
    size_t remaining;
    size_t copied = 0;
    PDEBUG("read %zu bytes with offset %lld",count,*f_pos);
    /**
     * TODO: handle read
     */
     if (!count) 
     return 0;
     
    if (mutex_lock_interruptible(&dev->lock)) 
    return -ERESTARTSYS;
    
    remaining = count;
    
    while (remaining) {
        size_t entry_offset = 0;
        struct aesd_buffer_entry *entry = aesd_circular_buffer_find_entry_offset_for_fpos(&dev->circ,*f_pos, &entry_offset);
        if (!entry) 
        break; // EOF

        size_t chunk = entry->size - entry_offset;
        if (chunk > remaining) chunk = remaining;

        if (copy_to_user(buf + copied, entry->buffptr + entry_offset, chunk)) {
            retval = -EFAULT;
            goto out_unlock;
        }
        *f_pos += chunk;
        copied += chunk;
        remaining -= chunk;
    }
    retval = copied; // may be 0 for EOF

out_unlock:
    mutex_unlock(&dev->lock);
    return retval;
}

ssize_t aesd_write(struct file *filp, const char __user *buf, size_t count,
                loff_t *f_pos)
{
    struct aesd_dev *dev = filp->private_data;
    char *kbuf = NULL;
    ssize_t retval = -ENOMEM;
    PDEBUG("write %zu bytes with offset %lld",count,*f_pos);
    /**
     * TODO: handle write
     */
     if (!count) 
     return 0;

    if (mutex_lock_interruptible(&dev->lock)) 
    return -ERESTARTSYS;

    kbuf = kmalloc(count, GFP_KERNEL);
    if (!kbuf) 
    goto out_unlock;
    if (copy_from_user(kbuf, buf, count)) 
    {
     retval = -EFAULT; 
     goto out_unlock; 
     }

    // Append to pending
    char *new_pending = krealloc((void *)dev->pending.buffptr, dev->pending.size + count, GFP_KERNEL);
    if (!new_pending) goto out_unlock;
    memcpy(new_pending + dev->pending.size, kbuf, count);
    dev->pending.buffptr = new_pending;
    dev->pending.size += count;

    // If we have a newline, finalize one command
    {
        const char *nl = memchr(dev->pending.buffptr, '\n', dev->pending.size);
        if (nl) {
            size_t cmd_len = (nl - dev->pending.buffptr) + 1;

            char *cmd = kmalloc(cmd_len, GFP_KERNEL);
            if (!cmd) goto out_unlock;
            memcpy(cmd, dev->pending.buffptr, cmd_len);

            struct aesd_buffer_entry new_entry = { .buffptr = cmd, .size = cmd_len };
            struct aesd_buffer_entry evicted =
                aesd_circular_buffer_add_entry(&dev->circ, &new_entry);
            if (evicted.buffptr) 
            kfree(evicted.buffptr); // free the one older than 10

            // keep tail after newline as new pending
            size_t tail_len = dev->pending.size - cmd_len;
            if (tail_len) {
                memmove((void *)dev->pending.buffptr,
                        dev->pending.buffptr + cmd_len,
                        tail_len);
                char *shrunk = krealloc((void *)dev->pending.buffptr, tail_len, GFP_KERNEL);
                if (shrunk) dev->pending.buffptr = shrunk;
                dev->pending.size = tail_len;
            } else {
                kfree(dev->pending.buffptr);
                dev->pending.buffptr = NULL;
                dev->pending.size = 0;
            }
        }
    }

    retval = count;

out_unlock:
    kfree(kbuf);
    mutex_unlock(&dev->lock);
    return retval;
}
struct file_operations aesd_fops = {
    .owner =    THIS_MODULE,
    .read =     aesd_read,
    .write =    aesd_write,
    .open =     aesd_open,
    .release =  aesd_release,
};

static int aesd_setup_cdev(struct aesd_dev *dev)
{
    int err, devno = MKDEV(aesd_major, aesd_minor);

    cdev_init(&dev->cdev, &aesd_fops);
    dev->cdev.owner = THIS_MODULE;
    dev->cdev.ops = &aesd_fops;
    err = cdev_add (&dev->cdev, devno, 1);
    if (err) {
        printk(KERN_ERR "Error %d adding aesd cdev", err);
    }
    return err;
}



int aesd_init_module(void)
{
    dev_t dev = 0;
    int result;
    result = alloc_chrdev_region(&dev, aesd_minor, 1,
            "aesdchar");
    aesd_major = MAJOR(dev);
    if (result < 0) {
        printk(KERN_WARNING "Can't get major %d\n", aesd_major);
        return result;
    }
    memset(&aesd_device,0,sizeof(struct aesd_dev));

    /**
     * TODO: initialize the AESD specific portion of the device
     */
    mutex_init(&aesd_device.lock);
    aesd_circular_buffer_init(&aesd_device.circ);
    aesd_device.pending.buffptr = NULL;
    aesd_device.pending.size = 0;
    result = aesd_setup_cdev(&aesd_device);

    if( result ) {
        unregister_chrdev_region(dev, 1);
    }
    return result;

}

void aesd_cleanup_module(void)
{
    dev_t devno = MKDEV(aesd_major, aesd_minor);

    cdev_del(&aesd_device.cdev);

    /**
     * TODO: cleanup AESD specific poritions here as necessary
     */
uint8_t i;
    for (i = 0; i < AESDCHAR_MAX_WRITE_OPERATIONS_SUPPORTED; i++) {
        if (aesd_device.circ.entry[i].buffptr)
            kfree(aesd_device.circ.entry[i].buffptr);
        aesd_device.circ.entry[i].buffptr = NULL;
        aesd_device.circ.entry[i].size = 0;
    }
    if (aesd_device.pending.buffptr) {
        kfree(aesd_device.pending.buffptr);
        aesd_device.pending.buffptr = NULL;
        aesd_device.pending.size = 0;
    }
    unregister_chrdev_region(devno, 1);
}



module_init(aesd_init_module);
module_exit(aesd_cleanup_module);
