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
#include <linux/fs.h> 
#include <linux/slab.h>  
#include <linux/string.h> 
#include "aesdchar.h"
#include "aesd_ioctl.h"
#include <linux/uaccess.h> 
#include <linux/minmax.h>  


int aesd_major =   0; // use dynamic major
int aesd_minor =   0;

MODULE_AUTHOR("Kaif Shaikh"); /** TODO: fill in your name **/
MODULE_LICENSE("Dual BSD/GPL");

struct aesd_dev aesd_device;

static loff_t aesd_llseek(struct file *filp, loff_t off, int whence)
{
    struct aesd_dev *dev = filp->private_data;
    loff_t newpos;
    size_t total_size = 0;

    if (!dev) return -EINVAL;
    if (mutex_lock_interruptible(&dev->lock)) return -ERESTARTSYS;

    /* compute number of valid entries */
    int count;
    if (dev->circ.full) count = AESDCHAR_MAX_WRITE_OPERATIONS_SUPPORTED;
    else if (dev->circ.in_offs == dev->circ.out_offs) count = 0;
    else if (dev->circ.in_offs > dev->circ.out_offs)
        count = dev->circ.in_offs - dev->circ.out_offs;
    else
        count = AESDCHAR_MAX_WRITE_OPERATIONS_SUPPORTED - dev->circ.out_offs + dev->circ.in_offs;

    uint8_t idx = dev->circ.out_offs;
    for (int i = 0; i < count; i++) {
        total_size += dev->circ.entry[idx].size;
        idx = (idx + 1) % AESDCHAR_MAX_WRITE_OPERATIONS_SUPPORTED;
    }

    switch (whence) {
    case SEEK_SET: newpos = off; break;
    case SEEK_CUR: newpos = filp->f_pos + off; break;
    case SEEK_END: newpos = (loff_t)total_size + off; break;
    default:
        mutex_unlock(&dev->lock);
        return -EINVAL;
    }

    if (newpos < 0) newpos = 0;
    if (newpos > (loff_t)total_size) newpos = (loff_t)total_size;

    filp->f_pos = newpos;
    mutex_unlock(&dev->lock);
    return newpos;
}

static long aesd_unlocked_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
    struct aesd_dev *dev = filp->private_data;
    struct aesd_seekto seekto;

    if (!dev) return -EINVAL;

    switch (cmd) {
    case AESDCHAR_IOCSEEKTO:
        if (copy_from_user(&seekto, (const void __user *)arg, sizeof(seekto)))
            return -EFAULT;

        if (mutex_lock_interruptible(&dev->lock)) return -ERESTARTSYS;

        /* how many valid entries exist right now? */
        {
            int count;
            if (dev->circ.full) count = AESDCHAR_MAX_WRITE_OPERATIONS_SUPPORTED;
            else if (dev->circ.in_offs == dev->circ.out_offs) count = 0;
            else if (dev->circ.in_offs > dev->circ.out_offs)
                count = dev->circ.in_offs - dev->circ.out_offs;
            else
                count = AESDCHAR_MAX_WRITE_OPERATIONS_SUPPORTED - dev->circ.out_offs + dev->circ.in_offs;

            /* validate write_cmd against current count */
            if ((int)seekto.write_cmd >= count) {
                mutex_unlock(&dev->lock);
                return -EINVAL;
            }

            /* translate logical command index to ring index starting at out_offs */
            uint8_t idx = (dev->circ.out_offs + seekto.write_cmd) % AESDCHAR_MAX_WRITE_OPERATIONS_SUPPORTED;

            /* validate offset within that command */
            if (seekto.write_cmd_offset >= dev->circ.entry[idx].size) {
                mutex_unlock(&dev->lock);
                return -EINVAL;
            }

            /* compute absolute byte position: sum sizes of prior commands, then add offset */
            loff_t pos = 0;
            uint8_t walk = dev->circ.out_offs;
            for (uint32_t i = 0; i < seekto.write_cmd; i++) {
                pos += dev->circ.entry[walk].size;
                walk = (walk + 1) % AESDCHAR_MAX_WRITE_OPERATIONS_SUPPORTED;
            }
            pos += seekto.write_cmd_offset;

            filp->f_pos = pos;
        }

        mutex_unlock(&dev->lock);
        return 0;

    default:
        return -ENOTTY;
    }
}

int aesd_open(struct inode *inode, struct file *filp)
{
    PDEBUG("open");
    /**
     * TODO: handle open
     */
    struct aesd_dev *dev;
    dev = container_of(inode->i_cdev, struct aesd_dev, cdev);
    filp->private_data = dev;
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
    ssize_t retval = 0;
    PDEBUG("read %zu bytes with offset %lld",count,*f_pos);
    /**
     * TODO: handle read
     */
     
    struct aesd_dev *dev = filp->private_data;
    size_t entry_offset;
    struct aesd_buffer_entry *entry;

    mutex_lock(&dev->lock);
    
    entry = aesd_circular_buffer_find_entry_offset_for_fpos(
        &dev->circ, *f_pos, &entry_offset);
    
    if(entry)
    {
        size_t bytes_to_read = min(count, entry->size - entry_offset);
        if(copy_to_user(buf, entry->buffptr + entry_offset, bytes_to_read))
        {
            retval = -EFAULT;
        } else
        {
            retval = bytes_to_read;
            *f_pos += bytes_to_read;
        }
    }
    
    mutex_unlock(&dev->lock);

    return retval;
}

ssize_t aesd_write(struct file *filp, const char __user *buf, size_t count,
                   loff_t *f_pos)
{
    struct aesd_dev *dev = filp->private_data;
    char *data = NULL;
    const char *newline;
    ssize_t retval = -ENOMEM;

    if (!count) return 0;
    if (mutex_lock_interruptible(&dev->lock)) return -ERESTARTSYS;

    data = kmalloc(count, GFP_KERNEL);
    if (!data) goto out_unlock;

    if (copy_from_user(data, buf, count)) {
        retval = -EFAULT;
        goto out_unlock;
    }

    newline = memchr(data, '\n', count);

    if (!newline) {
        char *newp = krealloc(dev->partial_write, dev->partial_size + count, GFP_KERNEL);
        if (!newp) goto out_unlock;
        memcpy(newp + dev->partial_size, data, count);
        dev->partial_write = newp;
        dev->partial_size += count;
        retval = count;                              // <— keep this as count
        goto out_unlock;
    }

    /* complete one command through '\n' */
    {
        size_t first_len  = (newline - data) + 1;
        size_t total_size = dev->partial_size + first_len;
        char *combined = krealloc(dev->partial_write, total_size, GFP_KERNEL);
        if (!combined) goto out_unlock;

        memcpy(combined + dev->partial_size, data, first_len);

        /* free overwritten slot if full */
        if (dev->circ.full) {
            struct aesd_buffer_entry *old = &dev->circ.entry[dev->circ.in_offs];
            if (old->buffptr) kfree(old->buffptr);
        }

        /* push entry */
        {
            struct aesd_buffer_entry entry = {
                .buffptr = combined,
                .size    = total_size
            };
            aesd_circular_buffer_add_entry(&dev->circ, &entry);
        }

        /* reset partial */
        dev->partial_write = NULL;
        dev->partial_size  = 0;

        /* stash any tail after newline */
        {
            size_t tail_len = count - first_len;
            if (tail_len) {
                char *tail = kmalloc(tail_len, GFP_KERNEL);
                if (!tail) { retval = -ENOMEM; goto out_unlock; }
                memcpy(tail, newline + 1, tail_len);
                dev->partial_write = tail;
                dev->partial_size  = tail_len;
            }
        }

        retval = count;                              // <— **THIS is the fix**
    }

out_unlock:
    kfree(data);
    mutex_unlock(&dev->lock);
    return retval;
}

struct file_operations aesd_fops = {
   .owner          = THIS_MODULE,
    .read           = aesd_read,
    .write          = aesd_write,
    .open           = aesd_open,
    .release        = aesd_release,
    .llseek         = aesd_llseek,          
    .unlocked_ioctl = aesd_unlocked_ioctl, 
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

    memset(&aesd_device, 0, sizeof(struct aesd_dev));
    mutex_init(&aesd_device.lock);
    aesd_circular_buffer_init(&aesd_device.circ);
    aesd_device.partial_write = NULL;
    aesd_device.partial_size = 0;

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

    //Cleanup memory
    for(int i = 0; i < AESDCHAR_MAX_WRITE_OPERATIONS_SUPPORTED; i++) {
        kfree(aesd_device.circ.entry[i].buffptr);
    }
    if(aesd_device.partial_write)
    {
        kfree(aesd_device.partial_write);
    }
    mutex_destroy(&aesd_device.lock);

    unregister_chrdev_region(devno, 1);
}



module_init(aesd_init_module);
module_exit(aesd_cleanup_module);
