/*
 * Optimized TEE driver for Goodix fingerprint sensor
 * Copyright (C) 2016 Goodix
 * Optimized for ASUS X00TD kernel 4.19
 */
#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/init.h>
#include <linux/module.h>
#include <linux/ioctl.h>
#include <linux/fs.h>
#include <linux/device.h>
#include <linux/input.h>
#include <linux/err.h>
#include <linux/list.h>
#include <linux/errno.h>
#include <linux/mutex.h>
#include <linux/compat.h>
#include <linux/delay.h>
#include <linux/uaccess.h>
#include <linux/interrupt.h>
#include <linux/irq.h>
#include <linux/gpio.h>
#include <linux/of_gpio.h>
#include <linux/fb.h>
#include <linux/pm_wakeup.h>
#include <linux/platform_device.h>

#include "gf_spi.h"

#define VER_MAJOR   1
#define VER_MINOR   3
#define PATCH_LEVEL 0

#define GF_SPIDEV_NAME  "goodix,fingerprint"
#define GF_DEV_NAME     "goodix_fp"
#define GF_INPUT_NAME   "uinput-goodix"
#define CHRD_DRIVER_NAME "goodix_fp_spi"
#define CLASS_NAME      "goodix_fp"

#define N_SPI_MINORS    32

static int SPIDEV_MAJOR;
static DECLARE_BITMAP(minors, N_SPI_MINORS);
static LIST_HEAD(device_list);
static DEFINE_MUTEX(device_list_lock);
static struct wakeup_source *fp_wakelock;
static struct gf_dev gf;
static struct class *gf_class;

/* Убрали __read_mostly чтобы избежать конфликта секций */
static const struct gf_key_map maps[] = {
    { EV_KEY, GF_KEY_INPUT_HOME },
    { EV_KEY, GF_KEY_INPUT_MENU },
    { EV_KEY, GF_KEY_INPUT_BACK },
    { EV_KEY, GF_KEY_INPUT_POWER },
};

/* Optimized IRQ enable/disable with spinlock */
static void gf_enable_irq(struct gf_dev *gf_dev)
{
    unsigned long flags;

    spin_lock_irqsave(&gf_dev->irq_lock, flags);
    if (!gf_dev->irq_enabled) {
        enable_irq(gf_dev->irq);
        gf_dev->irq_enabled = true;
    }
    spin_unlock_irqrestore(&gf_dev->irq_lock, flags);
}

static void gf_disable_irq(struct gf_dev *gf_dev)
{
    unsigned long flags;

    spin_lock_irqsave(&gf_dev->irq_lock, flags);
    if (gf_dev->irq_enabled) {
        gf_dev->irq_enabled = false;
        disable_irq_nosync(gf_dev->irq);
    }
    spin_unlock_irqrestore(&gf_dev->irq_lock, flags);
}

static void gf_kernel_key_input(struct gf_dev *gf_dev, struct gf_key *gf_key)
{
    uint32_t key_input;

    switch (gf_key->key) {
    case GF_KEY_HOME:
        key_input = GF_KEY_INPUT_HOME;
        break;
    case GF_KEY_POWER:
        key_input = GF_KEY_INPUT_POWER;
        break;
    case GF_KEY_CAMERA:
        key_input = GF_KEY_INPUT_CAMERA;
        break;
    default:
        key_input = gf_key->key;
        break;
    }

    if ((gf_key->key == GF_KEY_POWER || gf_key->key == GF_KEY_CAMERA)
        && gf_key->value == 1) {
        input_report_key(gf_dev->input, key_input, 1);
        input_sync(gf_dev->input);
        input_report_key(gf_dev->input, key_input, 0);
        input_sync(gf_dev->input);
    } else if (gf_key->key == GF_KEY_HOME) {
        input_report_key(gf_dev->input, key_input, gf_key->value);
        input_sync(gf_dev->input);
    }
}

static long gf_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
    struct gf_dev *gf_dev = &gf;
    struct gf_key gf_key;
    int retval = 0;
    u8 netlink_route = NETLINK_TEST;
    struct gf_ioc_chip_info info;

    if (_IOC_TYPE(cmd) != GF_IOC_MAGIC)
        return -ENODEV;

    /* Исправлено: используем 3-аргументную форму access_ok для kernel 4.19 */
    if (_IOC_DIR(cmd) & _IOC_READ)
        retval = !access_ok(VERIFY_WRITE, (void __user *)arg, _IOC_SIZE(cmd));
    else if (_IOC_DIR(cmd) & _IOC_WRITE)
        retval = !access_ok(VERIFY_READ, (void __user *)arg, _IOC_SIZE(cmd));
    if (retval)
        return -EFAULT;

    if (!gf_dev->device_available &&
        cmd != GF_IOC_ENABLE_POWER && cmd != GF_IOC_DISABLE_POWER) {
        pr_debug("Sensor is power off\n");
        return -ENODEV;
    }

    switch (cmd) {
    case GF_IOC_INIT:
        if (copy_to_user((void __user *)arg, &netlink_route, sizeof(u8)))
            retval = -EFAULT;
        break;

    case GF_IOC_EXIT:
        break;

    case GF_IOC_DISABLE_IRQ:
        gf_disable_irq(gf_dev);
        break;

    case GF_IOC_ENABLE_IRQ:
        gf_enable_irq(gf_dev);
        break;

    case GF_IOC_RESET:
        gf_hw_reset(gf_dev, 3);
        break;

    case GF_IOC_INPUT_KEY_EVENT:
        if (copy_from_user(&gf_key, (void __user *)arg, sizeof(struct gf_key))) {
            retval = -EFAULT;
            break;
        }
        gf_kernel_key_input(gf_dev, &gf_key);
        break;

    case GF_IOC_ENABLE_SPI_CLK:
    case GF_IOC_DISABLE_SPI_CLK:
        /* Not supported */
        break;

    case GF_IOC_ENABLE_POWER:
        if (!gf_dev->device_available) {
            gf_power_on(gf_dev);
            gf_dev->device_available = true;
        }
        break;

    case GF_IOC_DISABLE_POWER:
        if (gf_dev->device_available) {
            gf_power_off(gf_dev);
            gf_dev->device_available = false;
        }
        break;

    case GF_IOC_ENTER_SLEEP_MODE:
    case GF_IOC_GET_FW_INFO:
    case GF_IOC_REMOVE:
        break;

    case GF_IOC_CHIP_INFO:
        if (copy_from_user(&info, (void __user *)arg,
                           sizeof(struct gf_ioc_chip_info)))
            retval = -EFAULT;
        break;

    default:
        break;
    }

    return retval;
}

#ifdef CONFIG_COMPAT
static long gf_compat_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
    return gf_ioctl(filp, cmd, (unsigned long)compat_ptr(arg));
}
#endif

/* Optimized IRQ handler - minimal work in interrupt context */
static irqreturn_t gf_irq(int irq, void *handle)
{
    char msg = GF_NET_EVENT_IRQ;

    __pm_wakeup_event(fp_wakelock, WAKELOCK_HOLD_TIME);
    sendnlmsg(&msg);

    return IRQ_HANDLED;
}

static int gf_open(struct inode *inode, struct file *filp)
{
    struct gf_dev *gf_dev = NULL;
    int status = -ENXIO;

    mutex_lock(&device_list_lock);

    list_for_each_entry(gf_dev, &device_list, device_entry) {
        if (gf_dev->devt == inode->i_rdev) {
            status = 0;
            break;
        }
    }

    if (status != 0) {
        pr_err("No device for minor %d\n", iminor(inode));
        goto out;
    }

    /* First open - setup everything */
    if (gf_dev->users == 0) {
        gf_power_on(gf_dev);

        if (!gf_dev->irq_requested) {
            status = request_threaded_irq(gf_dev->irq, NULL, gf_irq,
                    IRQF_TRIGGER_RISING | IRQF_ONESHOT,
                    "gf", gf_dev);
            if (status) {
                pr_err("Failed to request IRQ: %d\n", status);
                gf_power_off(gf_dev);
                goto out;
            }
            gf_dev->irq_requested = true;
            /* Start with IRQ disabled */
            disable_irq(gf_dev->irq);
            gf_dev->irq_enabled = false;
        }

        enable_irq_wake(gf_dev->irq);
        gf_enable_irq(gf_dev);
        gf_hw_reset(gf_dev, 3);
        gf_dev->device_available = true;
    }

    gf_dev->users++;
    filp->private_data = gf_dev;
    nonseekable_open(inode, filp);

    pr_info("Device opened, users=%d, irq=%d\n", gf_dev->users, gf_dev->irq);

out:
    mutex_unlock(&device_list_lock);
    return status;
}

static int gf_release(struct inode *inode, struct file *filp)
{
    struct gf_dev *gf_dev = filp->private_data;

    mutex_lock(&device_list_lock);

    filp->private_data = NULL;
    gf_dev->users--;

    if (gf_dev->users == 0) {
        gf_disable_irq(gf_dev);
        disable_irq_wake(gf_dev->irq);
        gf_dev->device_available = false;
        gf_power_off(gf_dev);
        pr_info("Last close, powered off\n");
    }

    mutex_unlock(&device_list_lock);
    return 0;
}

static const struct file_operations gf_fops = {
    .owner = THIS_MODULE,
    .unlocked_ioctl = gf_ioctl,
#ifdef CONFIG_COMPAT
    .compat_ioctl = gf_compat_ioctl,
#endif
    .open = gf_open,
    .release = gf_release,
};

static int goodix_fb_state_chg_callback(struct notifier_block *nb,
                                        unsigned long val, void *data)
{
    struct gf_dev *gf_dev;
    struct fb_event *evdata = data;
    unsigned int blank;
    char msg;

    if (val != FB_EARLY_EVENT_BLANK || !evdata || !evdata->data)
        return NOTIFY_OK;

    gf_dev = container_of(nb, struct gf_dev, notifier);
    if (!gf_dev->device_available)
        return NOTIFY_OK;

    blank = *(int *)(evdata->data);

    switch (blank) {
    case FB_BLANK_POWERDOWN:
        gf_dev->fb_black = true;
        msg = GF_NET_EVENT_FB_BLACK;
        sendnlmsg(&msg);
        break;
    case FB_BLANK_UNBLANK:
        gf_dev->fb_black = false;
        msg = GF_NET_EVENT_FB_UNBLACK;
        sendnlmsg(&msg);
        break;
    default:
        break;
    }

    return NOTIFY_OK;
}

static struct notifier_block goodix_noti_block = {
    .notifier_call = goodix_fb_state_chg_callback,
};

static int gf_probe(struct platform_device *pdev)
{
    struct gf_dev *gf_dev = &gf;
    int status = -EINVAL;
    unsigned long minor;
    int i;

    pr_info("Probing Goodix fingerprint sensor\n");

    /* Initialize driver data */
    INIT_LIST_HEAD(&gf_dev->device_entry);
    spin_lock_init(&gf_dev->irq_lock);
    gf_dev->spi = pdev;
    gf_dev->irq_gpio = -EINVAL;
    gf_dev->reset_gpio = -EINVAL;
    gf_dev->vdd_gpio = -EINVAL;
    gf_dev->device_available = false;
    gf_dev->fb_black = false;
    gf_dev->irq_requested = false;
    gf_dev->irq_enabled = false;
    gf_dev->users = 0;

    status = gf_parse_dts(gf_dev);
    if (status)
        goto error_hw;

    /* Allocate minor number */
    mutex_lock(&device_list_lock);
    minor = find_first_zero_bit(minors, N_SPI_MINORS);
    if (minor < N_SPI_MINORS) {
        struct device *dev;
        gf_dev->devt = MKDEV(SPIDEV_MAJOR, minor);
        dev = device_create(gf_class, &pdev->dev, gf_dev->devt,
                           gf_dev, GF_DEV_NAME);
        status = IS_ERR(dev) ? PTR_ERR(dev) : 0;
    } else {
        status = -ENODEV;
    }

    if (status == 0) {
        set_bit(minor, minors);
        list_add(&gf_dev->device_entry, &device_list);
    }
    mutex_unlock(&device_list_lock);

    if (status)
        goto error_hw;

    /* Setup input device */
    gf_dev->input = input_allocate_device();
    if (!gf_dev->input) {
        status = -ENOMEM;
        goto error_dev;
    }

    gf_dev->input->name = GF_INPUT_NAME;
    for (i = 0; i < ARRAY_SIZE(maps); i++)
        input_set_capability(gf_dev->input, maps[i].type, maps[i].code);

    status = input_register_device(gf_dev->input);
    if (status) {
        pr_err("Failed to register input device\n");
        goto error_input;
    }

    /* Setup FB notifier */
    gf_dev->notifier = goodix_noti_block;
    fb_register_client(&gf_dev->notifier);

    /* Get IRQ number */
    gf_dev->irq = gf_irq_num(gf_dev);

    /* Create wakelock */
    fp_wakelock = wakeup_source_register(&pdev->dev, "fp_wakelock");
    if (!fp_wakelock) {
        pr_err("Failed to register wakeup source\n");
        status = -ENOMEM;
        goto error_wakelock;
    }

    platform_set_drvdata(pdev, gf_dev);

    pr_info("Probe successful, version V%d.%d.%02d\n",
            VER_MAJOR, VER_MINOR, PATCH_LEVEL);

    return 0;

error_wakelock:
    fb_unregister_client(&gf_dev->notifier);
    input_unregister_device(gf_dev->input);
    gf_dev->input = NULL;
error_input:
    if (gf_dev->input)
        input_free_device(gf_dev->input);
error_dev:
    mutex_lock(&device_list_lock);
    list_del(&gf_dev->device_entry);
    device_destroy(gf_class, gf_dev->devt);
    clear_bit(MINOR(gf_dev->devt), minors);
    mutex_unlock(&device_list_lock);
error_hw:
    gf_cleanup(gf_dev);
    return status;
}

static int gf_remove(struct platform_device *pdev)
{
    struct gf_dev *gf_dev = platform_get_drvdata(pdev);

    wakeup_source_unregister(fp_wakelock);
    fb_unregister_client(&gf_dev->notifier);

    if (gf_dev->irq_requested) {
        disable_irq_wake(gf_dev->irq);
        free_irq(gf_dev->irq, gf_dev);
    }

    if (gf_dev->input) {
        input_unregister_device(gf_dev->input);
        gf_dev->input = NULL;
    }

    mutex_lock(&device_list_lock);
    list_del(&gf_dev->device_entry);
    device_destroy(gf_class, gf_dev->devt);
    clear_bit(MINOR(gf_dev->devt), minors);
    mutex_unlock(&device_list_lock);

    gf_cleanup(gf_dev);

    return 0;
}

static const struct of_device_id gx_match_table[] = {
    { .compatible = GF_SPIDEV_NAME },
    { },
};
MODULE_DEVICE_TABLE(of, gx_match_table);

static struct platform_driver gf_driver = {
    .driver = {
        .name = GF_DEV_NAME,
        .owner = THIS_MODULE,
        .of_match_table = gx_match_table,
    },
    .probe = gf_probe,
    .remove = gf_remove,
};

static int __init gf_init(void)
{
    int status;

    BUILD_BUG_ON(N_SPI_MINORS > 256);

    status = register_chrdev(0, CHRD_DRIVER_NAME, &gf_fops);
    if (status < 0) {
        pr_err("Failed to register char device\n");
        return status;
    }
    SPIDEV_MAJOR = status;

    gf_class = class_create(THIS_MODULE, CLASS_NAME);
    if (IS_ERR(gf_class)) {
        unregister_chrdev(SPIDEV_MAJOR, CHRD_DRIVER_NAME);
        return PTR_ERR(gf_class);
    }

    status = platform_driver_register(&gf_driver);
    if (status < 0) {
        class_destroy(gf_class);
        unregister_chrdev(SPIDEV_MAJOR, CHRD_DRIVER_NAME);
        return status;
    }

#ifdef GF_NETLINK_ENABLE
    netlink_init();
#endif

    pr_info("Driver loaded\n");
    return 0;
}
module_init(gf_init);

static void __exit gf_exit(void)
{
#ifdef GF_NETLINK_ENABLE
    netlink_exit();
#endif
    platform_driver_unregister(&gf_driver);
    class_destroy(gf_class);
    unregister_chrdev(SPIDEV_MAJOR, CHRD_DRIVER_NAME);
}
module_exit(gf_exit);

MODULE_AUTHOR("Goodix");
MODULE_DESCRIPTION("Optimized Goodix fingerprint sensor driver");
MODULE_LICENSE("GPL v2");
