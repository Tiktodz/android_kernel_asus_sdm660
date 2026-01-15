/* Copyright (c) 2015-2019, The Linux Foundation. All rights reserved.
 * Copyright (c) 2023-2025, Modified for Android 12+ NXP NFC compatibility
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 and
 * only version 2 as published by the Free Software Foundation.
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/fs.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/reboot.h>
#include <linux/slab.h>
#include <linux/irq.h>
#include <linux/delay.h>
#include <linux/interrupt.h>
#include <linux/gpio.h>
#include <linux/spinlock.h>
#include <linux/of_gpio.h>
#include <linux/of_device.h>
#include <linux/uaccess.h>
#include <linux/clk.h>
#include <linux/pinctrl/consumer.h>
#include "nq-nci.h"

#ifdef CONFIG_COMPAT
#include <linux/compat.h>
#endif

#define DEV_COUNT           1
#define DEVICE_NAME         "nq-nci"
#define CLASS_NAME          "nqx"
#define PAGESIZE            512
#define MAX_BUFFER_SIZE     (320)
#define WAKEUP_SRC_TIMEOUT  (2000)
#define MAX_RETRY_COUNT     3
#define HW_CHECK_RETRIES    3

struct nqx_platform_data {
    unsigned int irq_gpio;
    unsigned int en_gpio;
    unsigned int clkreq_gpio;
    unsigned int firm_gpio;
    unsigned int ese_gpio;
    const char *clk_src_name;
    bool clk_pin_voting;
};

struct nqx_dev {
    wait_queue_head_t   read_wq;
    struct mutex        read_mutex;
    struct mutex        dev_ref_mutex;
    struct i2c_client   *client;
    dev_t               devno;
    struct class        *nqx_class;
    struct device       *nqx_device;
    struct cdev         c_dev;
    union nqx_uinfo     nqx_info;
    unsigned int        irq_gpio;
    unsigned int        en_gpio;
    unsigned int        firm_gpio;
    unsigned int        clkreq_gpio;
    unsigned int        ese_gpio;
    bool                nfc_ven_enabled;
    bool                irq_enabled;
    bool                irq_wake_up;
    spinlock_t          irq_enabled_lock;
    unsigned int        count_irq;
    unsigned int        dev_ref_count;
    unsigned int        core_reset_ntf;
    bool                clk_run;
    struct clk          *s_clk;
    size_t              kbuflen;
    u8                  *kbuf;
    struct nqx_platform_data *pdata;
    struct pinctrl      *pinctrl;
    struct pinctrl_state *pinctrl_active;
    struct pinctrl_state *pinctrl_suspend;
};

static const struct of_device_id msm_match_table[] = {
    {.compatible = "qcom,nq-nci"},
    {}
};
MODULE_DEVICE_TABLE(of, msm_match_table);

static bool has_nfc;
static unsigned int disable_ctrl;
static struct proc_dir_entry *has_nfc_proc;

static int nfcc_reboot(struct notifier_block *notifier, unsigned long val, void *v);
static int nqx_clock_select(struct nqx_dev *nqx_dev);
static int nqx_clock_deselect(struct nqx_dev *nqx_dev);
static int nfc_ioctl_power_states(struct file *filp, unsigned long arg);

static struct notifier_block nfcc_notifier = {
    .notifier_call  = nfcc_reboot,
    .next           = NULL,
    .priority       = 0
};

static void nqx_init_stat(struct nqx_dev *nqx_dev)
{
    nqx_dev->count_irq = 0;
}

static void nqx_disable_irq(struct nqx_dev *nqx_dev)
{
    unsigned long flags;

    spin_lock_irqsave(&nqx_dev->irq_enabled_lock, flags);
    if (nqx_dev->irq_enabled) {
        disable_irq_nosync(nqx_dev->client->irq);
        nqx_dev->irq_enabled = false;
    }
    spin_unlock_irqrestore(&nqx_dev->irq_enabled_lock, flags);
}

static void nqx_enable_irq(struct nqx_dev *nqx_dev)
{
    unsigned long flags;

    spin_lock_irqsave(&nqx_dev->irq_enabled_lock, flags);
    if (!nqx_dev->irq_enabled) {
        nqx_dev->irq_enabled = true;
        enable_irq(nqx_dev->client->irq);
    }
    spin_unlock_irqrestore(&nqx_dev->irq_enabled_lock, flags);
}

static irqreturn_t nqx_dev_irq_handler(int irq, void *dev_id)
{
    struct nqx_dev *nqx_dev = dev_id;
    unsigned long flags;

    if (device_may_wakeup(&nqx_dev->client->dev))
        pm_wakeup_event(&nqx_dev->client->dev, WAKEUP_SRC_TIMEOUT);

    nqx_disable_irq(nqx_dev);
    spin_lock_irqsave(&nqx_dev->irq_enabled_lock, flags);
    nqx_dev->count_irq++;
    spin_unlock_irqrestore(&nqx_dev->irq_enabled_lock, flags);
    wake_up(&nqx_dev->read_wq);

    return IRQ_HANDLED;
}

/*
 * Proc filesystem entry for NFC detection status
 * Uses file_operations (kernel 4.19 compatible)
 */
static ssize_t proc_has_nfc_read(struct file *file, char __user *user_buf,
                                 size_t count, loff_t *ppos)
{
    char page[PAGESIZE] = {0};
    int len;

    len = snprintf(page, PAGESIZE - 1, "%s\n", 
                   has_nfc ? "SUPPORTED" : "NOT SUPPORTED");
    return simple_read_from_buffer(user_buf, count, ppos, page, len);
}

/* Kernel 4.19 uses file_operations for proc entries */
static const struct file_operations proc_has_nfc_fops = {
    .owner = THIS_MODULE,
    .read  = proc_has_nfc_read,
};

/*
 * Hardware check - verify NFC chip is physically present
 * Returns true if chip responds to I2C commands
 */
static bool nqx_hw_check(struct i2c_client *client, unsigned int en_gpio)
{
    int ret;
    unsigned char nci_reset_cmd[] = {0x20, 0x00, 0x01, 0x01};
    unsigned char buf[32] = {0};
    int retry = HW_CHECK_RETRIES;

    /* Power on the chip */
    gpio_set_value(en_gpio, 1);
    msleep(20);

    /* Try to communicate */
    while (retry--) {
        ret = i2c_master_send(client, nci_reset_cmd, sizeof(nci_reset_cmd));
        if (ret == sizeof(nci_reset_cmd)) {
            msleep(10);
            ret = i2c_master_recv(client, buf, 6);
            if (ret > 0) {
                dev_info(&client->dev,
                    "NFC chip detected: %02x %02x %02x %02x %02x %02x\n",
                    buf[0], buf[1], buf[2], buf[3], buf[4], buf[5]);
                gpio_set_value(en_gpio, 0);
                return true;
            }
        }
        msleep(10);
    }

    gpio_set_value(en_gpio, 0);
    dev_info(&client->dev, "NFC chip NOT detected\n");
    return false;
}

static ssize_t nfc_read(struct file *filp, char __user *buf,
                        size_t count, loff_t *offset)
{
    struct nqx_dev *nqx_dev = filp->private_data;
    unsigned char *tmp = NULL;
    int ret;
    int irq_gpio_val;

    if (!nqx_dev)
        return -ENODEV;

    if (count > nqx_dev->kbuflen)
        count = nqx_dev->kbuflen;

    mutex_lock(&nqx_dev->read_mutex);

    irq_gpio_val = gpio_get_value(nqx_dev->irq_gpio);
    if (irq_gpio_val == 0) {
        if (filp->f_flags & O_NONBLOCK) {
            ret = -EAGAIN;
            goto err;
        }
        while (1) {
            ret = 0;
            if (!nqx_dev->irq_enabled) {
                nqx_dev->irq_enabled = true;
                enable_irq(nqx_dev->client->irq);
            }
            if (!gpio_get_value(nqx_dev->irq_gpio)) {
                ret = wait_event_interruptible(nqx_dev->read_wq,
                    !nqx_dev->irq_enabled);
            }
            if (ret)
                goto err;
            nqx_disable_irq(nqx_dev);

            if (gpio_get_value(nqx_dev->irq_gpio))
                break;
        }
    }

    tmp = nqx_dev->kbuf;
    if (!tmp) {
        ret = -ENODEV;
        goto err;
    }
    memset(tmp, 0x00, count);

    ret = i2c_master_recv(nqx_dev->client, tmp, count);
    if (ret < 0)
        goto err;

    if (ret > count) {
        ret = -EIO;
        goto err;
    }

    if (copy_to_user(buf, tmp, ret)) {
        ret = -EFAULT;
        goto err;
    }
    mutex_unlock(&nqx_dev->read_mutex);
    return ret;

err:
    mutex_unlock(&nqx_dev->read_mutex);
    return ret;
}

static ssize_t nfc_write(struct file *filp, const char __user *buf,
                         size_t count, loff_t *offset)
{
    struct nqx_dev *nqx_dev = filp->private_data;
    char *tmp = NULL;
    int ret = 0;

    if (!nqx_dev)
        return -ENODEV;

    if (count > nqx_dev->kbuflen)
        return -ENOMEM;

    tmp = memdup_user(buf, count);
    if (IS_ERR(tmp))
        return PTR_ERR(tmp);

    ret = i2c_master_send(nqx_dev->client, tmp, count);
    if (ret != count) {
        ret = -EIO;
        goto out_free;
    }
    usleep_range(1000, 1100);

out_free:
    kfree(tmp);
    return ret;
}

static int nqx_standby_write(struct nqx_dev *nqx_dev,
                             const unsigned char *buf, size_t len)
{
    int ret = -EINVAL;
    int retry_cnt;

    for (retry_cnt = 1; retry_cnt <= MAX_RETRY_COUNT; retry_cnt++) {
        ret = i2c_master_send(nqx_dev->client, buf, len);
        if (ret < 0)
            usleep_range(1000, 1100);
        else if (ret == len)
            break;
    }
    return ret;
}

static int sn100_ese_pwr(struct nqx_dev *nqx_dev, unsigned long int arg)
{
    int r = -1;

    if (arg == ESE_POWER_ON) {
        nqx_dev->nfc_ven_enabled = gpio_get_value(nqx_dev->en_gpio);
        if (!nqx_dev->nfc_ven_enabled) {
            gpio_set_value(nqx_dev->en_gpio, 1);
            usleep_range(1000, 1100);
        }
        r = 0;
    } else if (arg == ESE_POWER_OFF) {
        if (!nqx_dev->nfc_ven_enabled) {
            gpio_set_value(nqx_dev->en_gpio, 0);
            usleep_range(1000, 1100);
        }
        r = 0;
    } else if (arg == ESE_POWER_STATE) {
        r = gpio_get_value(nqx_dev->en_gpio);
    }
    return r;
}

static int nqx_ese_pwr(struct nqx_dev *nqx_dev, unsigned long int arg)
{
    int r = -1;
    const unsigned char svdd_off_cmd_warn[] = {0x2F, 0x31, 0x01, 0x01};
    const unsigned char svdd_off_cmd_done[] = {0x2F, 0x31, 0x01, 0x00};

    if (!gpio_is_valid(nqx_dev->ese_gpio))
        return -EINVAL;

    if (arg == ESE_POWER_ON) {
        if (gpio_get_value(nqx_dev->ese_gpio)) {
            r = 0;
        } else {
            nqx_dev->nfc_ven_enabled = gpio_get_value(nqx_dev->en_gpio);
            if (!nqx_dev->nfc_ven_enabled) {
                gpio_set_value(nqx_dev->en_gpio, 1);
                usleep_range(1000, 1100);
            }
            gpio_set_value(nqx_dev->ese_gpio, 1);
            usleep_range(1000, 1100);
            if (gpio_get_value(nqx_dev->ese_gpio))
                r = 0;
        }
    } else if (arg == ESE_POWER_OFF) {
        if (nqx_dev->nfc_ven_enabled &&
            ((nqx_dev->nqx_info.info.chip_type == NFCC_NQ_220) ||
             (nqx_dev->nqx_info.info.chip_type == NFCC_PN66T))) {
            r = nqx_standby_write(nqx_dev, svdd_off_cmd_warn,
                                  sizeof(svdd_off_cmd_warn));
            if (r < 0)
                return -ENXIO;

            gpio_set_value(nqx_dev->ese_gpio, 0);
            usleep_range(8000, 8100);

            r = nqx_standby_write(nqx_dev, svdd_off_cmd_done,
                                  sizeof(svdd_off_cmd_done));
            if (r < 0)
                return -ENXIO;
        } else {
            gpio_set_value(nqx_dev->ese_gpio, 0);
            usleep_range(1000, 1100);
        }

        if (!gpio_get_value(nqx_dev->ese_gpio))
            r = 0;

        if (!nqx_dev->nfc_ven_enabled) {
            usleep_range(1000, 1100);
            gpio_set_value(nqx_dev->en_gpio, 0);
        }
    } else if (arg == ESE_POWER_STATE) {
        r = gpio_get_value(nqx_dev->ese_gpio);
    }
    return r;
}

static bool is_sn100_chip(struct nqx_dev *nqx_dev)
{
    switch (nqx_dev->nqx_info.info.chip_type) {
    case NFCC_SN100_A:
    case NFCC_SN100_B:
    case NFCC_SN110_A:
    case NFCC_SN110_B:
    case NFCC_SN220_A:
    case NFCC_SN220_B:
        return true;
    default:
        return false;
    }
}

static int nfc_open(struct inode *inode, struct file *filp)
{
    struct nqx_dev *nqx_dev = container_of(inode->i_cdev,
                                           struct nqx_dev, c_dev);

    filp->private_data = nqx_dev;
    nqx_init_stat(nqx_dev);

    mutex_lock(&nqx_dev->dev_ref_mutex);

    if (nqx_dev->dev_ref_count == 0) {
        nfc_ioctl_power_states(filp, NFC_POWER_ON);
        nqx_enable_irq(nqx_dev);

        if (gpio_is_valid(nqx_dev->firm_gpio)) {
            gpio_set_value(nqx_dev->firm_gpio, 0);
            usleep_range(10000, 10100);
        }
    }
    nqx_dev->dev_ref_count++;

    mutex_unlock(&nqx_dev->dev_ref_mutex);
    return 0;
}

static int nfc_close(struct inode *inode, struct file *filp)
{
    struct nqx_dev *nqx_dev = container_of(inode->i_cdev,
                                           struct nqx_dev, c_dev);

    mutex_lock(&nqx_dev->dev_ref_mutex);

    if (nqx_dev->dev_ref_count == 1) {
        nfc_ioctl_power_states(filp, NFC_POWER_OFF);
        nqx_disable_irq(nqx_dev);

        if (gpio_is_valid(nqx_dev->firm_gpio)) {
            gpio_set_value(nqx_dev->firm_gpio, 0);
            usleep_range(10000, 10100);
        }
    }

    if (nqx_dev->dev_ref_count > 0)
        nqx_dev->dev_ref_count--;

    mutex_unlock(&nqx_dev->dev_ref_mutex);
    filp->private_data = NULL;
    return 0;
}

static int nfc_ioctl_power_states(struct file *filp, unsigned long arg)
{
    int r = 0;
    struct nqx_dev *nqx_dev = filp->private_data;

    if (!nqx_dev)
        return -ENODEV;

    switch (arg) {
    case NFC_POWER_OFF:
        nqx_disable_irq(nqx_dev);
        gpio_set_value(nqx_dev->en_gpio, 0);

        if (nqx_dev->pdata->clk_pin_voting) {
            r = nqx_clock_deselect(nqx_dev);
            if (r < 0)
                dev_err(&nqx_dev->client->dev,
                    "unable to disable clock\n");
        }

        if (nqx_dev->pinctrl && nqx_dev->pinctrl_suspend)
            pinctrl_select_state(nqx_dev->pinctrl,
                                 nqx_dev->pinctrl_suspend);

        nqx_dev->nfc_ven_enabled = false;
        break;

    case NFC_POWER_ON:
        if (nqx_dev->pinctrl && nqx_dev->pinctrl_active) {
            r = pinctrl_select_state(nqx_dev->pinctrl,
                                     nqx_dev->pinctrl_active);
            if (r)
                dev_err(&nqx_dev->client->dev,
                    "Failed to select pinctrl active state\n");
        }
        usleep_range(10000, 10100);

        if (!gpio_get_value(nqx_dev->en_gpio)) {
            gpio_set_value(nqx_dev->en_gpio, 1);
            msleep(100);
        }

        if (nqx_dev->pdata->clk_pin_voting) {
            r = nqx_clock_select(nqx_dev);
            if (r < 0)
                dev_err(&nqx_dev->client->dev,
                    "unable to enable clock\n");
        }

        nqx_enable_irq(nqx_dev);
        nqx_dev->nfc_ven_enabled = true;
        break;

    case NFC_FW_DWL_VEN_TOGGLE:
        if (gpio_is_valid(nqx_dev->firm_gpio)) {
            gpio_set_value(nqx_dev->firm_gpio, 1);
            usleep_range(10000, 10100);
        }
        gpio_set_value(nqx_dev->en_gpio, 0);
        usleep_range(10000, 10100);
        gpio_set_value(nqx_dev->en_gpio, 1);
        usleep_range(10000, 10100);
        break;

    case NFC_FW_DWL_HIGH:
        if (gpio_is_valid(nqx_dev->firm_gpio)) {
            gpio_set_value(nqx_dev->firm_gpio, 1);
            usleep_range(10000, 10100);
        }
        break;

    case NFC_FW_DWL_LOW:
        if (gpio_is_valid(nqx_dev->firm_gpio)) {
            gpio_set_value(nqx_dev->firm_gpio, 0);
            usleep_range(10000, 10100);
        }
        break;

    case NFC_ENABLE:
        gpio_set_value(nqx_dev->en_gpio, 1);
        usleep_range(10000, 10100);
        nqx_dev->nfc_ven_enabled = true;
        break;

    case NFC_DISABLE:
        gpio_set_value(nqx_dev->en_gpio, 0);
        usleep_range(10000, 10100);
        nqx_dev->nfc_ven_enabled = false;
        break;

    default:
        return -ENOIOCTLCMD;
    }

    return r;
}

static int nfc_ioctl_core_reset_ntf(struct file *filp)
{
    struct nqx_dev *nqx_dev = filp->private_data;
    return nqx_dev->core_reset_ntf;
}

static unsigned int nfc_ioctl_nfcc_info(struct file *filp, unsigned long arg)
{
    struct nqx_dev *nqx_dev = filp->private_data;
    return nqx_dev->nqx_info.i;
}

static long nfc_ioctl(struct file *pfile, unsigned int cmd, unsigned long arg)
{
    int r = 0;
    struct nqx_dev *nqx_dev = pfile->private_data;

    if (!nqx_dev)
        return -ENODEV;

    switch (cmd) {
    case NFC_SET_PWR:
        r = nfc_ioctl_power_states(pfile, arg);
        break;
    case ESE_SET_PWR:
        if (is_sn100_chip(nqx_dev))
            r = sn100_ese_pwr(nqx_dev, arg);
        else
            r = nqx_ese_pwr(nqx_dev, arg);
        break;
    case ESE_GET_PWR:
        if (is_sn100_chip(nqx_dev))
            r = sn100_ese_pwr(nqx_dev, ESE_POWER_STATE);
        else
            r = nqx_ese_pwr(nqx_dev, ESE_POWER_STATE);
        break;
    case SET_RX_BLOCK:
    case SET_EMULATOR_TEST_POINT:
        break;
    case NFCC_INITIAL_CORE_RESET_NTF:
        r = nfc_ioctl_core_reset_ntf(pfile);
        break;
    case NFCC_GET_INFO:
        r = nfc_ioctl_nfcc_info(pfile, arg);
        break;
    default:
        r = -ENOIOCTLCMD;
    }
    return r;
}

#ifdef CONFIG_COMPAT
static long nfc_compat_ioctl(struct file *pfile, unsigned int cmd,
                             unsigned long arg)
{
    long r = 0;

    arg = (compat_u64)arg;
    switch (cmd) {
    case NFC_SET_PWR:
        r = nfc_ioctl_power_states(pfile, arg);
        break;
    case ESE_SET_PWR:
        r = nqx_ese_pwr(pfile->private_data, arg);
        break;
    case ESE_GET_PWR:
        r = nqx_ese_pwr(pfile->private_data, ESE_POWER_STATE);
        break;
    case NFCC_INITIAL_CORE_RESET_NTF:
        r = nfc_ioctl_core_reset_ntf(pfile);
        break;
    case NFCC_GET_INFO:
        r = nfc_ioctl_nfcc_info(pfile, arg);
        break;
    case SET_RX_BLOCK:
    case SET_EMULATOR_TEST_POINT:
        break;
    default:
        r = -ENOTTY;
    }
    return r;
}
#endif

static const struct file_operations nfc_dev_fops = {
    .owner          = THIS_MODULE,
    .llseek         = no_llseek,
    .read           = nfc_read,
    .write          = nfc_write,
    .open           = nfc_open,
    .release        = nfc_close,
    .unlocked_ioctl = nfc_ioctl,
#ifdef CONFIG_COMPAT
    .compat_ioctl   = nfc_compat_ioctl
#endif
};

static int nqx_clock_select(struct nqx_dev *nqx_dev)
{
    int r = 0;

    nqx_dev->s_clk = clk_get(&nqx_dev->client->dev, "ref_clk");
    if (IS_ERR_OR_NULL(nqx_dev->s_clk))
        return -1;

    if (!nqx_dev->clk_run)
        r = clk_prepare_enable(nqx_dev->s_clk);

    if (r)
        return -1;

    nqx_dev->clk_run = true;
    return r;
}

static int nqx_clock_deselect(struct nqx_dev *nqx_dev)
{
    if (nqx_dev->s_clk != NULL) {
        if (nqx_dev->clk_run) {
            clk_disable_unprepare(nqx_dev->s_clk);
            nqx_dev->clk_run = false;
        }
        return 0;
    }
    return -1;
}

static int nfc_parse_dt(struct device *dev, struct nqx_platform_data *pdata)
{
    struct device_node *np = dev->of_node;

    pdata->en_gpio = of_get_named_gpio(np, "qcom,nq-ven", 0);
    if (!gpio_is_valid(pdata->en_gpio))
        return -EINVAL;
    disable_ctrl = pdata->en_gpio;

    pdata->irq_gpio = of_get_named_gpio(np, "qcom,nq-irq", 0);
    if (!gpio_is_valid(pdata->irq_gpio))
        return -EINVAL;

    pdata->firm_gpio = of_get_named_gpio(np, "qcom,nq-firm", 0);
    if (!gpio_is_valid(pdata->firm_gpio))
        pdata->firm_gpio = -EINVAL;

    pdata->ese_gpio = of_get_named_gpio(np, "qcom,nq-esepwr", 0);
    if (!gpio_is_valid(pdata->ese_gpio))
        pdata->ese_gpio = -EINVAL;

    if (of_property_read_string(np, "qcom,clk-src", &pdata->clk_src_name))
        pdata->clk_pin_voting = false;
    else
        pdata->clk_pin_voting = true;

    pdata->clkreq_gpio = of_get_named_gpio(np, "qcom,nq-clkreq", 0);

    return 0;
}

static int nqx_probe(struct i2c_client *client, const struct i2c_device_id *id)
{
    int r = 0;
    int irqn = 0;
    struct nqx_platform_data *platform_data;
    struct nqx_dev *nqx_dev;

    dev_info(&client->dev, "NQ-NCI probe start\n");

    if (client->dev.of_node) {
        platform_data = devm_kzalloc(&client->dev,
            sizeof(struct nqx_platform_data), GFP_KERNEL);
        if (!platform_data)
            return -ENOMEM;

        r = nfc_parse_dt(&client->dev, platform_data);
        if (r) {
            dev_err(&client->dev, "Failed to parse DT\n");
            goto err_free_data;
        }
    } else {
        platform_data = client->dev.platform_data;
    }

    if (!platform_data)
        return -ENODEV;

    if (!i2c_check_functionality(client->adapter, I2C_FUNC_I2C)) {
        dev_err(&client->dev, "I2C check failed\n");
        goto err_free_data;
    }

    /* Request EN GPIO first for hardware check */
    if (gpio_is_valid(platform_data->en_gpio)) {
        r = gpio_request(platform_data->en_gpio, "nfc_reset_gpio");
        if (r) {
            dev_err(&client->dev, "Failed to request EN GPIO\n");
            goto err_free_data;
        }
        r = gpio_direction_output(platform_data->en_gpio, 0);
        if (r) {
            gpio_free(platform_data->en_gpio);
            goto err_free_data;
        }
    } else {
        dev_err(&client->dev, "EN GPIO invalid\n");
        goto err_free_data;
    }

    /*
     * HARDWARE CHECK - Verify NFC chip is physically present
     * This MUST happen before allocating resources
     */
    if (!nqx_hw_check(client, platform_data->en_gpio)) {
        dev_info(&client->dev, "NFC hardware not present\n");
        has_nfc = false;

        /* Create proc entry showing NOT SUPPORTED */
        has_nfc_proc = proc_create("NFC_CHECK", 0444, NULL, &proc_has_nfc_fops);

        /* Clean up and return - not an error */
        gpio_free(platform_data->en_gpio);
        if (client->dev.of_node)
            devm_kfree(&client->dev, platform_data);

        dev_info(&client->dev, "NFC probe complete (no hardware)\n");
        return 0;
    }

    /* Hardware detected - continue full initialization */
    dev_info(&client->dev, "NFC hardware detected\n");

    nqx_dev = kzalloc(sizeof(*nqx_dev), GFP_KERNEL);
    if (!nqx_dev) {
        r = -ENOMEM;
        goto err_en_gpio;
    }

    nqx_dev->client = client;
    nqx_dev->kbuflen = MAX_BUFFER_SIZE;
    nqx_dev->kbuf = kzalloc(MAX_BUFFER_SIZE, GFP_KERNEL);
    if (!nqx_dev->kbuf) {
        r = -ENOMEM;
        goto err_free_dev;
    }

    nqx_dev->en_gpio = platform_data->en_gpio;

    /* Initialize pinctrl */
    nqx_dev->pinctrl = devm_pinctrl_get(&client->dev);
    if (IS_ERR(nqx_dev->pinctrl)) {
        nqx_dev->pinctrl = NULL;
    } else {
        nqx_dev->pinctrl_active = pinctrl_lookup_state(nqx_dev->pinctrl,
                                                       "nfc_active");
        if (IS_ERR(nqx_dev->pinctrl_active))
            nqx_dev->pinctrl_active = NULL;

        nqx_dev->pinctrl_suspend = pinctrl_lookup_state(nqx_dev->pinctrl,
                                                        "nfc_suspend");
        if (IS_ERR(nqx_dev->pinctrl_suspend))
            nqx_dev->pinctrl_suspend = NULL;
    }

    /* Request IRQ GPIO */
    if (gpio_is_valid(platform_data->irq_gpio)) {
        r = gpio_request(platform_data->irq_gpio, "nfc_irq_gpio");
        if (r)
            goto err_mem;

        r = gpio_direction_input(platform_data->irq_gpio);
        if (r)
            goto err_irq_gpio;

        irqn = gpio_to_irq(platform_data->irq_gpio);
        if (irqn < 0) {
            r = irqn;
            goto err_irq_gpio;
        }
        client->irq = irqn;
    } else {
        goto err_mem;
    }

    /* Request FIRM GPIO */
    if (gpio_is_valid(platform_data->firm_gpio)) {
        r = gpio_request(platform_data->firm_gpio, "nfc_firm_gpio");
        if (r)
            goto err_irq_gpio;

        r = gpio_direction_output(platform_data->firm_gpio, 0);
        if (r)
            goto err_firm_gpio;
    }

    /* Request ESE GPIO (optional) */
    if (gpio_is_valid(platform_data->ese_gpio)) {
        r = gpio_request(platform_data->ese_gpio, "nfc-ese_pwr");
        if (r) {
            nqx_dev->ese_gpio = -EINVAL;
        } else {
            nqx_dev->ese_gpio = platform_data->ese_gpio;
            r = gpio_direction_output(platform_data->ese_gpio, 0);
            if (r) {
                gpio_free(platform_data->ese_gpio);
                nqx_dev->ese_gpio = -EINVAL;
            }
        }
    } else {
        nqx_dev->ese_gpio = -EINVAL;
    }

    /* Request CLKREQ GPIO */
    if (gpio_is_valid(platform_data->clkreq_gpio)) {
        r = gpio_request(platform_data->clkreq_gpio, "nfc_clkreq_gpio");
        if (r)
            goto err_ese_gpio;

        r = gpio_direction_input(platform_data->clkreq_gpio);
        if (r)
            goto err_clkreq_gpio;
    } else {
        goto err_ese_gpio;
    }

    nqx_dev->irq_gpio = platform_data->irq_gpio;
    nqx_dev->firm_gpio = platform_data->firm_gpio;
    nqx_dev->clkreq_gpio = platform_data->clkreq_gpio;
    nqx_dev->pdata = platform_data;

    nqx_dev->nqx_info.info.chip_type = NFCC_NQ_330;
    nqx_dev->nqx_info.info.rom_version = 0x01;
    nqx_dev->nqx_info.info.fw_major = 0x01;
    nqx_dev->nqx_info.info.fw_minor = 0x00;

    init_waitqueue_head(&nqx_dev->read_wq);
    mutex_init(&nqx_dev->read_mutex);
    mutex_init(&nqx_dev->dev_ref_mutex);
    spin_lock_init(&nqx_dev->irq_enabled_lock);

    r = alloc_chrdev_region(&nqx_dev->devno, 0, DEV_COUNT, DEVICE_NAME);
    if (r < 0)
        goto err_char_dev_register;

    nqx_dev->nqx_class = class_create(THIS_MODULE, CLASS_NAME);
    if (IS_ERR(nqx_dev->nqx_class))
        goto err_class_create;

    cdev_init(&nqx_dev->c_dev, &nfc_dev_fops);
    r = cdev_add(&nqx_dev->c_dev, nqx_dev->devno, DEV_COUNT);
    if (r < 0)
        goto err_cdev_add;

    nqx_dev->nqx_device = device_create(nqx_dev->nqx_class, NULL,
                                        nqx_dev->devno, nqx_dev, DEVICE_NAME);
    if (IS_ERR(nqx_dev->nqx_device))
        goto err_device_create;

    nqx_dev->irq_enabled = true;
    r = request_irq(client->irq, nqx_dev_irq_handler,
                    IRQF_TRIGGER_HIGH, client->name, nqx_dev);
    if (r)
        goto err_request_irq_failed;

    nqx_disable_irq(nqx_dev);
    has_nfc = true;

    has_nfc_proc = proc_create("NFC_CHECK", 0444, NULL, &proc_has_nfc_fops);

    r = register_reboot_notifier(&nfcc_notifier);
    if (r)
        goto err_request_hw_check_failed;

    device_init_wakeup(&client->dev, true);
    device_set_wakeup_capable(&client->dev, true);
    i2c_set_clientdata(client, nqx_dev);
    nqx_dev->irq_wake_up = false;

    dev_info(&client->dev, "NQ NFC probed successfully\n");
    return 0;

err_request_hw_check_failed:
    free_irq(client->irq, nqx_dev);
err_request_irq_failed:
    device_destroy(nqx_dev->nqx_class, nqx_dev->devno);
err_device_create:
    cdev_del(&nqx_dev->c_dev);
err_cdev_add:
    class_destroy(nqx_dev->nqx_class);
err_class_create:
    unregister_chrdev_region(nqx_dev->devno, DEV_COUNT);
err_char_dev_register:
    mutex_destroy(&nqx_dev->read_mutex);
    mutex_destroy(&nqx_dev->dev_ref_mutex);
err_clkreq_gpio:
    gpio_free(platform_data->clkreq_gpio);
err_ese_gpio:
    if (nqx_dev->ese_gpio > 0)
        gpio_free(platform_data->ese_gpio);
err_firm_gpio:
    if (gpio_is_valid(platform_data->firm_gpio))
        gpio_free(platform_data->firm_gpio);
err_irq_gpio:
    gpio_free(platform_data->irq_gpio);
err_mem:
    kfree(nqx_dev->kbuf);
err_free_dev:
    kfree(nqx_dev);
err_en_gpio:
    gpio_free(platform_data->en_gpio);
err_free_data:
    if (client->dev.of_node)
        devm_kfree(&client->dev, platform_data);
    return r;
}

static int nqx_remove(struct i2c_client *client)
{
    struct nqx_dev *nqx_dev;

    nqx_dev = i2c_get_clientdata(client);
    if (!nqx_dev)
        return 0;

    if (has_nfc_proc)
        remove_proc_entry("NFC_CHECK", NULL);

    unregister_reboot_notifier(&nfcc_notifier);
    free_irq(client->irq, nqx_dev);
    cdev_del(&nqx_dev->c_dev);
    device_destroy(nqx_dev->nqx_class, nqx_dev->devno);
    class_destroy(nqx_dev->nqx_class);
    unregister_chrdev_region(nqx_dev->devno, DEV_COUNT);
    mutex_destroy(&nqx_dev->read_mutex);
    mutex_destroy(&nqx_dev->dev_ref_mutex);
    gpio_free(nqx_dev->clkreq_gpio);
    if (nqx_dev->ese_gpio > 0)
        gpio_free(nqx_dev->ese_gpio);
    if (gpio_is_valid(nqx_dev->firm_gpio))
        gpio_free(nqx_dev->firm_gpio);
    gpio_free(nqx_dev->irq_gpio);
    gpio_free(nqx_dev->en_gpio);
    kfree(nqx_dev->kbuf);
    if (client->dev.of_node)
        devm_kfree(&client->dev, nqx_dev->pdata);
    kfree(nqx_dev);

    return 0;
}

static int nqx_suspend(struct device *device)
{
    struct i2c_client *client = to_i2c_client(device);
    struct nqx_dev *nqx_dev = i2c_get_clientdata(client);

    if (!nqx_dev)
        return 0;

    if (device_may_wakeup(&client->dev) && nqx_dev->irq_enabled) {
        if (!enable_irq_wake(client->irq))
            nqx_dev->irq_wake_up = true;
    }
    return 0;
}

static int nqx_resume(struct device *device)
{
    struct i2c_client *client = to_i2c_client(device);
    struct nqx_dev *nqx_dev = i2c_get_clientdata(client);

    if (!nqx_dev)
        return 0;

    if (device_may_wakeup(&client->dev) && nqx_dev->irq_wake_up) {
        if (!disable_irq_wake(client->irq))
            nqx_dev->irq_wake_up = false;
    }
    return 0;
}

static const struct i2c_device_id nqx_id[] = {
    {"nqx-i2c", 0},
    {}
};

static const struct dev_pm_ops nfc_pm_ops = {
    SET_SYSTEM_SLEEP_PM_OPS(nqx_suspend, nqx_resume)
};

static struct i2c_driver nqx = {
    .id_table   = nqx_id,
    .probe      = nqx_probe,
    .remove     = nqx_remove,
    .driver     = {
        .owner          = THIS_MODULE,
        .name           = "nq-nci",
        .of_match_table = msm_match_table,
        .probe_type     = PROBE_PREFER_ASYNCHRONOUS,
        .pm             = &nfc_pm_ops,
    },
};

static int nfcc_reboot(struct notifier_block *notifier, unsigned long val,
                       void *v)
{
    gpio_set_value(disable_ctrl, 1);
    return NOTIFY_OK;
}

static int __init nqx_dev_init(void)
{
    return i2c_add_driver(&nqx);
}
module_init(nqx_dev_init);

static void __exit nqx_dev_exit(void)
{
    unregister_reboot_notifier(&nfcc_notifier);
    i2c_del_driver(&nqx);
}
module_exit(nqx_dev_exit);

MODULE_DESCRIPTION("NXP NQ NFC driver");
MODULE_LICENSE("GPL v2");
