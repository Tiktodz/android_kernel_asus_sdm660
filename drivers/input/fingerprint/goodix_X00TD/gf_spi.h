/*
 * Optimized driver for Goodix fingerprint sensor
 * Copyright (C) 2016 Goodix
 * Optimized for ASUS X00TD kernel 4.19
 */
#ifndef __GF_SPI_H
#define __GF_SPI_H

#include <linux/types.h>
#include <linux/notifier.h>
#include <linux/spinlock.h>

/* Mode definitions */
enum FP_MODE {
    GF_IMAGE_MODE = 0,
    GF_KEY_MODE,
    GF_SLEEP_MODE,
    GF_FF_MODE,
    GF_DEBUG_MODE = 0x56
};

/* Key input mappings */
#define GF_KEY_INPUT_HOME   KEY_HOME
#define GF_KEY_INPUT_MENU   KEY_MENU
#define GF_KEY_INPUT_BACK   KEY_BACK
#define GF_KEY_INPUT_POWER  KEY_POWER
#define GF_KEY_INPUT_CAMERA KEY_CAMERA

typedef enum gf_key_event {
    GF_KEY_NONE = 0,
    GF_KEY_HOME,
    GF_KEY_POWER,
    GF_KEY_MENU,
    GF_KEY_BACK,
    GF_KEY_CAMERA,
} gf_key_event_t;

struct gf_key {
    enum gf_key_event key;
    uint32_t value;
};

struct gf_key_map {
    unsigned int type;
    unsigned int code;
};

struct gf_ioc_chip_info {
    unsigned char vendor_id;
    unsigned char mode;
    unsigned char operation;
    unsigned char reserved[5];
};

/* IOCTL definitions */
#define GF_IOC_MAGIC    'g'
#define GF_IOC_INIT             _IOR(GF_IOC_MAGIC, 0, uint8_t)
#define GF_IOC_EXIT             _IO(GF_IOC_MAGIC, 1)
#define GF_IOC_RESET            _IO(GF_IOC_MAGIC, 2)
#define GF_IOC_ENABLE_IRQ       _IO(GF_IOC_MAGIC, 3)
#define GF_IOC_DISABLE_IRQ      _IO(GF_IOC_MAGIC, 4)
#define GF_IOC_ENABLE_SPI_CLK   _IOW(GF_IOC_MAGIC, 5, uint32_t)
#define GF_IOC_DISABLE_SPI_CLK  _IO(GF_IOC_MAGIC, 6)
#define GF_IOC_ENABLE_POWER     _IO(GF_IOC_MAGIC, 7)
#define GF_IOC_DISABLE_POWER    _IO(GF_IOC_MAGIC, 8)
#define GF_IOC_INPUT_KEY_EVENT  _IOW(GF_IOC_MAGIC, 9, struct gf_key)
#define GF_IOC_ENTER_SLEEP_MODE _IO(GF_IOC_MAGIC, 10)
#define GF_IOC_GET_FW_INFO      _IOR(GF_IOC_MAGIC, 11, uint8_t)
#define GF_IOC_REMOVE           _IO(GF_IOC_MAGIC, 12)
#define GF_IOC_CHIP_INFO        _IOW(GF_IOC_MAGIC, 13, struct gf_ioc_chip_info)

/* Configuration */
#define USE_PLATFORM_BUS    1
#define GF_NETLINK_ENABLE   1
#define GF_NET_EVENT_IRQ        1
#define GF_NET_EVENT_FB_BLACK   2
#define GF_NET_EVENT_FB_UNBLACK 3
#define NETLINK_TEST            25

/* Timing constants */
#define WAKELOCK_HOLD_TIME      400  /* ms */
#define RESET_DELAY_US          2500 /* us */
#define POWER_ON_DELAY_US       8000 /* us */

struct gf_dev {
    dev_t devt;
    struct list_head device_entry;
    struct platform_device *spi;
    struct input_dev *input;

    /* GPIO */
    signed irq_gpio;
    signed reset_gpio;
    signed vdd_gpio;
    int irq;

    /* State tracking with spinlock for IRQ-safe access */
    spinlock_t irq_lock;
    unsigned users;
    bool irq_enabled;
    bool device_available;
    bool fb_black;
    bool irq_requested;

    struct notifier_block notifier;
};

/* Function prototypes */
int gf_parse_dts(struct gf_dev *gf_dev);
void gf_cleanup(struct gf_dev *gf_dev);
int gf_power_on(struct gf_dev *gf_dev);
int gf_power_off(struct gf_dev *gf_dev);
int gf_hw_reset(struct gf_dev *gf_dev, unsigned int delay_ms);
int gf_irq_num(struct gf_dev *gf_dev);
void sendnlmsg(char *message);
int netlink_init(void);
void netlink_exit(void);

#endif /* __GF_SPI_H */
