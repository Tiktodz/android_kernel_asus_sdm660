/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (C) 2010 - 2018 Novatek, Inc.
 *
 * $Revision: 47247 $
 * $Date: 2019-07-10 10:41:36 +0800 (Wed, 10 Jul 2019) $
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 */
#ifndef 	_LINUX_NVT_TOUCH_H
#define		_LINUX_NVT_TOUCH_H

#include <linux/delay.h>
#include <linux/i2c.h>
#include <linux/input.h>
#include <linux/uaccess.h>
#include <linux/regulator/consumer.h>

#ifdef CONFIG_HAS_EARLYSUSPEND
#include <linux/earlysuspend.h>
#endif

#if defined(CONFIG_TOUCHSCREEN_NT36xxx) || defined(CONFIG_TOUCHSCREEN_NT36xxx_X00TD)
#include <linux/nvtouch.h>
#endif

#include "nt36xxx_mem_map.h"

#define SNVT_DEBUG 0

//---GPIO number---
#define SNVTTOUCH_RST_PIN 980
#define SNVTTOUCH_INT_PIN 943

#define SNVT_POWER_SOURCE_CUST_EN  1
//VSN,VSP
#if SNVT_POWER_SOURCE_CUST_EN
#define SLCM_LAB_MIN_UV                      6000000
#define SLCM_LAB_MAX_UV                      6000000
#define SLCM_IBB_MIN_UV                      6000000
#define SLCM_IBB_MAX_UV                      6000000
#endif

//---INT trigger mode---
//#define IRQ_TYPE_EDGE_RISING 1
//#define IRQ_TYPE_EDGE_FALLING 2
#define SINT_TRIGGER_TYPE IRQ_TYPE_EDGE_RISING


//---I2C driver info.---
#define SNVT_I2C_NAME "NVT-ts"
#define SNVT_DRIVER_TYPE "NTC-NVT-ts"
#define SI2C_BLDR_Address 0x01
#define SI2C_FW_Address 0x01
#define SI2C_HW_Address 0x62

#if SNVT_DEBUG
#define SNVT_LOG(fmt, args...)    pr_err("[%s] %s %d: " fmt, SNVT_DRIVER_TYPE, __func__, __LINE__, ##args)
#else
#define SNVT_LOG(fmt, args...)    pr_info("[%s] %s %d: " fmt, SNVT_DRIVER_TYPE, __func__, __LINE__, ##args)
#endif
#define SNVT_ERR(fmt, args...)    pr_err("[%s] %s %d: " fmt, SNVT_DRIVER_TYPE, __func__, __LINE__, ##args)

//---Input device info.---
#define SNVT_TS_NAME "NVTCapacitiveTouchScreen"


//---Touch info.---
#define STOUCH_DEFAULT_MAX_WIDTH 1080
#define STOUCH_DEFAULT_MAX_HEIGHT 1920
#define STOUCH_MAX_FINGER_NUM 10
#define STOUCH_KEY_NUM 0
#if STOUCH_KEY_NUM > 0
extern const uint16_t touch_key_array[STOUCH_KEY_NUM];
#endif
#define STOUCH_FORCE_NUM 1000

/* Enable only when module have tp reset pin and connected to host */
#define SNVT_TOUCH_SUPPORT_HW_RST 0

//---Customerized func.---
#define SNVT_TOUCH_PROC 1
#define SNVT_TOUCH_EXT_PROC 1
#define SNVT_TOUCH_MP 0
#define SMT_PROTOCOL_B 1
#define SWAKEUP_GESTURE 1
#if SWAKEUP_GESTURE
extern const uint16_t sgesture_key_array[];
#endif
#define SBOOT_UPDATE_FIRMWARE 0
#define SBOOT_UPDATE_FIRMWARE_NAME "novatek_ts_fw.bin"

//---ESD Protect.---
#define SNVT_TOUCH_ESD_PROTECT 0
#define SNVT_TOUCH_ESD_CHECK_PERIOD 1500	/* ms */

struct snvt_ts_data {
	struct i2c_client *client;
	struct input_dev *input_dev;
	struct delayed_work nvt_fwu_work;
	uint16_t addr;
	int8_t phys[32];
#if defined(CONFIG_FB)
#ifdef _MSM_DRM_NOTIFY_H_
	struct notifier_block drm_notif;
#else
	struct notifier_block fb_notif;
#endif
#elif defined(CONFIG_HAS_EARLYSUSPEND)
	struct early_suspend early_suspend;
#endif
	uint8_t fw_ver;
	uint8_t x_num;
	uint8_t y_num;
	uint16_t abs_x_max;
	uint16_t abs_y_max;
	uint8_t max_touch_num;
	uint8_t max_button_num;
	uint32_t SINT_TRIGGER_TYPE;
	int32_t irq_gpio;
	uint32_t irq_flags;
	int32_t reset_gpio;
	uint32_t reset_flags;
	struct mutex lock;
	const struct snvt_ts_mem_map *mmap;
	uint8_t carrier_system;
	uint16_t snvt_pid;
	uint8_t xbuf[1025];
	struct mutex xbuf_lock;
	bool irq_enabled;
#if SNVT_POWER_SOURCE_CUST_EN
	struct regulator *lcm_lab;
	struct regulator *lcm_ibb;
	atomic_t lcm_lab_power;
	atomic_t lcm_ibb_power;
#endif
};

#if SNVT_TOUCH_PROC
struct snvt_flash_data{
	rwlock_t lock;
	struct i2c_client *client;
};
#endif

typedef enum {
	RESET_STATE_INIT = 0xA0,// IC reset
	RESET_STATE_REK,        // ReK baseline
	RESET_STATE_REK_FINISH, // baseline is ready
	RESET_STATE_NORMAL_RUN, // normal run
	RESET_STATE_MAX  = 0xAF
} RST_COMPLETE_STATE;

typedef enum {
    EVENT_MAP_HOST_CMD                      = 0x50,
    EVENT_MAP_HANDSHAKING_or_SUB_CMD_BYTE   = 0x51,
    EVENT_MAP_RESET_COMPLETE                = 0x60,
    EVENT_MAP_FWINFO                        = 0x78,
    EVENT_MAP_PROJECTID                     = 0x9A,
} I2C_EVENT_MAP;

//---extern structures---
extern struct snvt_ts_data *nts;

//---extern functions---
extern int32_t SCTP_I2C_READ(struct i2c_client *client, uint16_t address, uint8_t *buf, uint16_t len);
extern int32_t SCTP_I2C_WRITE(struct i2c_client *client, uint16_t address, uint8_t *buf, uint16_t len);
extern void snvt_bootloader_reset(void);
extern void snvt_sw_reset_idle(void);
extern int32_t snvt_check_fw_reset_state(RST_COMPLETE_STATE check_reset_state);
extern int32_t snvt_get_fw_info(void);
extern int32_t snvt_clear_fw_status(void);
extern int32_t snvt_check_fw_status(void);
extern int32_t snvt_set_page(uint16_t i2c_addr, uint32_t addr);
#if SNVT_TOUCH_ESD_PROTECT
extern void snvt_esd_check_enable(uint8_t enable);
#endif /* #if SNVT_TOUCH_ESD_PROTECT */
extern void snvt_stop_crc_reboot(void);

#endif /* _LINUX_NVT_TOUCH_H */
