/* Copyright (c) 2015-2019, The Linux Foundation. All rights reserved.
 * Copyright (c) 2023-2024, NXP Semiconductors. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 and
 * only version 2 as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

#ifndef __NQ_NCI_H
#define __NQ_NCI_H

#include <linux/i2c.h>
#include <linux/types.h>
#include <linux/version.h>
#include <linux/semaphore.h>
#include <linux/completion.h>
#include <linux/ioctl.h>
#include <linux/cdev.h>

/* IOCTL commands for NXP NFC HAL (Android 12+) */
#define NFC_MAGIC			0xE9

#define NFC_SET_PWR			_IOW(NFC_MAGIC, 0x01, unsigned int)
#define ESE_SET_PWR			_IOW(NFC_MAGIC, 0x02, unsigned int)
#define ESE_GET_PWR			_IOR(NFC_MAGIC, 0x03, unsigned int)
#define SET_RX_BLOCK			_IOW(NFC_MAGIC, 0x04, unsigned int)
#define SET_EMULATOR_TEST_POINT		_IOW(NFC_MAGIC, 0x05, unsigned int)
#define NFCC_INITIAL_CORE_RESET_NTF	_IOW(NFC_MAGIC, 0x10, unsigned int)
#define NFCC_GET_INFO			_IOW(NFC_MAGIC, 0x11, unsigned int)

/* NFC HAL Power states */
#define NFC_POWER_OFF			0
#define NFC_POWER_ON			1
#define NFC_FW_DWL_VEN_TOGGLE		2
#define NFC_FW_DWL_HIGH			3
#define NFC_FW_DWL_LOW			4
#define NFC_ENABLE			5
#define NFC_DISABLE			6

/* eSE Power states */
#define ESE_POWER_ON			0
#define ESE_POWER_OFF			1
#define ESE_POWER_STATE			3

/* NCI protocol constants */
#define NFC_RX_BUFFER_CNT_START		(0x0)
#define PAYLOAD_HEADER_LENGTH		(0x3)
#define PAYLOAD_LENGTH_MAX		(256)
#define BYTE				(0x8)
#define NCI_IDENTIFIER			(0x10)

/* NCI command/response lengths */
#define NCI_RESET_CMD_LEN		4
#define NCI_RESET_RSP_LEN		4
#define NCI_RESET_NTF_LEN		13
#define NCI_INIT_CMD_LEN		3
#define NCI_INIT_RSP_LEN		28
#define NCI_GET_VERSION_CMD_LEN		8
#define NCI_GET_VERSION_RSP_LEN		12

enum nfcc_initial_core_reset_ntf {
	TIMEDOUT_INITIAL_CORE_RESET_NTF = 0,
	ARRIVED_INITIAL_CORE_RESET_NTF,
	DEFAULT_INITIAL_CORE_RESET_NTF,
};

enum nfcc_chip_variant {
	NFCC_NQ_210			= 0x48,
	NFCC_NQ_220			= 0x58,
	NFCC_NQ_310			= 0x40,
	NFCC_NQ_330			= 0x51,
	NFCC_PN553			= 0x41,
	NFCC_PN557			= 0x42,
	NFCC_PN66T			= 0x18,
	NFCC_SN100_A			= 0xa3,
	NFCC_SN100_B			= 0xa4,
	NFCC_SN110_A			= 0xa5,
	NFCC_SN110_B			= 0xa6,
	NFCC_SN220_A			= 0xa7,
	NFCC_SN220_B			= 0xa8,
	NFCC_NOT_SUPPORTED		= 0xFF
};

/* NFC chip info structure for HAL communication */
struct nfc_dev_info {
	__u8 chip_type;
	__u8 rom_version;
	__u8 fw_major;
	__u8 fw_minor;
};

union nqx_uinfo {
	__u32 i;
	struct nfc_dev_info info;
};

#endif /* __NQ_NCI_H */
