// SPDX-License-Identifier: GPL-2.0-only
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
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/interrupt.h>
#include <linux/irq.h>
#include <linux/gpio.h>
#include <linux/proc_fs.h>
#include <linux/input/mt.h>
#include <linux/of_gpio.h>
#include <linux/of_irq.h>

#if defined(CONFIG_FB)
#ifdef CONFIG_DRM_MSM
#include <linux/msm_drm_notify.h>
#endif
#include <linux/notifier.h>
#include <linux/fb.h>
#elif defined(CONFIG_HAS_EARLYSUSPEND)
#include <linux/earlysuspend.h>
#endif

#include "nt36xxx.h"
#if SNVT_TOUCH_ESD_PROTECT
#include <linux/jiffies.h>
#endif /* #if SNVT_TOUCH_ESD_PROTECT */

#if SNVT_TOUCH_ESD_PROTECT
static struct delayed_work nvt_esd_check_work;
static struct workqueue_struct *nvt_esd_check_wq;
static unsigned long irq_timer = 0;
uint8_t esd_check = false;
uint8_t esd_retry = 0;
#endif /* #if SNVT_TOUCH_ESD_PROTECT */

#if SNVT_TOUCH_EXT_PROC
extern int32_t snvt_extra_proc_init(void);
extern void snvt_extra_proc_deinit(void);
#endif

#if SNVT_POWER_SOURCE_CUST_EN
static int nvt_lcm_bias_power_init(struct snvt_ts_data *data)
{
	int ret;
	data->lcm_lab = regulator_get(&data->client->dev, "lcm_lab");
	if (IS_ERR(data->lcm_lab)){
		ret = PTR_ERR(data->lcm_lab);
		SNVT_ERR("Regulator get failed lcm_lab ret=%d", ret);
		goto _end;
	}
	if (regulator_count_voltages(data->lcm_lab)>0){
		ret = regulator_set_voltage(data->lcm_lab, SLCM_LAB_MIN_UV, SLCM_LAB_MAX_UV);
		if (ret){
			SNVT_ERR("Regulator set_vtg failed lcm_lab ret=%d", ret);
			goto reg_lcm_lab_put;
		}
	}
	data->lcm_ibb = regulator_get(&data->client->dev, "lcm_ibb");
	if (IS_ERR(data->lcm_ibb)){
		ret = PTR_ERR(data->lcm_ibb);
		SNVT_ERR("Regulator get failed lcm_ibb ret=%d", ret);
		goto reg_set_lcm_lab_vtg;
	}
	if (regulator_count_voltages(data->lcm_ibb)>0){
		ret = regulator_set_voltage(data->lcm_ibb, SLCM_IBB_MIN_UV, SLCM_IBB_MAX_UV);
		if (ret){
			SNVT_ERR("Regulator set_vtg failed lcm_lab ret=%d", ret);
			goto reg_lcm_ibb_put;
		}
	}
	return 0;
reg_lcm_ibb_put:
	regulator_put(data->lcm_ibb);
	data->lcm_ibb = NULL;
reg_set_lcm_lab_vtg:
	if (regulator_count_voltages(data->lcm_lab) > 0){
		regulator_set_voltage(data->lcm_lab, 0, SLCM_LAB_MAX_UV);
	}
reg_lcm_lab_put:
	regulator_put(data->lcm_lab);
	data->lcm_lab = NULL;
_end:
	return ret;
}

static int nvt_lcm_bias_power_deinit(struct snvt_ts_data *data)
{
	if (data-> lcm_ibb != NULL){
		if (regulator_count_voltages(data->lcm_ibb) > 0){
			regulator_set_voltage(data->lcm_ibb, 0, SLCM_LAB_MAX_UV);
		}
		regulator_put(data->lcm_ibb);
	}
	if (data-> lcm_lab != NULL){
		if (regulator_count_voltages(data->lcm_lab) > 0){
			regulator_set_voltage(data->lcm_lab, 0, SLCM_LAB_MAX_UV);
		}
		regulator_put(data->lcm_lab);
	}
	return 0;
}


static int nvt_lcm_power_source_ctrl(struct snvt_ts_data *data, int enable)
{
	int rc;

	if (data->lcm_lab!= NULL && data->lcm_ibb!= NULL){
		if (enable){
			if (atomic_inc_return(&(data->lcm_lab_power)) == 1) {
				rc = regulator_enable(data->lcm_lab);
				if (rc) {
					atomic_dec(&(data->lcm_lab_power));
					SNVT_ERR("Regulator lcm_lab enable failed rc=%d", rc);
				}
			}
			else {
				atomic_dec(&(data->lcm_lab_power));
			}
			if (atomic_inc_return(&(data->lcm_ibb_power)) == 1) {
				rc = regulator_enable(data->lcm_ibb);
				if (rc) {
					atomic_dec(&(data->lcm_ibb_power));
					SNVT_ERR("Regulator lcm_ibb enable failed rc=%d", rc);
				}
			}
			else {
				atomic_dec(&(data->lcm_ibb_power));
			}
		}
		else {
			if (atomic_dec_return(&(data->lcm_lab_power)) == 0) {
				rc = regulator_disable(data->lcm_lab);
				if (rc)
				{
					atomic_inc(&(data->lcm_lab_power));
					SNVT_ERR("Regulator lcm_lab disable failed rc=%d", rc);
				}
			}
			else{
				atomic_inc(&(data->lcm_lab_power));
			}
			if (atomic_dec_return(&(data->lcm_ibb_power)) == 0) {
				rc = regulator_disable(data->lcm_ibb);
				if (rc)	{
					atomic_inc(&(data->lcm_ibb_power));
					SNVT_ERR("Regulator lcm_ibb disable failed rc=%d", rc);
				}
			}
			else{
				atomic_inc(&(data->lcm_ibb_power));
			}
		}
	}
	else
		SNVT_ERR("Regulator lcm_ibb or lcm_lab is invalid");
	return 0;
}
#endif

#if SNVT_TOUCH_MP
extern int32_t nvt_mp_proc_init(void);
extern void nvt_mp_proc_deinit(void);
#endif

struct snvt_ts_data *nts;

#if SBOOT_UPDATE_FIRMWARE
static struct workqueue_struct *nvt_fwu_wq;
extern void SBOOT_UPDATE_FIRMWARE(struct work_struct *work);
#endif

#if defined(CONFIG_FB)
#ifdef _MSM_DRM_NOTIFY_H_
static int nvt_drm_notifier_callback(struct notifier_block *self, unsigned long event, void *data);
#else
static int nvt_fb_notifier_callback(struct notifier_block *self, unsigned long event, void *data);
#endif
#elif defined(CONFIG_HAS_EARLYSUSPEND)
static void nvt_ts_early_suspend(struct early_suspend *h);
static void nvt_ts_late_resume(struct early_suspend *h);
#endif

#if STOUCH_KEY_NUM > 0
const uint16_t touch_key_array[STOUCH_KEY_NUM] = {
	KEY_BACK,
	KEY_HOME,
	KEY_MENU
};
#endif

static uint8_t bTouchIsAwake = 0;

#if SWAKEUP_GESTURE
#define GESTURE_EVENT_C 		KEY_TP_GESTURE_C
#define GESTURE_EVENT_E 		KEY_TP_GESTURE_E
#define GESTURE_EVENT_M			KEY_TP_GESTURE_M
#define GESTURE_EVENT_O			KEY_TP_GESTURE_O
#define GESTURE_EVENT_S 		KEY_TP_GESTURE_S
#define GESTURE_EVENT_V 		KEY_TP_GESTURE_V
#define GESTURE_EVENT_W 		KEY_TP_GESTURE_W
#define GESTURE_EVENT_Z 		KEY_TP_GESTURE_Z
#define GESTURE_EVENT_SWIPE_UP		KEY_TP_GESTURE_SWIPE_UP
#define GESTURE_EVENT_SWIPE_DOWN	KEY_TP_GESTURE_SWIPE_DOWN
#define GESTURE_EVENT_SWIPE_LEFT	KEY_TP_GESTURE_SWIPE_LEFT
#define GESTURE_EVENT_SWIPE_RIGHT	KEY_TP_GESTURE_SWIPE_RIGHT
#define GESTURE_EVENT_DOUBLE_CLICK	KEY_WAKEUP

const uint16_t sgesture_key_array[] = {
	GESTURE_EVENT_C,  //GESTURE_WORD_C
	GESTURE_EVENT_W,  //GESTURE_WORD_W
	GESTURE_EVENT_V,  //GESTURE_WORD_V
	GESTURE_EVENT_DOUBLE_CLICK,//GESTURE_DOUBLE_CLICK
	GESTURE_EVENT_Z,  //GESTURE_WORD_Z
	GESTURE_EVENT_M,  //GESTURE_WORD_M
	GESTURE_EVENT_O,  //GESTURE_WORD_O
	GESTURE_EVENT_E,  //GESTURE_WORD_E
	GESTURE_EVENT_S,  //GESTURE_WORD_S
	GESTURE_EVENT_SWIPE_UP,  //GESTURE_SLIDE_UP
	GESTURE_EVENT_SWIPE_DOWN,  //GESTURE_SLIDE_DOWN
	GESTURE_EVENT_SWIPE_LEFT,  //GESTURE_SLIDE_LEFT
	GESTURE_EVENT_SWIPE_RIGHT,  //GESTURE_SLIDE_RIGHT
};

// Use for DT2W
static int allow_dclick = 1;
// Use for gesture actions
static int allow_gesture = 0;

#define DT2W_NODE dclicknode
#define GESTURE_NODE gesture_node

static struct kobject *tp_kobject;

// DT2W node
static ssize_t dclick_show(struct kobject *kobj, struct kobj_attribute *attr,
                      char *buf)
{
        return sprintf(buf, "%d\n", allow_dclick);
}

static ssize_t dclick_store(struct kobject *kobj, struct kobj_attribute *attr,
                      const char *buf, size_t count)
{
        sscanf(buf, "%du", &allow_dclick);
        return count;
}

static struct kobj_attribute dclick_attribute = __ATTR(DT2W_NODE, 0664, dclick_show,
                                                   dclick_store);

// gesture node
static ssize_t gesture_show(struct kobject *kobj, struct kobj_attribute *attr,
                      char *buf)
{
        return sprintf(buf, "%d\n", allow_gesture);
}

static ssize_t gesture_store(struct kobject *kobj, struct kobj_attribute *attr,
                      const char *buf, size_t count)
{
        sscanf(buf, "%du", &allow_gesture);
        return count;
}

static struct kobj_attribute gesture_attribute = __ATTR(GESTURE_NODE, 0664, gesture_show,
                                                   gesture_store);

// Create tp sysfs nodes
void screate_tp_nodes(void) {
	int create_dt2w_node = 0, create_gesture_node = 0;

        tp_kobject = kobject_create_and_add("touchpanel",
                                                 kernel_kobj);
        if(!tp_kobject)
        	SNVT_LOG("[NVT-ts] : Failed to create tp node \n");

        SNVT_LOG("[NVT-ts] : Gesture Node initialized successfully \n");

        create_dt2w_node = sysfs_create_file(tp_kobject, &dclick_attribute.attr);
        if (create_dt2w_node)
                SNVT_LOG("[NVT-ts] : failed to create the dclicknode file in /sys/kernel/touchpanel \n");

        create_gesture_node = sysfs_create_file(tp_kobject, &gesture_attribute.attr);
        if (create_gesture_node)
                SNVT_LOG("[NVT-ts] : failed to create the gesture_node file in /sys/kernel/touchpanel \n");
}

void sdestroy_gesture_control(void) {
	kobject_put(tp_kobject);
}
#endif

/*******************************************************
Description:
	Novatek touchscreen irq enable/disable function.

return:
	n.a.
*******************************************************/
static void nvt_irq_enable(bool enable)
{
	struct irq_desc *desc;

	if (enable) {
		if (!nts->irq_enabled) {
			enable_irq(nts->client->irq);
			enable_irq_wake(nts->client->irq);
			nts->irq_enabled = true;
		}
	} else {
		if (nts->irq_enabled) {
			disable_irq(nts->client->irq);
			disable_irq_wake(nts->client->irq);
			nts->irq_enabled = false;
		}
	}

	desc = irq_to_desc(nts->client->irq);
	SNVT_LOG("enable=%d, desc->depth=%d\n", enable, desc->depth);
}

/*******************************************************
Description:
	Novatek touchscreen i2c read function.

return:
	Executive outcomes. 2---succeed. -5---I/O error
*******************************************************/
int32_t SCTP_I2C_READ(struct i2c_client *client, uint16_t address, uint8_t *buf,
		uint16_t len)
{
	struct i2c_msg msgs[2];
	int32_t ret = -1;

	mutex_lock(&nts->xbuf_lock);

	msgs[0].flags = !I2C_M_RD;
	msgs[0].addr  = address;
	msgs[0].len   = 1;
	msgs[0].buf   = &buf[0];

	msgs[1].flags = I2C_M_RD;
	msgs[1].addr  = address;
	msgs[1].len   = len - 1;
	msgs[1].buf   = nts->xbuf;

	ret = i2c_transfer(client->adapter, msgs, 2);
	memcpy(buf + 1, nts->xbuf, len - 1);

	mutex_unlock(&nts->xbuf_lock);

	return ret;
}

/*******************************************************
Description:
	Novatek touchscreen i2c write function.

return:
	Executive outcomes. 1---succeed. -5---I/O error
*******************************************************/
int32_t SCTP_I2C_WRITE(struct i2c_client *client, uint16_t address, uint8_t *buf,
		uint16_t len)
{
	struct i2c_msg msg;
	int32_t ret = -1;

	mutex_lock(&nts->xbuf_lock);

	msg.flags = !I2C_M_RD;
	msg.addr  = address;
	msg.len   = len;
	memcpy(nts->xbuf, buf, len);
	msg.buf   = nts->xbuf;

	ret = i2c_transfer(client->adapter, &msg, 1);
	mutex_unlock(&nts->xbuf_lock);

	return ret;
}

/*******************************************************
Description:
	Novatek touchscreen set index/page/addr address.

return:
	Executive outcomes. 0---succeed. -5---access fail.
*******************************************************/
int32_t snvt_set_page(uint16_t i2c_addr, uint32_t addr)
{
	uint8_t buf[4] = {0};

	buf[0] = 0xFF;	//set index/page/addr command
	buf[1] = (addr >> 16) & 0xFF;
	buf[2] = (addr >> 8) & 0xFF;

	return SCTP_I2C_WRITE(nts->client, i2c_addr, buf, 3);
}

/*******************************************************
Description:
	Novatek touchscreen reset MCU then into idle mode
    function.

return:
	n.a.
*******************************************************/
void snvt_sw_reset_idle(void)
{
	uint8_t buf[4]={0};

	//---write i2c cmds to reset idle---
	buf[0]=0x00;
	buf[1]=0xA5;
	SCTP_I2C_WRITE(nts->client, SI2C_HW_Address, buf, 2);

	msleep(15);
}

/*******************************************************
Description:
	Novatek touchscreen reset MCU (boot) function.

return:
	n.a.
*******************************************************/
void snvt_bootloader_reset(void)
{
	uint8_t buf[8] = {0};

	SNVT_LOG("start\n");

	//---write i2c cmds to reset---
	buf[0] = 0x00;
	buf[1] = 0x69;
	SCTP_I2C_WRITE(nts->client, SI2C_HW_Address, buf, 2);

	// need 35ms delay after bootloader reset
	msleep(35);

	SNVT_LOG("end\n");
}

/*******************************************************
Description:
	Novatek touchscreen clear FW status function.

return:
	Executive outcomes. 0---succeed. -1---fail.
*******************************************************/
int32_t snvt_clear_fw_status(void)
{
	uint8_t buf[8] = {0};
	int32_t i = 0;
	const int32_t retry = 20;

	for (i = 0; i < retry; i++) {
		//---set xdata index to EVENT BUF ADDR---
		snvt_set_page(SI2C_FW_Address, nts->mmap->EVENT_BUF_ADDR | EVENT_MAP_HANDSHAKING_or_SUB_CMD_BYTE);

		//---clear fw status---
		buf[0] = EVENT_MAP_HANDSHAKING_or_SUB_CMD_BYTE;
		buf[1] = 0x00;
		SCTP_I2C_WRITE(nts->client, SI2C_FW_Address, buf, 2);

		//---read fw status---
		buf[0] = EVENT_MAP_HANDSHAKING_or_SUB_CMD_BYTE;
		buf[1] = 0xFF;
		SCTP_I2C_READ(nts->client, SI2C_FW_Address, buf, 2);

		if (buf[1] == 0x00)
			break;

		usleep_range(10000, 10000);
	}

	if (i >= retry) {
		SNVT_ERR("failed, i=%d, buf[1]=0x%02X\n", i, buf[1]);
		return -1;
	} else {
		return 0;
	}
}

/*******************************************************
Description:
	Novatek touchscreen check FW status function.

return:
	Executive outcomes. 0---succeed. -1---failed.
*******************************************************/
int32_t snvt_check_fw_status(void)
{
	uint8_t buf[8] = {0};
	int32_t i = 0;
	const int32_t retry = 50;

	for (i = 0; i < retry; i++) {
		//---set xdata index to EVENT BUF ADDR---
		snvt_set_page(SI2C_FW_Address, nts->mmap->EVENT_BUF_ADDR | EVENT_MAP_HANDSHAKING_or_SUB_CMD_BYTE);

		//---read fw status---
		buf[0] = EVENT_MAP_HANDSHAKING_or_SUB_CMD_BYTE;
		buf[1] = 0x00;
		SCTP_I2C_READ(nts->client, SI2C_FW_Address, buf, 2);

		if ((buf[1] & 0xF0) == 0xA0)
			break;

		usleep_range(10000, 10000);
	}

	if (i >= retry) {
		SNVT_ERR("failed, i=%d, buf[1]=0x%02X\n", i, buf[1]);
		return -1;
	} else {
		return 0;
	}
}

/*******************************************************
Description:
	Novatek touchscreen check FW reset state function.

return:
	Executive outcomes. 0---succeed. -1---failed.
*******************************************************/
int32_t snvt_check_fw_reset_state(RST_COMPLETE_STATE check_reset_state)
{
	uint8_t buf[8] = {0};
	int32_t ret = 0;
	int32_t retry = 0;

	while (1) {
		usleep_range(10000, 10000);

		//---read reset state---
		buf[0] = EVENT_MAP_RESET_COMPLETE;
		buf[1] = 0x00;
		SCTP_I2C_READ(nts->client, SI2C_FW_Address, buf, 6);

		if ((buf[1] >= check_reset_state) && (buf[1] <= RESET_STATE_MAX)) {
			ret = 0;
			break;
		}

		retry++;
		if(unlikely(retry > 100)) {
			SNVT_ERR("error, retry=%d, buf[1]=0x%02X, 0x%02X, 0x%02X, 0x%02X, 0x%02X\n",
				retry, buf[1], buf[2], buf[3], buf[4], buf[5]);
			ret = -1;
			break;
		}
	}

	return ret;
}

/*******************************************************
Description:
	Novatek touchscreen get novatek project id information
	function.

return:
	Executive outcomes. 0---success. -1---fail.
*******************************************************/
int32_t snvt_read_pid(void)
{
	uint8_t buf[3] = {0};

	//---set xdata index to EVENT BUF ADDR---
	snvt_set_page(SI2C_FW_Address, nts->mmap->EVENT_BUF_ADDR | EVENT_MAP_PROJECTID);

	//---read project id---
	buf[0] = EVENT_MAP_PROJECTID;
	buf[1] = 0x00;
	buf[2] = 0x00;
	SCTP_I2C_READ(nts->client, SI2C_FW_Address, buf, 3);

	nts->snvt_pid = (buf[2] << 8) + buf[1];

	SNVT_LOG("PID=%04X\n", nts->snvt_pid);

	return 0;
}

/*******************************************************
Description:
	Novatek touchscreen get firmware related information
	function.

return:
	Executive outcomes. 0---success. -1---fail.
*******************************************************/
int32_t snvt_get_fw_info(void)
{
	uint8_t buf[64] = {0};
	uint32_t retry_count = 0;
	int32_t ret = 0;

info_retry:
	//---set xdata index to EVENT BUF ADDR---
	snvt_set_page(SI2C_FW_Address, nts->mmap->EVENT_BUF_ADDR | EVENT_MAP_FWINFO);

	//---read fw info---
	buf[0] = EVENT_MAP_FWINFO;
	SCTP_I2C_READ(nts->client, SI2C_FW_Address, buf, 17);
	nts->fw_ver = buf[1];
	nts->x_num = buf[3];
	nts->y_num = buf[4];
	nts->abs_x_max = (uint16_t)((buf[5] << 8) | buf[6]);
	nts->abs_y_max = (uint16_t)((buf[7] << 8) | buf[8]);
	nts->max_button_num = buf[11];

	//---clear x_num, y_num if fw info is broken---
	if ((buf[1] + buf[2]) != 0xFF) {
		SNVT_ERR("FW info is broken! fw_ver=0x%02X, ~fw_ver=0x%02X\n", buf[1], buf[2]);
		nts->fw_ver = 0;
		nts->x_num = 18;
		nts->y_num = 32;
		nts->abs_x_max = STOUCH_DEFAULT_MAX_WIDTH;
		nts->abs_y_max = STOUCH_DEFAULT_MAX_HEIGHT;
		nts->max_button_num = STOUCH_KEY_NUM;

		if(retry_count < 3) {
			retry_count++;
			SNVT_ERR("retry_count=%d\n", retry_count);
			goto info_retry;
		} else {
			SNVT_ERR("Set default fw_ver=%d, x_num=%d, y_num=%d, "
					"abs_x_max=%d, abs_y_max=%d, max_button_num=%d!\n",
					nts->fw_ver, nts->x_num, nts->y_num,
					nts->abs_x_max, nts->abs_y_max, nts->max_button_num);
			ret = -1;
		}
	} else {
		ret = 0;
	}

	//---Get Novatek PID---
	snvt_read_pid();

	return ret;
}

/*******************************************************
  Create Device Node (Proc Entry)
*******************************************************/
#if SNVT_TOUCH_PROC
static struct proc_dir_entry *SNVT_proc_entry;
#define DEVICE_NAME	"NVTflash"

/*******************************************************
Description:
	Novatek touchscreen /proc/NVTflash read function.

return:
	Executive outcomes. 2---succeed. -5,-14---failed.
*******************************************************/
static ssize_t nvt_flash_read(struct file *file, char __user *buff, size_t count, loff_t *offp)
{
	uint8_t str[68] = {0};
	int32_t ret = -1;
	int32_t retries = 0;
	int8_t i2c_wr = 0;

	if (count > sizeof(str)) {
		SNVT_ERR("error count=%zu\n", count);
		return -EFAULT;
	}

	if (copy_from_user(str, buff, count)) {
		SNVT_ERR("copy from user error\n");
		return -EFAULT;
	}

#if SNVT_TOUCH_ESD_PROTECT
	/*
	 * stop esd check work to avoid case that 0x77 report righ after here to enable esd check again
	 * finally lead to trigger esd recovery bootloader reset
	 */
	cancel_delayed_work_sync(&nvt_esd_check_work);
	snvt_esd_check_enable(false);
#endif /* #if SNVT_TOUCH_ESD_PROTECT */

	i2c_wr = str[0] >> 7;

	if (i2c_wr == 0) {	//I2C write
		while (retries < 20) {
			ret = SCTP_I2C_WRITE(nts->client, (str[0] & 0x7F), &str[2], str[1]);
			if (ret == 1)
				break;
			else
				SNVT_ERR("error, retries=%d, ret=%d\n", retries, ret);

			retries++;
		}

		if (unlikely(retries == 20)) {
			SNVT_ERR("error, ret = %d\n", ret);
			return -EIO;
		}

		return ret;
	} else if (i2c_wr == 1) {	//I2C read
		while (retries < 20) {
			ret = SCTP_I2C_READ(nts->client, (str[0] & 0x7F), &str[2], str[1]);
			if (ret == 2)
				break;
			else
				SNVT_ERR("error, retries=%d, ret=%d\n", retries, ret);

			retries++;
		}

		// copy buff to user if i2c transfer
		if (retries < 20) {
			if (copy_to_user(buff, str, count))
				return -EFAULT;
		}

		if (unlikely(retries == 20)) {
			SNVT_ERR("error, ret = %d\n", ret);
			return -EIO;
		}

		return ret;
	} else {
		SNVT_ERR("Call error, str[0]=%d\n", str[0]);
		return -EFAULT;
	}
}

/*******************************************************
Description:
	Novatek touchscreen /proc/NVTflash open function.

return:
	Executive outcomes. 0---succeed. -12---failed.
*******************************************************/
static int32_t nvt_flash_open(struct inode *inode, struct file *file)
{
	struct snvt_flash_data *dev;

	dev = kmalloc(sizeof(struct snvt_flash_data), GFP_KERNEL);
	if (dev == NULL) {
		SNVT_ERR("Failed to allocate memory for nvt flash data\n");
		return -ENOMEM;
	}

	rwlock_init(&dev->lock);
	file->private_data = dev;

	return 0;
}

/*******************************************************
Description:
	Novatek touchscreen /proc/NVTflash close function.

return:
	Executive outcomes. 0---succeed.
*******************************************************/
static int32_t nvt_flash_close(struct inode *inode, struct file *file)
{
	struct snvt_flash_data *dev = file->private_data;

	kfree(dev);

	return 0;
}

static const struct file_operations nvt_flash_fops = {
	.open = nvt_flash_open,
	.release = nvt_flash_close,
	.read = nvt_flash_read,
};

/*******************************************************
Description:
	Novatek touchscreen /proc/NVTflash initial function.

return:
	Executive outcomes. 0---succeed. -12---failed.
*******************************************************/
static int32_t nvt_flash_proc_init(void)
{
	SNVT_proc_entry = proc_create(DEVICE_NAME, 0444, NULL,&nvt_flash_fops);
	if (SNVT_proc_entry == NULL) {
		SNVT_ERR("Failed!\n");
		return -ENOMEM;
	} else {
		SNVT_LOG("Succeeded!\n");
	}

	SNVT_LOG("==========================================================\n");
	SNVT_LOG("Create /proc/%s\n", DEVICE_NAME);
	SNVT_LOG("==========================================================\n");

	return 0;
}

/*******************************************************
Description:
	Novatek touchscreen /proc/NVTflash deinitial function.

return:
	n.a.
*******************************************************/
static void nvt_flash_proc_deinit(void)
{
	if (SNVT_proc_entry != NULL) {
		remove_proc_entry(DEVICE_NAME, NULL);
		SNVT_proc_entry = NULL;
		SNVT_LOG("Removed /proc/%s\n", DEVICE_NAME);
	}
}
#endif

#if SWAKEUP_GESTURE
#define GESTURE_WORD_C          12
#define GESTURE_WORD_W          13
#define GESTURE_WORD_V          14
#define GESTURE_DOUBLE_CLICK    15
#define GESTURE_WORD_Z          16
#define GESTURE_WORD_M          17
#define GESTURE_WORD_O          18
#define GESTURE_WORD_e          19
#define GESTURE_WORD_S          20
#define GESTURE_SLIDE_UP        21
#define GESTURE_SLIDE_DOWN      22
#define GESTURE_SLIDE_LEFT      23
#define GESTURE_SLIDE_RIGHT     24
/* customized gesture id */
#define DATA_PROTOCOL           31

/* function page definition */
#define FUNCPAGE_GESTURE         1

static struct wakeup_source *gesture_wakelock;

/*******************************************************
Description:
	Novatek touchscreen wake up gesture key report function.

return:
	n.a.
*******************************************************/
#ifdef CONFIG_MACH_ASUS_X00TD
void snvt_ts_wakeup_gesture_report(uint8_t gesture_id)
{
	uint32_t keycode = 0;
#else
void snvt_ts_wakeup_gesture_report(uint8_t gesture_id, uint8_t *data)
{
	uint32_t keycode = 0;
	uint8_t func_type = data[2];
	uint8_t func_id = data[3];

	/* support fw specifal data protocol */
	if ((gesture_id == DATA_PROTOCOL) && (func_type == FUNCPAGE_GESTURE)) {
		gesture_id = func_id;
	} else if (gesture_id > DATA_PROTOCOL) {
		SNVT_ERR("gesture_id %d is invalid, func_type=%d, func_id=%d\n", gesture_id, func_type, func_id);
		return;
	}
#endif
	
	SNVT_LOG("gesture_id = %d\n", gesture_id);

	if (allow_gesture) {
		switch (gesture_id) {
			case GESTURE_WORD_C:
				SNVT_LOG("Gesture : Word-C.\n");
				keycode = sgesture_key_array[0];
				break;
			case GESTURE_WORD_W:
				SNVT_LOG("Gesture : Word-W.\n");
				keycode = sgesture_key_array[1];
				break;
			case GESTURE_WORD_V:
				SNVT_LOG("Gesture : Word-V.\n");
				keycode = sgesture_key_array[2];
				break;
			case GESTURE_DOUBLE_CLICK:
				if (allow_dclick) {
					SNVT_LOG("Gesture : Double Click.\n");
					keycode = sgesture_key_array[3];
				}
				break;
			case GESTURE_WORD_Z:
				SNVT_LOG("Gesture : Word-Z.\n");
				keycode = sgesture_key_array[4];
				break;
			case GESTURE_WORD_M:
				SNVT_LOG("Gesture : Word-M.\n");
				keycode = sgesture_key_array[5];
				break;
			case GESTURE_WORD_O:
				SNVT_LOG("Gesture : Word-O.\n");
				keycode = sgesture_key_array[6];
				break;
			case GESTURE_WORD_e:
				SNVT_LOG("Gesture : Word-e.\n");
				keycode = sgesture_key_array[7];
				break;
			case GESTURE_WORD_S:
				SNVT_LOG("Gesture : Word-S.\n");
				keycode = sgesture_key_array[8];
				break;
			case GESTURE_SLIDE_UP:
				SNVT_LOG("Gesture : Slide UP.\n");
				keycode = sgesture_key_array[9];
				break;
			case GESTURE_SLIDE_DOWN:
				SNVT_LOG("Gesture : Slide DOWN.\n");
				keycode = sgesture_key_array[10];
				break;
			case GESTURE_SLIDE_LEFT:
				SNVT_LOG("Gesture : Slide LEFT.\n");
				keycode = sgesture_key_array[11];
				break;
			case GESTURE_SLIDE_RIGHT:
				SNVT_LOG("Gesture : Slide RIGHT.\n");
				keycode = sgesture_key_array[12];
				break;
			default:
				break;
		}
	} else if(allow_dclick && gesture_id == GESTURE_DOUBLE_CLICK) {
                  SNVT_LOG("Gesture : Double Click.\n");
                  keycode = sgesture_key_array[3];
	}

	if (keycode > 0) {
		input_report_key(nts->input_dev, keycode, 1);
		input_sync(nts->input_dev);
		input_report_key(nts->input_dev, keycode, 0);
		input_sync(nts->input_dev);
	}
}
#endif

/*******************************************************
Description:
	Novatek touchscreen parse device tree function.

return:
	n.a.
*******************************************************/
#ifdef CONFIG_OF
static void nvt_parse_dt(struct device *dev)
{
	struct device_node *np = dev->of_node;

#if SNVT_TOUCH_SUPPORT_HW_RST
	nts->reset_gpio = of_get_named_gpio_flags(np, "novatek,reset-gpio", 0, &nts->reset_flags);
	SNVT_LOG("novatek,reset-gpio=%d\n", nts->reset_gpio);
#endif
	nts->irq_gpio = of_get_named_gpio_flags(np, "novatek,irq-gpio", 0, &nts->irq_flags);
	SNVT_LOG("novatek,irq-gpio=%d\n", nts->irq_gpio);

}
#else
static void nvt_parse_dt(struct device *dev)
{
#if SNVT_TOUCH_SUPPORT_HW_RST
	nts->reset_gpio = SNVTTOUCH_RST_PIN;
#endif
	nts->irq_gpio = SNVTTOUCH_INT_PIN;
}
#endif

/*******************************************************
Description:
	Novatek touchscreen config and request gpio

return:
	Executive outcomes. 0---succeed. not 0---failed.
*******************************************************/
static int nvt_gpio_config(struct snvt_ts_data *nts)
{
	int32_t ret = 0;

#if SNVT_TOUCH_SUPPORT_HW_RST
	/* request RST-pin (Output/High) */
	if (gpio_is_valid(nts->reset_gpio)) {
		ret = gpio_request_one(nts->reset_gpio, GPIOF_OUT_INIT_HIGH, "NVT-tp-rst");
		if (ret) {
			SNVT_ERR("Failed to request NVT-tp-rst GPIO\n");
			goto err_request_reset_gpio;
		}
	}
#endif

	/* request INT-pin (Input) */
	if (gpio_is_valid(nts->irq_gpio)) {
		ret = gpio_request_one(nts->irq_gpio, GPIOF_IN, "NVT-int");
		if (ret) {
			SNVT_ERR("Failed to request NVT-int GPIO\n");
			goto err_request_irq_gpio;
		}
	}

	return ret;

err_request_irq_gpio:
#if SNVT_TOUCH_SUPPORT_HW_RST
	gpio_free(nts->reset_gpio);
err_request_reset_gpio:
#endif
	return ret;
}

/*******************************************************
Description:
	Novatek touchscreen deconfig gpio

return:
	n.a.
*******************************************************/
static void nvt_gpio_deconfig(struct snvt_ts_data *nts)
{
	if (gpio_is_valid(nts->irq_gpio))
		gpio_free(nts->irq_gpio);
#if SNVT_TOUCH_SUPPORT_HW_RST
	if (gpio_is_valid(nts->reset_gpio))
		gpio_free(nts->reset_gpio);
#endif
}

static uint8_t nvt_fw_recovery(uint8_t *point_data)
{
	uint8_t i = 0;
	uint8_t detected = true;

	/* check pattern */
	for (i=1 ; i<7 ; i++) {
		if (point_data[i] != 0x77) {
			detected = false;
			break;
		}
	}

	return detected;
}

#if SNVT_TOUCH_ESD_PROTECT
void snvt_esd_check_enable(uint8_t enable)
{
	/* update interrupt timer */
	irq_timer = jiffies;
	/* clear esd_retry counter, if protect function is enabled */
	esd_retry = enable ? 0 : esd_retry;
	/* enable/disable esd check flag */
	esd_check = enable;
}

static void nvt_esd_check_func(struct work_struct *work)
{
	unsigned int timer = jiffies_to_msecs(jiffies - irq_timer);

	//SNVT_ERR("esd_check = %d (retry %d)\n", esd_check, esd_retry);	//DEBUG

	if ((timer > SNVT_TOUCH_ESD_CHECK_PERIOD) && esd_check) {
		mutex_lock(&nts->lock);
		SNVT_ERR("do ESD recovery, timer = %d, retry = %d\n", timer, esd_retry);
		/* do esd recovery, bootloader reset */
		snvt_bootloader_reset();
		mutex_unlock(&nts->lock);
		/* update interrupt timer */
		irq_timer = jiffies;
		/* update esd_retry counter */
		esd_retry++;
	}

	queue_delayed_work(nvt_esd_check_wq, &nvt_esd_check_work,
			msecs_to_jiffies(SNVT_TOUCH_ESD_CHECK_PERIOD));
}
#endif /* #if SNVT_TOUCH_ESD_PROTECT */

#define POINT_DATA_LEN 65
/*******************************************************
Description:
	Novatek touchscreen work function.

return:
	n.a.
*******************************************************/
static irqreturn_t nvt_ts_work_func(int irq, void *data)
{
	int32_t ret = -1;
	uint8_t point_data[POINT_DATA_LEN + 1] = {0};
	uint32_t position = 0;
	uint32_t input_x = 0;
	uint32_t input_y = 0;
	uint32_t input_w = 0;
	uint32_t input_p = 0;
	uint8_t input_id = 0;
#if SMT_PROTOCOL_B
	uint8_t press_id[STOUCH_MAX_FINGER_NUM] = {0};
#endif /* SMT_PROTOCOL_B */
	int32_t i = 0;
	int32_t finger_cnt = 0;

#if SWAKEUP_GESTURE
	if (unlikely(bTouchIsAwake == 0)) {
		__pm_wakeup_event(gesture_wakelock, msecs_to_jiffies(5000));
	}
#endif

	mutex_lock(&nts->lock);

	ret = SCTP_I2C_READ(nts->client, SI2C_FW_Address, point_data, POINT_DATA_LEN + 1);
	if (unlikely(ret < 0)) {
		SNVT_ERR("SCTP_I2C_READ failed.(%d)\n", ret);
		goto XFER_ERROR;
	}
/*
	//--- dump I2C buf ---
	for (i = 0; i < 10; i++) {
		printk("%02X %02X %02X %02X %02X %02X  ",
			point_data[1+i*6], point_data[2+i*6], point_data[3+i*6], point_data[4+i*6], point_data[5+i*6], point_data[6+i*6]);
	}
	printk("\n");
*/

	if (nvt_fw_recovery(point_data)) {
#if SNVT_TOUCH_ESD_PROTECT
		snvt_esd_check_enable(true);
#endif /* #if SNVT_TOUCH_ESD_PROTECT */
		goto XFER_ERROR;
	}

#if SWAKEUP_GESTURE
	if (unlikely(bTouchIsAwake == 0)) {
		input_id = (uint8_t)(point_data[1] >> 3);
#ifdef CONFIG_MACH_ASUS_X00TD
		snvt_ts_wakeup_gesture_report(input_id);
#else
		snvt_ts_wakeup_gesture_report(input_id, point_data);
#endif
		nvt_irq_enable(true);
		mutex_unlock(&nts->lock);
		return IRQ_HANDLED;
	}
#endif

	finger_cnt = 0;

	for (i = 0; i < nts->max_touch_num; i++) {
		position = 1 + 6 * i;
		input_id = (uint8_t)(point_data[position + 0] >> 3);
		if ((input_id == 0) || (input_id > nts->max_touch_num))
			continue;

		if (((point_data[position] & 0x07) == 0x01) || ((point_data[position] & 0x07) == 0x02)) {	//finger down (enter & moving)
#if SNVT_TOUCH_ESD_PROTECT
			/* update interrupt timer */
			irq_timer = jiffies;
#endif /* #if SNVT_TOUCH_ESD_PROTECT */
			input_x = (uint32_t)(point_data[position + 1] << 4) + (uint32_t) (point_data[position + 3] >> 4);
			input_y = (uint32_t)(point_data[position + 2] << 4) + (uint32_t) (point_data[position + 3] & 0x0F);
			if ((input_x < 0) || (input_y < 0))
				continue;
			if ((input_x > nts->abs_x_max) || (input_y > nts->abs_y_max))
				continue;
			input_w = (uint32_t)(point_data[position + 4]);
			if (input_w == 0)
				input_w = 1;
			if (i < 2) {
				input_p = (uint32_t)(point_data[position + 5]) + (uint32_t)(point_data[i + 63] << 8);
				if (input_p > STOUCH_FORCE_NUM)
					input_p = STOUCH_FORCE_NUM;
			} else {
				input_p = (uint32_t)(point_data[position + 5]);
			}
			if (input_p == 0)
				input_p = 1;

#if SMT_PROTOCOL_B
			press_id[input_id - 1] = 1;
			input_mt_slot(nts->input_dev, input_id - 1);
			input_mt_report_slot_state(nts->input_dev, MT_TOOL_FINGER, true);
#else /* SMT_PROTOCOL_B */
			input_report_abs(nts->input_dev, ABS_MT_TRACKING_ID, input_id - 1);
			input_report_key(nts->input_dev, BTN_TOUCH, 1);
#endif /* SMT_PROTOCOL_B */

			input_report_abs(nts->input_dev, ABS_MT_POSITION_X, input_x);
			input_report_abs(nts->input_dev, ABS_MT_POSITION_Y, input_y);
			input_report_abs(nts->input_dev, ABS_MT_TOUCH_MAJOR, input_w);
			input_report_abs(nts->input_dev, ABS_MT_PRESSURE, input_p);

#if SMT_PROTOCOL_B
#else /* SMT_PROTOCOL_B */
			input_mt_sync(nts->input_dev);
#endif /* SMT_PROTOCOL_B */

			finger_cnt++;
		}
	}

#if SMT_PROTOCOL_B
	for (i = 0; i < nts->max_touch_num; i++) {
		if (press_id[i] != 1) {
			input_mt_slot(nts->input_dev, i);
			input_report_abs(nts->input_dev, ABS_MT_TOUCH_MAJOR, 0);
			input_report_abs(nts->input_dev, ABS_MT_PRESSURE, 0);
			input_mt_report_slot_state(nts->input_dev, MT_TOOL_FINGER, false);
		}
	}

	input_report_key(nts->input_dev, BTN_TOUCH, (finger_cnt > 0));
#else /* SMT_PROTOCOL_B */
	if (finger_cnt == 0) {
		input_report_key(nts->input_dev, BTN_TOUCH, 0);
		input_mt_sync(nts->input_dev);
	}
#endif /* SMT_PROTOCOL_B */

#if STOUCH_KEY_NUM > 0
	if (point_data[61] == 0xF8) {
#if SNVT_TOUCH_ESD_PROTECT
		/* update interrupt timer */
		irq_timer = jiffies;
#endif /* #if SNVT_TOUCH_ESD_PROTECT */
		for (i = 0; i < nts->max_button_num; i++) {
			input_report_key(nts->input_dev, touch_key_array[i], ((point_data[62] >> i) & 0x01));
		}
	} else {
		for (i = 0; i < nts->max_button_num; i++) {
			input_report_key(nts->input_dev, touch_key_array[i], 0);
		}
	}
#endif

	input_sync(nts->input_dev);

XFER_ERROR:

	mutex_unlock(&nts->lock);

	return IRQ_HANDLED;
}

/*******************************************************
Description:
	Novatek touchscreen check and stop crc reboot loop.

return:
	n.a.
*******************************************************/
void snvt_stop_crc_reboot(void)
{
	uint8_t buf[8] = {0};
	int32_t retry = 0;

	//read dummy buffer to check CRC fail reboot is happening or not

	//---change I2C index to prevent geting 0xFF, but not 0xFC---
	snvt_set_page(SI2C_BLDR_Address, 0x1F64E);

	//---read to check if buf is 0xFC which means IC is in CRC reboot ---
	buf[0] = 0x4E;
	SCTP_I2C_READ(nts->client, SI2C_BLDR_Address, buf, 4);

	if ((buf[1] == 0xFC) ||
		((buf[1] == 0xFF) && (buf[2] == 0xFF) && (buf[3] == 0xFF))) {

		//IC is in CRC fail reboot loop, needs to be stopped!
		for (retry = 5; retry > 0; retry--) {

			//---write i2c cmds to reset idle : 1st---
			buf[0]=0x00;
			buf[1]=0xA5;
			SCTP_I2C_WRITE(nts->client, SI2C_HW_Address, buf, 2);

			//---write i2c cmds to reset idle : 2rd---
			buf[0]=0x00;
			buf[1]=0xA5;
			SCTP_I2C_WRITE(nts->client, SI2C_HW_Address, buf, 2);
			msleep(1);

			//---clear CRC_ERR_FLAG---
			snvt_set_page(SI2C_BLDR_Address, 0x3F135);

			buf[0] = 0x35;
			buf[1] = 0xA5;
			SCTP_I2C_WRITE(nts->client, SI2C_BLDR_Address, buf, 2);

			//---check CRC_ERR_FLAG---
			snvt_set_page(SI2C_BLDR_Address, 0x3F135);

			buf[0] = 0x35;
			buf[1] = 0x00;
			SCTP_I2C_READ(nts->client, SI2C_BLDR_Address, buf, 2);

			if (buf[1] == 0xA5)
				break;
		}
		if (retry == 0)
			SNVT_ERR("CRC auto reboot is not able to be stopped! buf[1]=0x%02X\n", buf[1]);
	}

	return;
}

/*******************************************************
Description:
	Novatek touchscreen check chip version trim function.

return:
	Executive outcomes. 0---NVT IC. -1---not NVT IC.
*******************************************************/
static int8_t nvt_ts_check_chip_ver_trim(void)
{
	uint8_t buf[8] = {0};
	int32_t retry = 0;
	int32_t list = 0;
	int32_t i = 0;
	int32_t found_nvt_chip = 0;
	int32_t ret = -1;

	snvt_bootloader_reset(); // NOT in retry loop

	//---Check for 5 times---
	for (retry = 5; retry > 0; retry--) {
		snvt_sw_reset_idle();

		buf[0] = 0x00;
		buf[1] = 0x35;
		SCTP_I2C_WRITE(nts->client, SI2C_HW_Address, buf, 2);
		msleep(10);

		snvt_set_page(SI2C_BLDR_Address, 0x1F64E);

		buf[0] = 0x4E;
		buf[1] = 0x00;
		buf[2] = 0x00;
		buf[3] = 0x00;
		buf[4] = 0x00;
		buf[5] = 0x00;
		buf[6] = 0x00;
		SCTP_I2C_READ(nts->client, SI2C_BLDR_Address, buf, 7);
		SNVT_LOG("buf[1]=0x%02X, buf[2]=0x%02X, buf[3]=0x%02X, buf[4]=0x%02X, buf[5]=0x%02X, buf[6]=0x%02X\n",
			buf[1], buf[2], buf[3], buf[4], buf[5], buf[6]);

		//---Stop CRC check to prevent IC auto reboot---
		if ((buf[1] == 0xFC) ||
			((buf[1] == 0xFF) && (buf[2] == 0xFF) && (buf[3] == 0xFF))) {
			snvt_stop_crc_reboot();
			continue;
		}

		// compare read chip id on supported list
		for (list = 0; list < (sizeof(trim_id_table) / sizeof(struct nvt_ts_trim_id_table)); list++) {
			found_nvt_chip = 0;

			// compare each byte
			for (i = 0; i < NVT_ID_BYTE_MAX; i++) {
				if (trim_id_table[list].mask[i]) {
					if (buf[i + 1] != trim_id_table[list].id[i])
						break;
				}
			}

			if (i == NVT_ID_BYTE_MAX) {
				found_nvt_chip = 1;
			}

			if (found_nvt_chip) {
				SNVT_LOG("This is NVT touch IC\n");
				nts->mmap = trim_id_table[list].mmap;
				nts->carrier_system = trim_id_table[list].hwinfo->carrier_system;
				ret = 0;
				goto out;
			} else {
				nts->mmap = NULL;
				ret = -1;
			}
		}

		msleep(10);
	}

out:
	return ret;
}

/*******************************************************
Description:
	Novatek touchscreen driver probe function.

return:
	Executive outcomes. 0---succeed. negative---failed
*******************************************************/
static int32_t nvt_ts_probe(struct i2c_client *client, const struct i2c_device_id *id)
{
	int32_t ret = 0;
#if ((STOUCH_KEY_NUM > 0) || SWAKEUP_GESTURE)
	int32_t retry = 0;
#endif

	SNVT_LOG("start\n");

	nts = kmalloc(sizeof(struct snvt_ts_data), GFP_KERNEL);
	if (nts == NULL) {
		SNVT_ERR("failed to allocated memory for nvt nts data\n");
		return -ENOMEM;
	}

	nts->client = client;
	i2c_set_clientdata(client, nts);

	//---parse dts---
	nvt_parse_dt(&client->dev);

#if SNVT_POWER_SOURCE_CUST_EN
	atomic_set(&(nts->lcm_lab_power), 0);
	atomic_set(&(nts->lcm_ibb_power), 0);
	ret = nvt_lcm_bias_power_init(nts);

	if (ret) {
		SNVT_ERR("power resource init error!\n");
		goto err_power_resource_init_fail;
	}

	nvt_lcm_power_source_ctrl(nts, 1);
#endif

	//---request and config GPIOs---
	ret = nvt_gpio_config(nts);
	if (ret) {
		SNVT_ERR("gpio config error!\n");
		goto err_gpio_config_failed;
	}

	//---check i2c func.---
	if (!i2c_check_functionality(client->adapter, I2C_FUNC_I2C)) {
		SNVT_ERR("i2c_check_functionality failed. (no I2C_FUNC_I2C)\n");
		ret = -ENODEV;
		goto err_check_functionality_failed;
	}

	mutex_init(&nts->lock);
	mutex_init(&nts->xbuf_lock);

	// need 10ms delay after POR(power on reset)
	msleep(10);

	//---check chip version trim---
	ret = nvt_ts_check_chip_ver_trim();
	if (ret) {
		SNVT_ERR("chip is not identified\n");
		ret = -EINVAL;
		goto err_chipvertrim_failed;
	}

	snvt_bootloader_reset();
	snvt_check_fw_reset_state(RESET_STATE_INIT);
	snvt_get_fw_info();

	//---allocate input device---
	nts->input_dev = input_allocate_device();
	if (nts->input_dev == NULL) {
		SNVT_ERR("allocate input device failed\n");
		ret = -ENOMEM;
		goto err_input_dev_alloc_failed;
	}

	nts->max_touch_num = STOUCH_MAX_FINGER_NUM;

#if STOUCH_KEY_NUM > 0
	nts->max_button_num = STOUCH_KEY_NUM;
#endif

	nts->SINT_TRIGGER_TYPE = SINT_TRIGGER_TYPE;


	//---set input device info.---
	nts->input_dev->evbit[0] = BIT_MASK(EV_SYN) | BIT_MASK(EV_KEY) | BIT_MASK(EV_ABS) ;
	nts->input_dev->keybit[BIT_WORD(BTN_TOUCH)] = BIT_MASK(BTN_TOUCH);
	nts->input_dev->propbit[0] = BIT(INPUT_PROP_DIRECT);

#if SMT_PROTOCOL_B
	input_mt_init_slots(nts->input_dev, nts->max_touch_num, 0);
#endif

	input_set_abs_params(nts->input_dev, ABS_MT_PRESSURE, 0, STOUCH_FORCE_NUM, 0, 0);    //pressure = STOUCH_FORCE_NUM

#if STOUCH_MAX_FINGER_NUM > 1
	input_set_abs_params(nts->input_dev, ABS_MT_TOUCH_MAJOR, 0, 255, 0, 0);    //area = 255

	input_set_abs_params(nts->input_dev, ABS_MT_POSITION_X, 0, nts->abs_x_max, 0, 0);
	input_set_abs_params(nts->input_dev, ABS_MT_POSITION_Y, 0, nts->abs_y_max, 0, 0);
#if SMT_PROTOCOL_B
	// no need to set ABS_MT_TRACKING_ID, input_mt_init_slots() already set it
#else
	input_set_abs_params(nts->input_dev, ABS_MT_TRACKING_ID, 0, nts->max_touch_num, 0, 0);
#endif //SMT_PROTOCOL_B
#endif //STOUCH_MAX_FINGER_NUM > 1

#if STOUCH_KEY_NUM > 0
	for (retry = 0; retry < nts->max_button_num; retry++) {
		input_set_capability(nts->input_dev, EV_KEY, touch_key_array[retry]);
	}
#endif

#if SWAKEUP_GESTURE
	for (retry = 0; retry < ARRAY_SIZE(sgesture_key_array); retry++) {
		input_set_capability(nts->input_dev, EV_KEY, sgesture_key_array[retry]);
	}
	gesture_wakelock = wakeup_source_register(NULL, "poll-wake-lock");
	screate_tp_nodes();
#endif

	snprintf(nts->phys, sizeof(nts->phys), "input/nts");
	nts->input_dev->name = SNVT_TS_NAME;
	nts->input_dev->phys = nts->phys;
	nts->input_dev->id.bustype = BUS_I2C;

	//---register input device---
	ret = input_register_device(nts->input_dev);
	if (ret) {
		SNVT_ERR("register input device (%s) failed. ret=%d\n", nts->input_dev->name, ret);
		goto err_input_register_device_failed;
	}

	//---set int-pin & request irq---
	client->irq = gpio_to_irq(nts->irq_gpio);
	if (client->irq) {
		SNVT_LOG("SINT_TRIGGER_TYPE=%d\n", nts->SINT_TRIGGER_TYPE);
		nts->irq_enabled = true;
		ret = request_threaded_irq(client->irq, NULL, nvt_ts_work_func,
				nts->SINT_TRIGGER_TYPE | IRQF_ONESHOT, SNVT_I2C_NAME, nts);
		if (ret != 0) {
			SNVT_ERR("request irq failed. ret=%d\n", ret);
			goto err_int_request_failed;
		} else {
			nvt_irq_enable(false);
			SNVT_LOG("request irq %d succeed\n", client->irq);
		}
	}

#if SWAKEUP_GESTURE
	device_init_wakeup(&nts->input_dev->dev, 1);
#endif

#if SBOOT_UPDATE_FIRMWARE
	nvt_fwu_wq = alloc_workqueue("nvt_fwu_wq", WQ_UNBOUND | WQ_MEM_RECLAIM, 1);
	if (!nvt_fwu_wq) {
		SNVT_ERR("nvt_fwu_wq create workqueue failed\n");
		ret = -ENOMEM;
		goto err_create_nvt_fwu_wq_failed;
	}
	INIT_DELAYED_WORK(&nts->nvt_fwu_work, SBOOT_UPDATE_FIRMWARE);
	// please make sure boot update start after display reset(RESX) sequence
	queue_delayed_work(nvt_fwu_wq, &nts->nvt_fwu_work, msecs_to_jiffies(14000));
#endif

	SNVT_LOG("SNVT_TOUCH_ESD_PROTECT is %d\n", SNVT_TOUCH_ESD_PROTECT);
#if SNVT_TOUCH_ESD_PROTECT
	INIT_DELAYED_WORK(&nvt_esd_check_work, nvt_esd_check_func);
	nvt_esd_check_wq = alloc_workqueue("nvt_esd_check_wq", WQ_MEM_RECLAIM, 1);
	if (!nvt_esd_check_wq) {
		SNVT_ERR("nvt_esd_check_wq create workqueue failed\n");
		ret = -ENOMEM;
		goto err_create_nvt_esd_check_wq_failed;
	}
	queue_delayed_work(nvt_esd_check_wq, &nvt_esd_check_work,
			msecs_to_jiffies(SNVT_TOUCH_ESD_CHECK_PERIOD));
#endif /* #if SNVT_TOUCH_ESD_PROTECT */

	//---set device node---
#if SNVT_TOUCH_PROC
	ret = nvt_flash_proc_init();
	if (ret != 0) {
		SNVT_ERR("nvt flash proc init failed. ret=%d\n", ret);
		goto err_flash_proc_init_failed;
	}
#endif

#if SNVT_TOUCH_EXT_PROC
	ret = snvt_extra_proc_init();
	if (ret != 0) {
		SNVT_ERR("nvt extra proc init failed. ret=%d\n", ret);
		goto err_extra_proc_init_failed;
	}
#endif

#if SNVT_TOUCH_MP
	ret = nvt_mp_proc_init();
	if (ret != 0) {
		SNVT_ERR("nvt mp proc init failed. ret=%d\n", ret);
		goto err_mp_proc_init_failed;
	}
#endif

#if defined(CONFIG_FB)
#ifdef _MSM_DRM_NOTIFY_H_
	nts->drm_notif.notifier_call = nvt_drm_notifier_callback;
	ret = msm_drm_register_client(&nts->drm_notif);
	if(ret) {
		SNVT_ERR("register drm_notifier failed. ret=%d\n", ret);
		goto err_register_drm_notif_failed;
	}
#else
	nts->fb_notif.notifier_call = nvt_fb_notifier_callback;
	ret = fb_register_client(&nts->fb_notif);
	if(ret) {
		SNVT_ERR("register fb_notifier failed. ret=%d\n", ret);
		goto err_register_fb_notif_failed;
	}
#endif
#elif defined(CONFIG_HAS_EARLYSUSPEND)
	nts->early_suspend.level = EARLY_SUSPEND_LEVEL_BLANK_SCREEN + 1;
	nts->early_suspend.suspend = nvt_ts_early_suspend;
	nts->early_suspend.resume = nvt_ts_late_resume;
	ret = register_early_suspend(&nts->early_suspend);
	if(ret) {
		SNVT_ERR("register early suspend failed. ret=%d\n", ret);
		goto err_register_early_suspend_failed;
	}
#endif

	bTouchIsAwake = 1;
	SNVT_LOG("end\n");

	nvt_irq_enable(true);

	return 0;

#if defined(CONFIG_FB)
#ifdef _MSM_DRM_NOTIFY_H_
	if (msm_drm_unregister_client(&nts->drm_notif))
		SNVT_ERR("Error occurred while unregistering drm_notifier.\n");
err_register_drm_notif_failed:
#else
	if (fb_unregister_client(&nts->fb_notif))
		SNVT_ERR("Error occurred while unregistering fb_notifier.\n");
err_register_fb_notif_failed:
#endif
#elif defined(CONFIG_HAS_EARLYSUSPEND)
	unregister_early_suspend(&nts->early_suspend);
err_register_early_suspend_failed:
#endif
#if SNVT_TOUCH_MP
nvt_mp_proc_deinit();
err_mp_proc_init_failed:
#endif
#if SNVT_TOUCH_EXT_PROC
snvt_extra_proc_deinit();
err_extra_proc_init_failed:
#endif
#if SNVT_TOUCH_PROC
nvt_flash_proc_deinit();
err_flash_proc_init_failed:
#endif
#if SNVT_TOUCH_ESD_PROTECT
	if (nvt_esd_check_wq) {
		cancel_delayed_work_sync(&nvt_esd_check_work);
		destroy_workqueue(nvt_esd_check_wq);
		nvt_esd_check_wq = NULL;
	}
err_create_nvt_esd_check_wq_failed:
#endif
#if SBOOT_UPDATE_FIRMWARE
	if (nvt_fwu_wq) {
		cancel_delayed_work_sync(&nts->nvt_fwu_work);
		destroy_workqueue(nvt_fwu_wq);
		nvt_fwu_wq = NULL;
	}
err_create_nvt_fwu_wq_failed:
#endif
#if SWAKEUP_GESTURE
	device_init_wakeup(&nts->input_dev->dev, 0);
#endif
	free_irq(client->irq, nts);
err_int_request_failed:
	input_unregister_device(nts->input_dev);
	nts->input_dev = NULL;
err_input_register_device_failed:
	if (nts->input_dev) {
		input_free_device(nts->input_dev);
		nts->input_dev = NULL;
	}
err_input_dev_alloc_failed:
err_chipvertrim_failed:
	mutex_destroy(&nts->xbuf_lock);
	mutex_destroy(&nts->lock);
err_check_functionality_failed:
	nvt_gpio_deconfig(nts);
err_gpio_config_failed:
#ifdef SNVT_POWER_SOURCE_CUST_EN
	nvt_lcm_power_source_ctrl(nts, 0);
	nvt_lcm_bias_power_deinit(nts);
#endif
err_power_resource_init_fail:
	i2c_set_clientdata(client, NULL);
	if (nts) {
		kfree(nts);
		nts = NULL;
	}
	return ret;
}

/*******************************************************
Description:
	Novatek touchscreen driver release function.

return:
	Executive outcomes. 0---succeed.
*******************************************************/
static int32_t nvt_ts_remove(struct i2c_client *client)
{
	SNVT_LOG("Removing driver...\n");

#if defined(CONFIG_FB)
#ifdef _MSM_DRM_NOTIFY_H_
	if (msm_drm_unregister_client(&nts->drm_notif))
		SNVT_ERR("Error occurred while unregistering drm_notifier.\n");
#else
	if (fb_unregister_client(&nts->fb_notif))
		SNVT_ERR("Error occurred while unregistering fb_notifier.\n");
#endif
#elif defined(CONFIG_HAS_EARLYSUSPEND)
	unregister_early_suspend(&nts->early_suspend);
#endif

#if SNVT_TOUCH_MP
	nvt_mp_proc_deinit();
#endif
#if SNVT_TOUCH_EXT_PROC
	snvt_extra_proc_deinit();
#endif
#if SNVT_TOUCH_PROC
	nvt_flash_proc_deinit();
#endif

#if SNVT_TOUCH_ESD_PROTECT
	if (nvt_esd_check_wq) {
		cancel_delayed_work_sync(&nvt_esd_check_work);
		snvt_esd_check_enable(false);
		destroy_workqueue(nvt_esd_check_wq);
		nvt_esd_check_wq = NULL;
	}
#endif

#if SBOOT_UPDATE_FIRMWARE
	if (nvt_fwu_wq) {
		cancel_delayed_work_sync(&nts->nvt_fwu_work);
		destroy_workqueue(nvt_fwu_wq);
		nvt_fwu_wq = NULL;
	}
#endif

#if SWAKEUP_GESTURE
	device_init_wakeup(&nts->input_dev->dev, 0);
#endif

	nvt_irq_enable(false);
	free_irq(client->irq, nts);

	mutex_destroy(&nts->xbuf_lock);
	mutex_destroy(&nts->lock);

	nvt_gpio_deconfig(nts);

	if (nts->input_dev) {
		input_unregister_device(nts->input_dev);
		nts->input_dev = NULL;
	}

	i2c_set_clientdata(client, NULL);

	if (nts) {
		kfree(nts);
		nts = NULL;
	}

	return 0;
}

static void nvt_ts_shutdown(struct i2c_client *client)
{
	SNVT_LOG("Shutdown driver...\n");

	nvt_irq_enable(false);

#if defined(CONFIG_FB)
#ifdef _MSM_DRM_NOTIFY_H_
	if (msm_drm_unregister_client(&nts->drm_notif))
		SNVT_ERR("Error occurred while unregistering drm_notifier.\n");
#else
	if (fb_unregister_client(&nts->fb_notif))
		SNVT_ERR("Error occurred while unregistering fb_notifier.\n");
#endif
#elif defined(CONFIG_HAS_EARLYSUSPEND)
	unregister_early_suspend(&nts->early_suspend);
#endif

#if SNVT_TOUCH_MP
	nvt_mp_proc_deinit();
#endif
#if SNVT_TOUCH_EXT_PROC
	snvt_extra_proc_deinit();
#endif
#if SNVT_TOUCH_PROC
	nvt_flash_proc_deinit();
#endif

#if SNVT_TOUCH_ESD_PROTECT
	if (nvt_esd_check_wq) {
		cancel_delayed_work_sync(&nvt_esd_check_work);
		snvt_esd_check_enable(false);
		destroy_workqueue(nvt_esd_check_wq);
		nvt_esd_check_wq = NULL;
	}
#endif /* #if SNVT_TOUCH_ESD_PROTECT */

#if SBOOT_UPDATE_FIRMWARE
	if (nvt_fwu_wq) {
		cancel_delayed_work_sync(&nts->nvt_fwu_work);
		destroy_workqueue(nvt_fwu_wq);
		nvt_fwu_wq = NULL;
	}
#endif

#if SWAKEUP_GESTURE
	device_init_wakeup(&nts->input_dev->dev, 0);
#endif
}

/*******************************************************
Description:
	Novatek touchscreen driver suspend function.

return:
	Executive outcomes. 0---succeed.
*******************************************************/
static int32_t nvt_ts_suspend(struct device *dev)
{
	struct snvt_ts_data *data = dev_get_drvdata(dev);
	uint8_t buf[4] = {0};
#if SMT_PROTOCOL_B
	uint32_t i = 0;
#endif

	if (!bTouchIsAwake) {
		SNVT_LOG("Touch is already suspend\n");
		return 0;
	}

#if SNVT_TOUCH_ESD_PROTECT
	SNVT_LOG("cancel delayed work sync\n");
	cancel_delayed_work_sync(&nvt_esd_check_work);
	snvt_esd_check_enable(false);
#endif /* #if SNVT_TOUCH_ESD_PROTECT */

	mutex_lock(&nts->lock);

	SNVT_LOG("start\n");

	bTouchIsAwake = 0;

#if SWAKEUP_GESTURE
if (!allow_dclick && !allow_gesture) {
	nvt_irq_enable(false);

	//---write i2c command to enter "deep sleep mode"---
	buf[0] = EVENT_MAP_HOST_CMD;
	buf[1] = 0x11;
	SCTP_I2C_WRITE(nts->client, SI2C_FW_Address, buf, 2);

	// Force deep sleep mode
	snvt_set_page(SI2C_FW_Address, 0x11a50);
	buf[0] = 0x11a50 & 0xff;
	buf[1] = 0x11;
	SCTP_I2C_WRITE(nts->client, SI2C_FW_Address, buf, 2);

	SNVT_LOG("Enter normal mode sleep \n");
}
else {
	//---write i2c command to enter "wakeup gesture mode"---
	buf[0] = EVENT_MAP_HOST_CMD;
	buf[1] = 0x13;
	SCTP_I2C_WRITE(nts->client, SI2C_FW_Address, buf, 2);

	nvt_irq_enable(true);
	SNVT_LOG("gesture suspend end not disable vsp/vsn\n");
	SNVT_LOG("Enabled touch wakeup gesture\n");
}

#else // SWAKEUP_GESTURE
	nvt_irq_enable(false);
	//---write command to enter "deep sleep mode"---
	buf[0] = EVENT_MAP_HOST_CMD;
	buf[1] = 0x11;
	SCTP_I2C_WRITE(nts->client, SI2C_FW_Address, buf, 2);
	
	snvt_set_page(SI2C_FW_Address, 0x11a50);
	buf[0] = 0x11a50 & 0xff;
	buf[1] = 0x11;
	SCTP_I2C_WRITE(nts->client, SI2C_FW_Address, buf, 2);

#endif // SWAKEUP_GESTURE

	mutex_unlock(&nts->lock);

	/* release all touches */
#if SMT_PROTOCOL_B
	for (i = 0; i < nts->max_touch_num; i++) {
		input_mt_slot(nts->input_dev, i);
		input_report_abs(nts->input_dev, ABS_MT_TOUCH_MAJOR, 0);
		input_report_abs(nts->input_dev, ABS_MT_PRESSURE, 0);
		input_mt_report_slot_state(nts->input_dev, MT_TOOL_FINGER, 0);
	}
#endif
	input_report_key(nts->input_dev, BTN_TOUCH, 0);
#if !SMT_PROTOCOL_B
	input_mt_sync(nts->input_dev);
#endif
	input_sync(nts->input_dev);

	msleep(50);

#if SNVT_POWER_SOURCE_CUST_EN
	if (!allow_dclick && !allow_gesture) {
	nvt_lcm_power_source_ctrl(data, 0);//disable vsp/vsn
	SNVT_LOG("sleep suspend end  disable vsp/vsn\n");
	}
	else{
	SNVT_LOG("gesture suspend end not disable vsp/vsn\n");
	}
#endif

	SNVT_LOG("end\n");

	return 0;
}

/*******************************************************
Description:
	Novatek touchscreen driver resume function.

return:
	Executive outcomes. 0---succeed.
*******************************************************/
static int32_t nvt_ts_resume(struct device *dev)
{
#ifdef SNVT_POWER_SOURCE_CUST_EN	
	struct snvt_ts_data *data = dev_get_drvdata(dev);
	nvt_lcm_power_source_ctrl(data, 1);//enable vsp/vsn
#endif	
	if (bTouchIsAwake) {
		SNVT_LOG("Touch is already resume\n");
		return 0;
	}

	mutex_lock(&nts->lock);

	SNVT_LOG("start\n");

	// please make sure display reset(RESX) sequence and mipi dsi cmds sent before this
#if SNVT_TOUCH_SUPPORT_HW_RST
	gpio_set_value(nts->reset_gpio, 1);
#endif
	snvt_bootloader_reset();
	snvt_check_fw_reset_state(RESET_STATE_REK);

#if SWAKEUP_GESTURE
	nvt_irq_enable(true);
#endif

#if SNVT_TOUCH_ESD_PROTECT
	snvt_esd_check_enable(false);
	queue_delayed_work(nvt_esd_check_wq, &nvt_esd_check_work,
			msecs_to_jiffies(SNVT_TOUCH_ESD_CHECK_PERIOD));
#endif /* #if SNVT_TOUCH_ESD_PROTECT */

	bTouchIsAwake = 1;

	mutex_unlock(&nts->lock);

	SNVT_LOG("end\n");

	return 0;
}


#if defined(CONFIG_FB)
#ifdef _MSM_DRM_NOTIFY_H_
static int nvt_drm_notifier_callback(struct notifier_block *self, unsigned long event, void *data)
{
	struct msm_drm_notifier *evdata = data;
	int *blank;
	struct snvt_ts_data *nts =
		container_of(self, struct snvt_ts_data, drm_notif);

	if (!evdata || (evdata->id != 0))
		return 0;

	if (evdata->data && nts) {
		blank = evdata->data;
		if (event == MSM_DRM_EARLY_EVENT_BLANK) {
			if (*blank == MSM_DRM_BLANK_POWERDOWN) {
				SNVT_LOG("event=%lu, *blank=%d\n", event, *blank);
				nvt_ts_suspend(&nts->client->dev);
			}
		} else if (event == MSM_DRM_EVENT_BLANK) {
			if (*blank == MSM_DRM_BLANK_UNBLANK) {
				SNVT_LOG("event=%lu, *blank=%d\n", event, *blank);
				nvt_ts_resume(&nts->client->dev);
			}
		}
	}

	return 0;
}
#else
static int nvt_fb_notifier_callback(struct notifier_block *self, unsigned long event, void *data)
{
	struct fb_event *evdata = data;
	int *blank;
	struct snvt_ts_data *nts =
		container_of(self, struct snvt_ts_data, fb_notif);

	if (evdata && evdata->data && event == FB_EARLY_EVENT_BLANK) {
		blank = evdata->data;
		if (*blank == FB_BLANK_POWERDOWN) {
			SNVT_LOG("event=%lu, *blank=%d\n", event, *blank);
			nvt_ts_suspend(&nts->client->dev);
		}
	} else if (evdata && evdata->data && event == FB_EVENT_BLANK) {
		blank = evdata->data;
		if (*blank == FB_BLANK_UNBLANK) {
			SNVT_LOG("event=%lu, *blank=%d\n", event, *blank);
			nvt_ts_resume(&nts->client->dev);
		}
	}

	return 0;
}
#endif
#elif defined(CONFIG_HAS_EARLYSUSPEND)
/*******************************************************
Description:
	Novatek touchscreen driver early suspend function.

return:
	n.a.
*******************************************************/
static void nvt_ts_early_suspend(struct early_suspend *h)
{
	nvt_ts_suspend(nts->client, PMSG_SUSPEND);
}

/*******************************************************
Description:
	Novatek touchscreen driver late resume function.

return:
	n.a.
*******************************************************/
static void nvt_ts_late_resume(struct early_suspend *h)
{
	nvt_ts_resume(nts->client);
}
#endif

static const struct i2c_device_id nvt_ts_id[] = {
	{ SNVT_I2C_NAME, 0 },
	{ }
};

#ifdef CONFIG_OF
static struct of_device_id nvt_match_table[] = {
	{ .compatible = "novatek,NVT-ts",},
	{ },
};
#endif

static struct i2c_driver nvt_i2c_driver = {
	.probe		= nvt_ts_probe,
	.remove		= nvt_ts_remove,
	.shutdown	= nvt_ts_shutdown,
	.id_table	= nvt_ts_id,
	.driver = {
		.name	= SNVT_I2C_NAME,
#ifdef CONFIG_OF
		.of_match_table = nvt_match_table,
#endif
		.probe_type = PROBE_PREFER_ASYNCHRONOUS,
	},
};

/*******************************************************
Description:
	Driver Install function.

return:
	Executive Outcomes. 0---succeed. not 0---failed.
********************************************************/
static int32_t __init nvt_driver_init(void)
{
	int32_t ret = 0;

#if defined(CONFIG_TOUCHSCREEN_NT36xxx) || defined(CONFIG_TOUCHSCREEN_NT36xxx_X00TD)
	if (get_new_nvtouch() < 1)
		return 0;
#endif

	SNVT_LOG("start\n");
	//---add i2c driver---
	ret = i2c_add_driver(&nvt_i2c_driver);
	if (ret) {
		SNVT_ERR("failed to add i2c driver");
		goto err_driver;
	}

	SNVT_LOG("finished\n");

err_driver:
	return ret;
}

/*******************************************************
Description:
	Driver uninstall function.

return:
	n.a.
********************************************************/
static void __exit nvt_driver_exit(void)
{
#if defined(CONFIG_TOUCHSCREEN_NT36xxx) || defined(CONFIG_TOUCHSCREEN_NT36xxx_X00TD)
	if (get_new_nvtouch() < 1)
		return;
#endif

#if SWAKEUP_GESTURE
    sdestroy_gesture_control();
#endif
#ifdef SNVT_POWER_SOURCE_CUST_EN	
	nvt_lcm_bias_power_deinit(nts);
#endif
	i2c_del_driver(&nvt_i2c_driver);
}

//late_initcall(nvt_driver_init);
module_init(nvt_driver_init);
module_exit(nvt_driver_exit);

MODULE_DESCRIPTION("Novatek Touchscreen Driver");
