/*
 * Optimized platform interface for Goodix fingerprint
 */
#include <linux/delay.h>
#include <linux/of_gpio.h>
#include <linux/gpio.h>
#include <linux/platform_device.h>

#include "gf_spi.h"

int gf_parse_dts(struct gf_dev *gf_dev)
{
    struct device *dev = &gf_dev->spi->dev;
    int rc;

    /* VDD GPIO */
    gf_dev->vdd_gpio = of_get_named_gpio(dev->of_node, "goodix,gpio_vdd", 0);
    if (!gpio_is_valid(gf_dev->vdd_gpio)) {
        dev_err(dev, "Invalid VDD GPIO\n");
        return -EINVAL;
    }

    rc = devm_gpio_request_one(dev, gf_dev->vdd_gpio,
                               GPIOF_OUT_INIT_LOW, "goodix_vdd");
    if (rc) {
        dev_err(dev, "Failed to request VDD GPIO: %d\n", rc);
        return rc;
    }

    /* Reset GPIO */
    gf_dev->reset_gpio = of_get_named_gpio(dev->of_node, "goodix,reset_gpio", 0);
    if (!gpio_is_valid(gf_dev->reset_gpio)) {
        dev_err(dev, "Invalid reset GPIO\n");
        return -EINVAL;
    }

    rc = devm_gpio_request_one(dev, gf_dev->reset_gpio,
                               GPIOF_OUT_INIT_HIGH, "goodix_reset");
    if (rc) {
        dev_err(dev, "Failed to request reset GPIO: %d\n", rc);
        return rc;
    }

    /* IRQ GPIO */
    gf_dev->irq_gpio = of_get_named_gpio(dev->of_node, "goodix,irq_gpio", 0);
    if (!gpio_is_valid(gf_dev->irq_gpio)) {
        dev_err(dev, "Invalid IRQ GPIO\n");
        return -EINVAL;
    }

    rc = devm_gpio_request_one(dev, gf_dev->irq_gpio,
                               GPIOF_IN, "goodix_irq");
    if (rc) {
        dev_err(dev, "Failed to request IRQ GPIO: %d\n", rc);
        return rc;
    }

    return 0;
}

void gf_cleanup(struct gf_dev *gf_dev)
{
    /* GPIOs freed automatically via devm_ */
    pr_info("Cleanup complete\n");
}

int gf_power_on(struct gf_dev *gf_dev)
{
    if (gpio_is_valid(gf_dev->vdd_gpio)) {
        gpio_set_value(gf_dev->vdd_gpio, 1);
        usleep_range(POWER_ON_DELAY_US, POWER_ON_DELAY_US + 1000);
    }
    pr_debug("Power on\n");
    return 0;
}

int gf_power_off(struct gf_dev *gf_dev)
{
    if (gpio_is_valid(gf_dev->vdd_gpio)) {
        gpio_set_value(gf_dev->vdd_gpio, 0);  /* ИСПРАВЛЕНО: было 1 */
    }
    pr_debug("Power off\n");
    return 0;
}

int gf_hw_reset(struct gf_dev *gf_dev, unsigned int delay_ms)
{
    if (!gf_dev || !gpio_is_valid(gf_dev->reset_gpio))
        return -EINVAL;

    gpio_set_value(gf_dev->reset_gpio, 0);
    usleep_range(RESET_DELAY_US, RESET_DELAY_US + 500);
    gpio_set_value(gf_dev->reset_gpio, 1);
    
    if (delay_ms)
        msleep(delay_ms);
    
    return 0;
}

int gf_irq_num(struct gf_dev *gf_dev)
{
    if (!gf_dev || !gpio_is_valid(gf_dev->irq_gpio))
        return -EINVAL;
    
    return gpio_to_irq(gf_dev->irq_gpio);
}
