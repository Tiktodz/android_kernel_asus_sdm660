/*
 * Optimized netlink interface for Goodix fingerprint
 */
#include <linux/init.h>
#include <linux/module.h>
#include <net/sock.h>
#include <net/netlink.h>

#define NETLINK_TEST 25
#define MAX_MSGSIZE  32

static int pid = -1;
static struct sock *nl_sk;
static DEFINE_MUTEX(nl_mutex);

void sendnlmsg(char *message)
{
    struct sk_buff *skb;
    struct nlmsghdr *nlh;
    int len = NLMSG_SPACE(MAX_MSGSIZE);
    int slen;

    if (!message || !nl_sk || pid <= 0)
        return;

    skb = alloc_skb(len, GFP_ATOMIC);
    if (!skb)
        return;

    nlh = nlmsg_put(skb, 0, 0, 0, MAX_MSGSIZE, 0);
    if (!nlh) {
        kfree_skb(skb);
        return;
    }

    NETLINK_CB(skb).portid = 0;
    NETLINK_CB(skb).dst_group = 0;

    slen = strlen(message);
    if (slen >= MAX_MSGSIZE)
        slen = MAX_MSGSIZE - 1;
    
    memcpy(NLMSG_DATA(nlh), message, slen);
    ((char *)NLMSG_DATA(nlh))[slen] = '\0';

    if (netlink_unicast(nl_sk, skb, pid, MSG_DONTWAIT) < 0)
        pr_debug("Failed to send netlink message\n");
}

static void nl_data_ready(struct sk_buff *__skb)
{
    struct sk_buff *skb;
    struct nlmsghdr *nlh;

    skb = skb_get(__skb);
    if (skb->len >= NLMSG_SPACE(0)) {
        nlh = nlmsg_hdr(skb);
        pid = nlh->nlmsg_pid;
    }
    kfree_skb(skb);
}

int netlink_init(void)
{
    struct netlink_kernel_cfg cfg = {
        .groups = 0,
        .flags = 0,
        .input = nl_data_ready,
        .cb_mutex = NULL,
    };

    nl_sk = netlink_kernel_create(&init_net, NETLINK_TEST, &cfg);
    if (!nl_sk) {
        pr_err("Failed to create netlink socket\n");
        return -ENOMEM;
    }

    return 0;
}

void netlink_exit(void)
{
    if (nl_sk) {
        netlink_kernel_release(nl_sk);
        nl_sk = NULL;
    }
}
