#define _GNU_SOURCE /* for F_SETSIG */
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/poll.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <arpa/inet.h>
#include <netpacket/packet.h>

#include "platform.h"

#include "util.h"
#include "net.h"
#include "ether.h"

#include "driver/ether_soc_dev.h"


#define ETHER_SOC_IRQ (INTR_IRQ_BASE+3)

struct  ether_soc {
    char name[IFNAMSIZ];
    int soc;
    unsigned int irq;
};

#define PRIV(x) ((struct ether_soc *)x->priv)

static int ether_soc_addr(struct net_device *dev)
{
    int soc;
    struct ifreq ifr = {};
    soc = socket(AF_INET, SOCK_DGRAM, 0);

    if (soc == -1) {
        errorf("socket: %s, dev=%s", strerror(errno), dev->name);
        return -1;
    }

    strncpy(ifr.ifr_name, PRIV(dev)->name, sizeof(ifr.ifr_name)-1);
    if (ioctl(soc, SIOCGIFHWADDR, &ifr) == -1) {
        errorf("ioctl [SIOCGIFHWADDR]: %s, dev=%s", strerror(errno), dev->name);
        close(soc);
        return -1;
    }
    memcpy(dev->addr, ifr.ifr_hwaddr.sa_data, ETHER_ADDR_LEN);
    close(soc);
    return 0;
}

char *ip_soc_netmask(struct net_device *dev, char *mask_addr, size_t size){
    int soc;
    struct ifreq ifr = {};
    soc = socket(AF_INET, SOCK_DGRAM, 0);
    if (soc == -1) {
        errorf("socket: %s, dev=%s", strerror(errno), dev->name);
        return NULL;
    }

    strncpy(ifr.ifr_name, PRIV(dev)->name, sizeof(ifr.ifr_name)-1);
    if (ioctl(soc, SIOCGIFNETMASK, &ifr) == -1) {
        errorf("ioctl [SIOCGIFNETMASK]: %s, dev=%s", strerror(errno), dev->name);
        close(soc);
        return NULL;
    }
    
    close(soc);

    uint8_t *u8;
    u8 = (uint8_t *)(&((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr);
    snprintf(mask_addr, size, "%d.%d.%d.%d", u8[0], u8[1], u8[2], u8[3]);

    return mask_addr;
}

static int ether_soc_open(struct net_device *dev)
{
    int soc;
    struct ifreq ifr = {};
    struct sockaddr_ll addr;

    /* パケットソケットの生成 */
    soc = socket(PF_PACKET, SOCK_RAW, hton16(ETH_P_ALL));
    PRIV(dev)->soc = soc;
    if (soc == -1) {
        errorf("socket: %s, dev=%s", strerror(errno), dev->name);
        return -1;
    }

    /* インタフェースの名称からインデックス番号を取得 */
    strncpy(ifr.ifr_name, PRIV(dev)->name, sizeof(ifr.ifr_name) - 1);
    if (ioctl(soc, SIOCGIFINDEX, &ifr) == -1) {
        perror("ioctl [SIOCGIFINDEX]");
        close(soc);
        return -1;
    }

    ////
    struct ether_soc *esoc;
    esoc = PRIV(dev);
    /* Set Asynchronous I/O signal delivery destination */
    if (fcntl(esoc->soc, F_SETOWN, getpid()) == -1) {
        errorf("fcntl(F_SETOWN): %s, dev=%s", strerror(errno), dev->name);
        close(esoc->soc);
        return -1;
    }
    /* Enable Asynchronous I/O */
    if (fcntl(esoc->soc, F_SETFL, O_ASYNC) == -1) {
        errorf("fcntl(F_SETFL): %s, dev=%s", strerror(errno), dev->name);
        close(esoc->soc);
        return -1;
    }
    /* Use other signal instead of SIGIO */
    if (fcntl(esoc->soc, F_SETSIG, esoc->irq) == -1) {
        errorf("fcntl(F_SETSIG): %s, dev=%s", strerror(errno), dev->name);
        close(esoc->soc);
        return -1;
    }
    ////

    /* ソケットにインタフェースを紐づけ */
    memset(&addr, 0x00, sizeof(addr));
    addr.sll_family = AF_PACKET;
    addr.sll_protocol = hton16(ETH_P_ALL);
    addr.sll_ifindex = ifr.ifr_ifindex;
    if (bind(soc, (struct sockaddr *)&addr, sizeof(addr)) == -1) {
        perror("bind");
        close(soc);
        return -1;
    }
    return 0;
}

static int ether_soc_close(struct net_device *dev)
{
    close(PRIV(dev)->soc);
    return 0;
}

static ssize_t ether_soc_write(struct net_device *dev, const uint8_t *frame, size_t flen)
{
    return write(PRIV(dev)->soc, frame, flen);
}

int ether_soc_transmit(struct net_device *dev, uint16_t type, const uint8_t *buf, size_t len, const void *dst)
{
    return ether_transmit_helper(dev, type, buf, len, dst, ether_soc_write);
}

static ssize_t ether_soc_read(struct net_device *dev, uint8_t *buf, size_t size)
{
    ssize_t len;

    len = read(PRIV(dev)->soc, buf, size);
    if(len <= 0){
        if (len == -1 && errno != EINTR) {
            errorf("read: %s, dev=%s", strerror(errno), dev->name);
        }
    return -1;
    }
    return len;
}

static int ether_soc_isr(unsigned int irq, void *id)
{
    struct net_device *dev;;
    struct pollfd pfd;
    int ret;

    dev = (struct net_device *)id;
    pfd.fd = PRIV(dev)->soc;
    pfd.events = POLLIN;
    while(1){
        ret = poll(&pfd, 1, 0);
        if(ret == -1){
            if (errno == EINTR) {
                continue;
            }
            errorf("poll: %s, dev=%s", strerror(errno), dev->name);
            return -1;
        }
        if (ret == 0) {
            /* No frames to input immediately. */
            break;
        }
        ether_input_helper(dev, ether_soc_read);
    }
    return 0;
}

static struct net_device_ops ether_soc_ops = {
    .open = ether_soc_open,
    .close = ether_soc_close,
    .transmit = ether_soc_transmit,
};

struct net_device *ether_soc_init(const char *name)
{
    struct net_device *dev;
    struct ether_soc *esoc;


    dev = net_device_alloc();
    if (!dev) {
        errorf("net_device_alloc() failure");
        return NULL;
    }
    ether_setup_helper(dev);

    dev->ops = &ether_soc_ops;
    esoc = memory_alloc(sizeof(*esoc));
    if(!esoc){
        errorf("memory_alloc() failure");
        return NULL;
    }
    strncpy(esoc->name, name, sizeof(esoc->name)-1);
    esoc->soc = -1;
    esoc->irq = ETHER_SOC_IRQ;
    dev->priv = esoc;

    //
    if(ether_soc_addr(dev) == -1){
        errorf("ether_soc_addr() failure, dev=%s", dev->name);
        return NULL;
        }
    //

    if (net_device_register(dev) == -1) {
        errorf("net_device_register() failure");
        memory_free(esoc);
        return NULL;
    }
    intr_request_irq(esoc->irq, ether_soc_isr, INTR_IRQ_SHARED, dev->name, dev);
    infof("ethernet device initialized, dev=%s", dev->name);
    return dev;
}