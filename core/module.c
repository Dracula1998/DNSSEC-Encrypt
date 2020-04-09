#include "constants.h"

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/skbuff.h>
#include <linux/init.h>
#include <linux/fs.h>
#include <linux/timer.h>
#include <linux/timex.h>
#include <linux/rtc.h>
#include <linux/string.h>
#include <linux/types.h>
#include <linux/unistd.h>
#include <asm/uaccess.h>
#include <asm/processor.h>
#include <linux/crypto.h>

//========================Filter Declaration==START========================================

//=========================Filter Declaration==END=========================================

//========================Logger Declaration==START========================================

#define LOG_LEVEL LOGGER_OK

void init_writer(void);

/**
 * Be aware that the message has max length. The message length should be less than
 * 512 bytes and the source length should be less than 64.
 *
 * @param source
 * @param level
 * @param message
 */
void log_message(char *source, int level, char *message);

void close_writer(void);

//========================Logger Declaration==END==========================================

//================================Filter Implementation==START=============================

//================================Filter Implementation==END===============================

//=============================Logger Implementation==START================================

struct file *file;

void init_writer(void)
{
    file = filp_open("/var/log/NetFilter.log", O_RDWR | O_CREAT | O_APPEND, 0644);
    if (IS_ERR(file))
    {
        printk(NAME "Create log file error\n");
        file = NULL;
        return;
    }
}

void print_console(int level, char *log_str)
{

    if (log_str == NULL)
        return;

    char *console_color = NULL;

    switch (level)
    {
    case LOGGER_DEBUG:
        console_color = COLOR_PURPLE;
        break;
    case LOGGER_INFO:
        console_color = COLOR_BLACK;
        break;
    case LOGGER_OK:
        console_color = COLOR_BLUE;
        break;
    case LOGGER_LOW:
        console_color = COLOR_CYAN;
        break;
    case LOGGER_WARN:
        console_color = COLOR_YELLOW;
        break;
    case LOGGER_FATAL:
        console_color = COLOR_RED;
        break;
    default:
        console_color = COLOR_WHITE;
        break;
    }

    printk("%s" NAME "%s" COLOR_RESET, console_color, log_str);
}

void write_log(char *log_str, int length)
{

    if (log_str == NULL)
        return;

    mm_segment_t old_fs = get_fs();
    set_fs(get_ds());
    vfs_write(file, log_str, length, &file->f_pos);
    set_fs(old_fs);
}

void close_writer(void)
{
    filp_close(file, NULL);
}

void get_current_time(char *time)
{

    struct timex txc;
    struct rtc_time tm;

    do_gettimeofday(&(txc.time));

    txc.time.tv_sec -= sys_tz.tz_minuteswest * 60;
    rtc_time_to_tm(txc.time.tv_sec, &tm);
    sprintf(time, "%d-%02d-%02d %02d:%02d:%02d",
            tm.tm_year + 1900,
            tm.tm_mon + 1,
            tm.tm_mday,
            tm.tm_hour,
            tm.tm_min,
            tm.tm_sec);
}

void log_message(char *source, int level, char *message)
{

    int message_len, source_len;
    char time[32];
    char *level_str = NULL;
    char *log_str;

    if (file == NULL)
        return;
    if (message == NULL || source == NULL)
        return;

    message_len = strnlen(message, 512);
    source_len = strnlen(source, 64);

    // length too long
    if (message_len >= 512)
    {
        print_console(LOGGER_WARN, NAME "Message length exceeded 512");
        return;
    }
    if (source_len >= 64)
    {
        print_console(LOGGER_WARN, NAME "Source length exceeded 64");
        return;
    }

    if (level < LOG_LEVEL)
        return;

    switch (level)
    {
    case LOGGER_DEBUG:
        level_str = "DEBUG";
        break;
    case LOGGER_INFO:
        level_str = "INFO";
        break;
    case LOGGER_OK:
        level_str = "OK";
        break;
    case LOGGER_LOW:
        level_str = "LOW";
        break;
    case LOGGER_WARN:
        level_str = "WARN";
        break;
    case LOGGER_FATAL:
        level_str = "FATAL";
        break;
    default:
        level_str = "UNKNOWN";
        break;
    }

    get_current_time(time);

    log_str = kmalloc(32 + 2 + source_len + 2 + strlen(level_str) + 1 + message_len + 2, GFP_KERNEL);

    sprintf(log_str, "%s [%s] %s %s", time, source, level_str, message);
    print_console(level, log_str);
    strncat(log_str, "\n", 1);
    write_log(log_str, strlen(log_str));
    kfree(log_str);
}

//========================Logger Implementation==END=======================================

//========================Kernel Module Implementation=====================================
static struct nf_hook_ops nfho_dns_in;
static struct nf_hook_ops nfho_dns_out;

unsigned int dns_in_func(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
{
    char message[128];
    struct iphdr *ip;
    struct udphdr *udp;
    uint16_t *p_data = NULL;
    int dns_length = 0;
    int csum = 0;

    if(!skb)
    {
        sprintf(message, "this is not a valid packet", 0);
        log_message("Release", LOGGER_OK, message);
        return NF_ACCEPT;
    }

    if(skb->protocol != htons(0x0800)) //capture ip packets, release arp packets
    {
        sprintf(message, "this is not a ip packet", 0);
        log_message("Release", LOGGER_OK, message);
        return NF_ACCEPT;
    }
    ip = ip_hdr(skb);
    if ((ip->protocol != 17)) //capture udp packets
    {
        sprintf(message, "this is not a udp packet", 0);
        log_message("Release", LOGGER_OK, message);
        return NF_ACCEPT;
    }
    
    udp = (struct udpher *)(ip + 1);
    if ((udp != NULL) && (ntohs(udp->dest) != 53)) //capture DNS packets
    {
        sprintf(message, "this is not a dns packet", 0);
        log_message("Release", LOGGER_OK, message);
        return NF_ACCEPT;
    }
    
    sprintf(message, "a new dns income packet %d", 0);
    log_message("Capture:", LOGGER_OK, message);

    p_data = (uint16_t *)(udp + 1);
    dns_length = sizeof(p_data);
    p_data[1] = htons(0x1234);
    
    // change the udp header
    udp->len = htons(ntohs(udp->len) - dns_length + sizeof(p_data));

    // change the ip header
    ip->tot_len = htons(ntohs(ip->tot_len) - dns_length + sizeof(p_data));

    // update the checksums
    csum = csum_partical(udp, udp->len);
    udp->check = udp_v4_check(ip->tot_len, ip->saddr, ip->daddr, csum);

    sprintf(message, "a new modified dns income packet %d", 0);
    log_message("Send:", LOGGER_OK, message);
    return NF_ACCEPT;
}

unsigned int dns_out_func(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
{
    char message[128];
    struct iphdr *ip;
    struct udphdr *udp;

    if(!skb)
    {
        sprintf(message, "this is not a valid packet", 0);
        log_message("Release", LOGGER_OK, message);
        return NF_ACCEPT;
    }

    if(skb->protocol != htons(0x0800)) //capture ip packets, release arp packets
    {
        sprintf(message, "this is not a ip packet", 0);
        log_message("Release", LOGGER_OK, message);
        return NF_ACCEPT;
    }
    ip = ip_hdr(skb);
    if ((ip->protocol != 17)) //capture udp packets
    {
        sprintf(message, "this is not a udp packet", 0);
        log_message("Release", LOGGER_OK, message);
        return NF_ACCEPT;
    }
    
    udp = udp_hdr(skb);
    if (ntohs(udp->source) != 53) //capture DNS packets
    {
        sprintf(message, "this is not a dns packet", 0);
        log_message("Release", LOGGER_OK, message);
        return NF_ACCEPT;
    }

    sprintf(message, "capture a new dns outcome packet %d", 0);
    log_message("Capture:", LOGGER_OK, message);
    return NF_ACCEPT;
}

static int __init hook_init(void)
{
    int ret = 0;
    struct net *n;
    char message[128];

    init_writer();

    nfho_dns_in.hook = dns_in_func;
    nfho_dns_in.pf = NFPROTO_IPV4;
    nfho_dns_in.hooknum = NF_INET_LOCAL_IN;
    nfho_dns_in.priority = NF_IP_PRI_FIRST;

    nfho_dns_out.hook = dns_out_func;
    nfho_dns_out.pf = NFPROTO_IPV4;
    nfho_dns_out.hooknum = NF_INET_LOCAL_OUT;
    nfho_dns_out.priority = NF_IP_PRI_FIRST;

    for_each_net(n) ret += nf_register_net_hook(n, &nfho_dns_in);
    for_each_net(n) ret += nf_register_net_hook(n, &nfho_dns_out);

    sprintf(message, "nf_register_hook returnd %d", ret);
    log_message("Hook init", LOGGER_OK, message);

    return ret;
}

static void __exit hook_exit(void)
{
    struct net *n;

    log_message("Hook exit", LOGGER_OK, "Hook deinit");

    for_each_net(n) nf_unregister_net_hook(n, &nfho_dns_in);
    for_each_net(n) nf_unregister_net_hook(n, &nfho_dns_out);

    close_writer();
}

module_init(hook_init);
module_exit(hook_exit);

MODULE_LICENSE("Dual MIT/GPL");
MODULE_AUTHOR("Dracula1998");
//========================Kernel Module Implementation==END================================
