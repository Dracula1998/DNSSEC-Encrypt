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

#include <linux/inet.h>
#include <linux/skbuff.h>
#include <linux/netdevice.h>
#include <linux/jhash.h>
#include <linux/slab.h>
#include <net/checksum.h>
#include <net/ip.h>
#include <net/tcp.h>
#include <net/udp.h>

#include <linux/scatterlist.h>
#include <linux/gfp.h>
#include <linux/err.h>
#include <linux/syscalls.h>
#include <linux/highmem.h>
#include <crypto/skcipher.h>
#include <crypto/akcipher.h>
#include <crypto/rng.h>
#include <linux/random.h>

//========================Filter Declaration==START========================================

/* tie all data structures used in encrytion together */
struct skcipher_def {
    struct scatterlist sg;
    struct crypto_skcipher *tfm;
    struct skcipher_request *req;
    struct crypto_wait wait;
};

/**
 * this method is used to verify whether the packet is a dns packet
 * 
 * @param skb the target data pack
 * @param ip the ip pack
 * @param udp the udp pack
 * @param message  a buffer used to place log message
 *  
 */
int is_dns(struct sk_buff *skb, struct iphdr *ip, struct udphdr *udp, char *message);

int dns_type(struct udphdr *udp, char *message);

void update_check_sum(struct iphdr *ip, struct udphdr *udp, char *dns_data, int old_length, int new_length, char *message);

int get_random_numbers(u8 *buf, unsigned int len);

int aes_add_padding(char **data, int data_length); 
int aes_rm_padding(char **data, int data_length);
void hexdump(unsigned char *buf, unsigned int len);



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
// void log_message(char *source, int level, char *message);

void close_writer(void);

//========================Logger Declaration==END==========================================

//================================Filter Implementation==START=============================

int is_dns(struct sk_buff *skb, struct iphdr *ip, struct udphdr *udp, char *message)
{
    if (!skb)
    {
        // sprintf(message, "this is not a valid packet");
        // log_message("Release", LOGGER_OK, message);
        return DNS_PACKET_NO;
    }

    //capture ip packets, release arp packets
    if (skb->protocol != htons(0x0800))
    {
        // sprintf(message, "this is not a ip packet");
        // log_message("Release", LOGGER_OK, message);
        return DNS_PACKET_NO;
    }

    //capture udp packets
    if ((ip->protocol != 17))
    {
        // sprintf(message, "this is not a udp packet");
        // log_message("Release", LOGGER_OK, message);
        return DNS_PACKET_NO;
    }

    if (udp == NULL)
    {
        return DNS_PACKET_NO;
    }

    //capture DNS packets
    if ((udp != NULL) && (ntohs(udp->dest) != 53) && (ntohs(udp->source) != 53))
    {
        // sprintf(message, "this is not a dns packet");
        // log_message("Release", LOGGER_OK, message);
        return DNS_PACKET_NO;
    }

    sprintf(message, "a new dns packet %d", 0);
    // log_message("Capture:", LOGGER_OK, message);

    return DNS_PACKET_YES;
}

int dns_type(struct udphdr *udp, char *message)
{
    if (ntohs(udp->dest) == 53)
    {
        sprintf(message, "this is a query packet");
        // log_message("Type", LOGGER_OK, message);
        return DNS_PACKET_QUERY;
    }
    else
    {
        sprintf(message, "this is a response packet");
        // log_message("Type", LOGGER_OK, message);
        return DNS_PACKET_RESPONSE;
    }
}

void update_check_sum(struct iphdr *ip, struct udphdr *udp, char *dns_data, int old_length, int new_length, char *message)
{
    int csum = 0;
    int add_length = new_length - old_length;

    // change the udp header
    udp->len = htons(ntohs(udp->len) + add_length);

    // change the ip header
    ip->tot_len = htons(ntohs(ip->tot_len) + add_length);

    // update the checksums
    csum = csum_partial(udp, udp->len, 0);
    udp->check = udp_v4_check(ip->tot_len, ip->saddr, ip->daddr, csum);

    sprintf(message, "update the checksum");
    // log_message("Check", LOGGER_OK, message);
}


int get_random_numbers(u8 *buf, unsigned int len)
{
    struct crypto_rng *rng = NULL;
    char *drbg = "drbg_nopr_sha256"; /* Hash DRBG with SHA-256, no PR */
    int ret;

    if (!buf || !len) {
        pr_debug("No output buffer provided\n");
        return -EINVAL;
    }

    rng = crypto_alloc_rng(drbg, 0, 0);
    if (IS_ERR(rng)) {
        pr_debug("could not allocate RNG handle for %s\n", drbg);
        return PTR_ERR(rng);
    }

    ret = crypto_rng_get_bytes(rng, buf, len);
    if (ret < 0)
        pr_debug("generation of random numbers failed\n");
    else if (ret == 0)
        pr_debug("RNG returned no data");
    else
        pr_debug("RNG returned %d bytes of data\n", ret);

    crypto_free_rng(rng);
    return ret;
}

int aes_add_padding(char **data, int data_length)
{
    int padding, tmp_length;
    char *tmp;
    if (data_length % BLK_SIZE == 0)
    {
        return data_length;
    }
    
    padding = BLK_SIZE - data_length % BLK_SIZE;
    tmp_length = padding + data_length;
    tmp = kmalloc(tmp_length, GFP_KERNEL);
    memcpy(tmp, *data, data_length);
    memset(tmp + data_length, padding, padding);
    *data = tmp;
    return tmp_length;
}


int aes_rm_padding(char **data, int data_length)
{
    int padding, i;
    if (data_length % 16 != 0)
    {
        return -1;
    }
    
    padding = (*data)[data_length - 1];
    for (i = 0; (*data)[data_length - 1 -i] == padding; i++);

    if (padding == i)
        return data_length - i;
    else
    {
        if (i == 1)
        {
            return data_length;
        }
        else
        {
            return -1;
        }    
    }
}


static int __rdx_akcrypto_tfm_aes(struct crypto_skcipher *tfm,
			void *input, void *output, unsigned char *key, int len, int phase)
{
	struct skcipher_request *req;
	void *out_buf = NULL;
	unsigned int out_len_max = 0;
	struct scatterlist src, dst;
	void *xbuf = NULL;
	int err = 0;
	char *ivdata;

	xbuf = kzalloc(PAGE_SIZE, GFP_KERNEL);
	if (!xbuf)
		return err;

	req = skcipher_request_alloc(tfm, GFP_KERNEL);
	if (!req)
		goto free_xbuf;

	err = crypto_skcipher_setkey(tfm, key, AES_KEY_LEN);

	if (err){
		pr_err("set key error! err: %d phase: %d\n", err, phase);
		goto free_req;
	}

	/* IV will be random */
	ivdata = kzalloc(AES_IV_LEN, GFP_KERNEL);


	err = -ENOMEM;
	pr_debug("out_len_max = %d, len = %d\n", out_len_max, len);
	out_buf = kzalloc(PAGE_SIZE, GFP_KERNEL);

	if (!out_buf)
		goto free_req;

	if (WARN_ON(len > PAGE_SIZE))
		goto free_all;
	memcpy(xbuf, input, len);
	sg_init_one(&src, xbuf, len);
	sg_init_one(&dst, out_buf, len);

	skcipher_request_set_crypt(req, &src, &dst, len, ivdata);

    pr_info("message dump: \n");
    hexdump(key, AES_KEY_LEN);
    hexdump(ivdata, AES_IV_LEN);
    hexdump(xbuf, len);
    

//    akcipher_request_set_callback(req, CRYPTO_TFM_REQ_MAY_BACKLOG,
//                               tcrypt_complete, &result);

	if (phase) { //sign phase
		//err = wait_async_op(&result, crypto_akcipher_encrypt(req));
		pr_warn ("start enc\n");
		err =  crypto_skcipher_encrypt(req);
		if (err) {
			pr_err("skcipher: encrypt failed. err %d\n", err);
			goto free_all;
		}
		pr_debug("after encrypt in out_buf:\n");
		//hexdump(out_buf, out_len_max);
		memcpy(output, out_buf, len);
	} else { //verification phase
		pr_warn("dec start\n");
		//err = wait_async_op(&result, crypto_akcipher_decrypt(req));
		err =  crypto_skcipher_decrypt(req);
		if (err) {
			pr_err("skcipher: decrypt failed. err %d\n",
					err);
			goto free_all;
		}
		pr_debug("after decrypt in out_buf:\n");
		//hexdump(out_buf, out_len_max);
		memcpy(output, out_buf, len);
	}

free_all:
	kfree(out_buf);
free_req:
	skcipher_request_free(req);
free_xbuf:
	kfree(xbuf);
	return err;
}

int aes_crypto(void *input, void *output, unsigned char *key, int len, int option)
{
     struct crypto_skcipher *tfm;
     int err = 0;

     tfm = crypto_alloc_skcipher("cbc-aes-aesni", 0, 0);
     if (IS_ERR(tfm)) {
             pr_err("alg: skcipher: Failed to load tfm for aes: %ld\n", PTR_ERR(tfm));
             return PTR_ERR(tfm);
     }
     err = __rdx_akcrypto_tfm_aes(tfm, input, output, key, len, option);

     crypto_free_skcipher(tfm);
     return err;
}



static unsigned int remove_zero_bit(unsigned char *buf, unsigned int length)
{
    int i;
    int text_length;
    for (i = 0; buf[i] == 0; i++)
        ;
    text_length = length - i;
    if (text_length > 0)
    {
        memcpy(buf, buf + i, text_length);
        return text_length;
    }

    return 0;
}

void hexdump(unsigned char *buf, unsigned int len)
{
    int i;

    for (i = 0; i < len; i++)
    {
        pr_warn(KERN_CONT "%02X", buf[i]);
    }
    pr_warn("\n");
}

static void chardump(unsigned char *buf, unsigned int len)
{
    int i;

    for (i = 0; i < len; i++)
    {
        pr_warn(KERN_CONT "%c", buf[i]);
    }
    pr_warn("\n");
}

static int __rdx_akcrypto_tfm_sv(struct crypto_akcipher *tfm,
                                 void *input, int len, void *output, int phase)
{
    struct akcipher_request *req;
    void *out_buf = NULL;
    // struct tcrypt_result result;
    unsigned int out_len_max = 0;
    struct scatterlist src, dst;
    void *xbuf = NULL;
    int err = 0;

    xbuf = kmalloc(PAGE_SIZE, GFP_KERNEL);
    if (!xbuf)
        return err;

    req = akcipher_request_alloc(tfm, GFP_KERNEL);
    if (!req)
        goto free_xbuf;

    //	init_completion(&result.completion);

    if (phase)
    {
        pr_debug("set pub key \n");
        err = crypto_akcipher_set_pub_key(tfm, pub_key, pub_key_len);
    }
    else
    {
        pr_debug("set priv key\n");
        //err = crypto_akcipher_set_pub_key(tfm, pub_key, pub_key_len);
        err = crypto_akcipher_set_priv_key(tfm, priv_key, priv_key_len);
    }

    if (err)
    {
        pr_err("set key error! err: %d phase: %d\n", err, phase);
        goto free_req;
    }

    err = -ENOMEM;
    out_len_max = crypto_akcipher_maxsize(tfm);
    pr_debug("out_len_max = %d, len = %d\n", out_len_max, len);
    out_buf = kzalloc(PAGE_SIZE, GFP_KERNEL);

    if (!out_buf)
        goto free_req;

    if (WARN_ON(len > PAGE_SIZE))
        goto free_all;
    memcpy(xbuf, input, len);
    sg_init_one(&src, xbuf, len);
    sg_init_one(&dst, out_buf, out_len_max);
    akcipher_request_set_crypt(req, &src, &dst, len, out_len_max);
    //    akcipher_request_set_callback(req, CRYPTO_TFM_REQ_MAY_BACKLOG,
    //                               tcrypt_complete, &result);

    if (phase)
    { //sign phase
        err = crypto_akcipher_encrypt(req);
        if (err)
        {
            pr_err("alg: akcipher: encrypt failed. err %d\n", err);
            goto free_all;
        }
        pr_debug("after encrypt in out_buf:\n");
        //hexdump(out_buf, out_len_max);
        memcpy(output, out_buf, out_len_max);
    }
    else
    { //verification phase
        err = crypto_akcipher_decrypt(req);
        if (err)
        {
            pr_err("alg: akcipher: decrypt failed. err %d\n",
                   err);
            goto free_all;
        }
        pr_debug("after decrypt in out_buf:\n");
        memcpy(output, out_buf, out_len_max);
    }

free_all:
    kfree(out_buf);
free_req:
    akcipher_request_free(req);
free_xbuf:
    kfree(xbuf);
    return err;
}

int rsa_crypto(void *input, int len, void *output, int option)
{
    struct crypto_akcipher *tfm;
    int err = 0;

    tfm = crypto_alloc_akcipher("rsa", CRYPTO_ALG_INTERNAL, 0);
    if (IS_ERR(tfm))
    {
        pr_err("alg: akcipher: Failed to load tfm for rsa: %ld\n", PTR_ERR(tfm));
        return PTR_ERR(tfm);
    }
    err = __rdx_akcrypto_tfm_sv(tfm, input, len, output, option);

    crypto_free_akcipher(tfm);
    return err;
}

char *msg = "a test message";
int msg_len = 14;

int test_rsa(void)
{
    int ret = 0;
    char *c, *m;
    int text_length;
    c = kzalloc(RSA_KEY_LEN, GFP_KERNEL);
    m = kzalloc(RSA_KEY_LEN, GFP_KERNEL);

    pr_warn("initial msg :\n");
    chardump(msg, msg_len);

    ret = rsa_crypto(msg, msg_len, c, DATA_ENCRYPT);
    if (ret)
    {
        pr_err("RSA sign error\n");
        goto err;
    }
    pr_warn("encrypted msg :\n");
    hexdump(c, RSA_KEY_LEN);

    ret = rsa_crypto(c, RSA_KEY_LEN, m, DATA_DECRYPT);
    if (ret)
    {
        pr_err("RSA verify error\n");
        goto err;
    }
    pr_warn("decrypted msg :\n");
    text_length = remove_zero_bit(m, RSA_KEY_LEN);
    chardump(m, text_length);
err:
    kfree(c);
    kfree(m);
    return ret;
};


int aes_test(void)
{
    char *data = NULL;
    unsigned char key[32];
	int length = 122;
    char *c, *m;
    c = kzalloc(PAGE_SIZE, GFP_KERNEL);
	m = kzalloc(PAGE_SIZE, GFP_KERNEL);

    pr_info("test start");
	/* AES 256 with random key */
    get_random_bytes(&key, 32);

	/* Input data will be random */
    data = kmalloc(length, GFP_KERNEL);
    if (!data) {
        pr_info("could not allocate scratchpad\n");
        goto out;
    }
    get_random_bytes(data, length);
    pr_info("Initial data: ");
    hexdump(data, length);
	
    length = aes_add_padding(&data, length);
    if (length < 0)
    {
        pr_info("add aes padding error\n");
    }
    pr_info("after padding: ");
    hexdump(data, length);
    
  	aes_crypto(data, c, key, length, DATA_ENCRYPT);
    pr_info("after encrypt: ");
    hexdump(c, length);
    aes_crypto(c, m, key, length, DATA_DECRYPT);
    pr_info("after decrypt: ");
    hexdump(m, length);
    length = aes_rm_padding(&m, length);
    pr_info("after unpadding: ");
    hexdump(m, length);
    pr_info("aes test finished\n");
	return 0;

out:
    kfree(key);
    if (data)
        kfree(data);
    return -1;
}


struct sk_buff* skb_update_data(struct sk_buff *skb, char *old_data, char *new_data, int old_length, int new_length)
{
    int add_length;
    struct sk_buff *nskb;

    pr_info("enter update data function");
    add_length = new_length - old_length;
    if (add_length < 0)
    {
        goto out;
    }
    

    if (skb_tailroom(skb) < add_length)
    {
        pr_info("expand the skb to nskb");
        nskb = skb_copy_expand(skb, skb_headroom(skb), skb_tailroom(skb) + add_length, GFP_ATOMIC);
        pr_info("expand finished");
    }
    else
    {
        pr_info("there is no need to expand");
        nskb = skb;
    }
    
    if (!nskb)
    {
        return -1;
    }
    
    pr_info("expand the data buffer");
    skb_put(nskb, add_length);
    pr_info("expanded the data buffer");
// out:
//     memcpy(skb->data, new_data, new_length);
//     pr_info("added the nre data");
    
    return nskb;
}
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
    char *console_color;

    if (log_str == NULL)
        return;


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
    mm_segment_t old_fs;

    if (log_str == NULL)
        return;

    old_fs = get_fs();
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

// void log_message(char *source, int level, char *message)
// {

//     int message_len, source_len;
//     char time[32];
//     char *level_str = NULL;
//     char *log_str;

//     if (file == NULL)
//         return;
//     if (message == NULL || source == NULL)
//         return;

//     message_len = strnlen(message, 512);
//     source_len = strnlen(source, 64);

//     // length too long
//     if (message_len >= 512)
//     {
//         print_console(LOGGER_WARN, NAME "Message length exceeded 512");
//         return;
//     }
//     if (source_len >= 64)
//     {
//         print_console(LOGGER_WARN, NAME "Source length exceeded 64");
//         return;
//     }

//     if (level < LOG_LEVEL)
//         return;

//     switch (level)
//     {
//     case LOGGER_DEBUG:
//         level_str = "DEBUG";
//         break;
//     case LOGGER_INFO:
//         level_str = "INFO";
//         break;
//     case LOGGER_OK:
//         level_str = "OK";
//         break;
//     case LOGGER_LOW:
//         level_str = "LOW";
//         break;
//     case LOGGER_WARN:
//         level_str = "WARN";
//         break;
//     case LOGGER_FATAL:
//         level_str = "FATAL";
//         break;
//     default:
//         level_str = "UNKNOWN";
//         break;
//     }

//     get_current_time(time);

//     log_str = kmalloc(32 + 2 + source_len + 2 + strlen(level_str) + 1 + message_len + 2, GFP_KERNEL);

//     sprintf(log_str, "%s [%s] %s %s", time, source, level_str, message);
//     print_console(level, log_str);
//     strncat(log_str, "\n", 1);
//     write_log(log_str, strlen(log_str));
//     kfree(log_str);
// }

//========================Logger Implementation==END=======================================

//========================Kernel Module Implementation=====================================
static struct nf_hook_ops nfho_dns_in;
static struct nf_hook_ops nfho_dns_out;
static char aes_key_client[AES_KEY_LEN];
static char aes_key_server[AES_KEY_LEN];
static struct net_device *my_net_device;

unsigned int dns_in_func(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
{
    char message[128];
    struct iphdr *ip;
    struct udphdr *udp;
    char aes_key[32];
    char *dns_data, *out_data;
    int dns_length = 0;

    ip = ip_hdr(skb);

    udp = (struct udphdr *)(ip + 1);

    if (is_dns(skb, ip, udp, message) == DNS_PACKET_NO)
    {
        return NF_ACCEPT;
    }

    dns_data = (char *)(udp + 1);
    dns_length = sizeof(dns_data);
    out_data = kzalloc(PAGE_SIZE, GFP_KERNEL);
    if (dns_type(udp, message) == DNS_PACKET_QUERY)
    {
        // int aes_key_length;
        // aes_key = kzalloc(RSA_KEY_LEN, GFP_KERNEL);
        // rsa_crypto(dns_data, RSA_KEY_LEN, aes_key, DATA_DECRYPT);
        // aes_key_length = remove_zero_bit(aes_key, RSA_KEY_LEN);
        // if (aes_key_length != AES_KEY_LEN)
        // {
        //     return NF_ACCEPT;
        // }
        // memcpy(aes_key_server, aes_key, AES_KEY_LEN);
        // aes_crypto(dns_data + RSA_KEY_LEN, out_data, aes_key, dns_length-RSA_KEY_LEN, DATA_DECRYPT);
        // dns_length = aes_rm_padding(&out_data, dns_length-RSA_KEY_LEN);
        // memcpy(dns_data, out_data, dns_length);   
    }
    else if (dns_type(udp, message) == DNS_PACKET_RESPONSE)
    {
        // aes_key = aes_key_client;
        // aes_crypto(dns_data, out_data, aes_key, dns_length, DATA_DECRYPT);
        // dns_length = aes_rm_padding(&out_data, dns_length);
        // memcpy(dns_data, out_data, dns_length);
    }
    else
    {
        return NF_ACCEPT;
    }

    update_check_sum(ip, udp, dns_data, dns_data, out_data, message);

    sprintf(message, "a new modified dns income packet");
    // log_message("Accept", LOGGER_OK, message);
    return NF_ACCEPT;
}

unsigned int dns_out_func(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
{
    char message[128];
    struct sk_buff *nskb;
    struct iphdr *ip;
    struct udphdr *udp;
    char aes_key[32];
    char *dns_data, *out_data;
    int dns_length, secret_length, out_length = 0;

    ip = ip_hdr(skb);
    udp = (struct udphdr *)(ip + 1);

    if (is_dns(skb, ip, udp, message) == DNS_PACKET_NO)
    {
        return NF_ACCEPT;
    }

    dns_data = (char *)(udp + 1);
    dns_length = sizeof(dns_data);
    out_data = kzalloc(PAGE_SIZE, GFP_KERNEL);

    if (dns_type(udp, message) == DNS_PACKET_QUERY)
    {
        // initialize and store the key used by aes encrytion
        get_random_bytes(&aes_key, AES_KEY_LEN);
        // pr_info("aes key generated: ");
        // hexdump(aes_key, AES_KEY_LEN);
        memcpy(aes_key_client, aes_key, AES_KEY_LEN);
        // pr_info("aes key stored: ");
        // hexdump(aes_key_client, AES_KEY_LEN);
        // hexdump(pub_key, pub_key_len);
        rsa_crypto(aes_key, AES_KEY_LEN, out_data, DATA_ENCRYPT);
        // pr_info("aes key enctypted");
        // hexdump(out_data, RSA_KEY_LEN);
        secret_length = aes_add_padding(&dns_data, dns_length);
        // pr_info("aes key enctypted");
        aes_crypto(dns_data, out_data + RSA_KEY_LEN, aes_key, secret_length, DATA_ENCRYPT);

        out_length = secret_length + RSA_KEY_LEN;
        nskb = skb_update_data(skb, dns_data, out_data, dns_length, out_length);
        // nskb->dev = my_net_device;
        // pr_info("ready to send new packet");
        // netif_rx(nskb);
        // pr_info("drop a dns query packet");
        return NF_DROP;
    }
    else if (dns_type(udp, message) == DNS_PACKET_RESPONSE)
    {
        // initialize and store the key used by aes encrytion
        // aes_key = aes_key_server;

        // out_data = kzalloc(PAGE_SIZE, GFP_KERNEL);
        // secret_length = aes_add_padding(&dns_data, dns_length);
        // aes_crypto(dns_data, out_data, aes_key, secret_length, DATA_ENCRYPT);
        
        // memcpy(dns_data, out_data, secret_length);
    }
    else
    {
        return NF_ACCEPT;
    }

    memcpy(dns_data, out_data, out_length);
    update_check_sum(ip, udp, dns_data, dns_length, out_length, message); 

    // sprintf(message, "%x   %x", ntohs(dns_data[0]), ntohs(dns_data[1]));
    // log_message("Identify", LOGGER_OK, message);

    // sprintf(message, "a new modified dns outcome packet");
    // log_message("Accept", LOGGER_OK, message);
    pr_info("release a packet");
    return NF_ACCEPT;
}

static int __init hook_init(void)
{
    int ret = 0;
    struct net *n;
    char message[128];

    // init_writer();

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
    // log_message("Hook init", LOGGER_OK, message);

    return ret;
}

static void __exit hook_exit(void)
{
    struct net *n;

    // log_message("Hook exit", LOGGER_OK, "Hook deinit");

    for_each_net(n) nf_unregister_net_hook(n, &nfho_dns_in);
    for_each_net(n) nf_unregister_net_hook(n, &nfho_dns_out);

    // close_writer();
}


module_init(hook_init);
module_exit(hook_exit);

MODULE_LICENSE("Dual MIT/GPL");
MODULE_AUTHOR("Dracula1998");
//========================Kernel Module Implementation==END================================
