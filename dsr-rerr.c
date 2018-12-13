/* Copyright (C) Uppsala University
 *
 * This file is distributed under the terms of the GNU general Public
 * License (GPL), see the file LICENSE
 *
 * Author: Erik Nordström, <erikn@it.uu.se>
 */
#ifdef __KERNEL__
#include "dsr-dev.h"
#endif

#ifdef NS2
#include "ns-agent.h"
#endif

#include "dsr.h"
#include "dsr-rerr.h"
#include "dsr-opt.h"
#include "debug.h"
#include "dsr-srt.h"
#include "dsr-ack.h"
#include "link-cache.h"
#include "maint-buf.h"

static struct dsr_rerr_opt *dsr_rerr_opt_add(char *buf, int len,
					     int err_type,
					     struct in_addr err_src,
					     struct in_addr err_dst,
					     struct in_addr unreach_addr,
					     int salv)
{
	struct dsr_rerr_opt *rerr_opt;

	if (!buf || len < (int)DSR_RERR_HDR_LEN)
		return NULL;

	rerr_opt = (struct dsr_rerr_opt *)buf;

	rerr_opt->type = DSR_OPT_RERR;
	rerr_opt->length = DSR_RERR_OPT_LEN;
	rerr_opt->err_type = err_type;
	rerr_opt->err_src = err_src.s_addr;
	rerr_opt->err_dst = err_dst.s_addr;
	rerr_opt->res = 0;
	rerr_opt->salv = salv;

	switch (err_type) {
	case NODE_UNREACHABLE:
		if (len < (int)(DSR_RERR_HDR_LEN + sizeof(struct in_addr)))
			return NULL;
		rerr_opt->length += sizeof(struct in_addr);
		memcpy(rerr_opt->info, &unreach_addr, sizeof(struct in_addr));
		break;
	case FLOW_STATE_NOT_SUPPORTED:
		break;
	case OPTION_NOT_SUPPORTED:
		break;
	}

	return rerr_opt;
}

int NSCLASS dsr_rerr_send(struct dsr_pkt *dp_trigg, struct in_addr unr_addr)/*dp_trigg和unr_addr，
分别指代转发出错的数据分组和无法到达的节点地址。函数执行成功返回0，不成功返回-1。*/
{
	struct dsr_pkt *dp;
	struct dsr_rerr_opt *rerr_opt;
	struct in_addr dst, err_src, err_dst, myaddr;
	char *buf;
	int n, len, i;

	myaddr = my_addr();

	if (!dp_trigg || dp_trigg->src.s_addr == myaddr.s_addr)
		return -1;

	if (!dp_trigg->srt_opt) {
		DEBUG("Could not find source route option\n");
		return -1;
	}

	if (dp_trigg->srt_opt->salv == 0)
		dst = dp_trigg->src;
	else
		dst.s_addr = dp_trigg->srt_opt->addrs[1];

	dp = dsr_pkt_alloc(NULL);

	if (!dp) {
		DEBUG("Could not allocate DSR packet\n");
		return -1;
	}

	dp->srt = dsr_rtc_find(myaddr, dst);

	if (!dp->srt) {
		DEBUG("No source route to %s\n", print_ip(dst));
		return -1;
	}

	len = DSR_OPT_HDR_LEN + DSR_SRT_OPT_LEN(dp->srt) + 
		(DSR_RERR_HDR_LEN + 4) + 
		DSR_ACK_HDR_LEN * dp_trigg->num_ack_opts;
	
	/* Also count in RERR opts in trigger packet */
	for (i = 0; i < dp_trigg->num_rerr_opts; i++) {
		if (dp_trigg->rerr_opt[i]->salv > ConfVal(MAX_SALVAGE_COUNT))
			break;

		len += (dp_trigg->rerr_opt[i]->length + 2);
	}
	
	DEBUG("opt_len=%d SR: %s\n", len, print_srt(dp->srt));
	n = dp->srt->laddrs / sizeof(struct in_addr);
	dp->src = myaddr;
	dp->dst = dst;
	dp->nxt_hop = dsr_srt_next_hop(dp->srt, n);

	dp->nh.iph = dsr_build_ip(dp, dp->src, dp->dst, IP_HDR_LEN,
				  IP_HDR_LEN + len, IPPROTO_DSR, IPDEFTTL);

	if (!dp->nh.iph) {
		DEBUG("Could not create IP header\n");
		goto out_err;
	}

	buf = dsr_pkt_alloc_opts(dp, len);

	if (!buf)
		goto out_err;

	dp->dh.opth = dsr_opt_hdr_add(buf, len, DSR_NO_NEXT_HDR_TYPE);

	if (!dp->dh.opth) {
		DEBUG("Could not create DSR options header\n");
		goto out_err;
	}

	buf += DSR_OPT_HDR_LEN;
	len -= DSR_OPT_HDR_LEN;

	dp->srt_opt = dsr_srt_opt_add(buf, len, 0, 0, dp->srt);

	if (!dp->srt_opt) {
		DEBUG("Could not create Source Route option header\n");
		goto out_err;
	}

	buf += DSR_SRT_OPT_LEN(dp->srt);
	len -= DSR_SRT_OPT_LEN(dp->srt);

	rerr_opt = dsr_rerr_opt_add(buf, len, NODE_UNREACHABLE, dp->src, 
				    dp->dst, unr_addr, 
				    dp_trigg->srt_opt->salv);

	if (!rerr_opt)
		goto out_err;

	buf += (rerr_opt->length + 2);
	len -= (rerr_opt->length + 2);

	/* Add old RERR options */
	for (i = 0; i < dp_trigg->num_rerr_opts; i++) {

		if (dp_trigg->rerr_opt[i]->salv > ConfVal(MAX_SALVAGE_COUNT))
			break;

		memcpy(buf, dp_trigg->rerr_opt[i], 
		       dp_trigg->rerr_opt[i]->length + 2);

		len -= (dp_trigg->rerr_opt[i]->length + 2);
		buf += (dp_trigg->rerr_opt[i]->length + 2);
	}

	/* TODO: Must preserve order of RERR and ACK options from triggering
	 * packet */

	/* Add old ACK options */
	for (i = 0; i < dp_trigg->num_ack_opts; i++) {
		memcpy(buf, dp_trigg->ack_opt[i], 
		       dp_trigg->ack_opt[i]->length + 2);

		len -= (dp_trigg->ack_opt[i]->length + 2);
		buf += (dp_trigg->ack_opt[i]->length + 2);
	}

	err_src.s_addr = rerr_opt->err_src;
	err_dst.s_addr = rerr_opt->err_dst;

	DEBUG("Send RERR err_src %s err_dst %s unr_dst %s\n",
	      print_ip(err_src),
	      print_ip(err_dst), 
	      print_ip(*((struct in_addr *)rerr_opt->info)));

	XMIT(dp);

	return 0;

 out_err:

	dsr_pkt_free(dp);

	return -1;

}/*当节点向下一个节点多次转发数据分组后仍然没有收到下一节点的ack确认信息时，说明这两个节点之间的链路已经断了，
这时要启动DSR的路由维护机制，该节点调用dsr_reer_send()函数，创建并向这个分组的源节点发送rerr路由错误消息。*/

int NSCLASS dsr_rerr_opt_recv(struct dsr_pkt *dp, struct dsr_rerr_opt *rerr_opt)/*形参分别为：dp和rerr_opt，
分别指代收到的rerr路由错误消息和存放路由错误选项的指针。函数成功执行返回0，不成功返回-1.*/
{
	struct in_addr err_src, err_dst, unr_addr;

	if (!rerr_opt)
		return -1;
	
	dp->rerr_opt[dp->num_rerr_opts++] = rerr_opt;

	switch (rerr_opt->err_type) {
	case NODE_UNREACHABLE:
		err_src.s_addr = rerr_opt->err_src;
		err_dst.s_addr = rerr_opt->err_dst;

		memcpy(&unr_addr, rerr_opt->info, sizeof(struct in_addr));

		DEBUG("NODE_UNREACHABLE err_src=%s err_dst=%s unr=%s\n",
		      print_ip(err_src), print_ip(err_dst), print_ip(unr_addr));

		/* For now we drop all unacked packets... should probably
		 * salvage */
		maint_buf_del_all(err_dst);

		/* Remove broken link from cache */
		lc_link_del(err_src, unr_addr);

		/* TODO: Check options following the RERR option */
/* 		dsr_rtc_del(my_addr(), err_dst); */
		break;
	case FLOW_STATE_NOT_SUPPORTED:
		DEBUG("FLOW_STATE_NOT_SUPPORTED\n");
		break;
	case OPTION_NOT_SUPPORTED:
		DEBUG("OPTION_NOT_SUPPORTED\n");
		break;
	}

	return 0;
}/*当源节点或中间节点收到rerr路由错误消息时，节点调用dsr_rerr_opt_recv()函数对rerr进行处理，
对于节点不可达错误则删除自己的路由缓存中所有包括失效链路的路由。*/
