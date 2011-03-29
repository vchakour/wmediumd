/*
 * Path Selection Daemon for open80211s
 * Copyright (c) 2010, cozybit Inc.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * See README and COPYING for more details.
 */

#include <unistd.h>
#include <sys/select.h>
#include <stdlib.h>
#include <string.h>
#include "o11s-wmediumd.h"
#include "nl80211.h"
#include "netlink.h"

// Runtime config variables
static fd_set rd_sock_set;
static fd_set wr_sock_set;
static int max_fds;
static char *ifname = NULL;

static struct mac80211_hwsim_tx_header status;
static char data[3000];

static void usage(void)
{
	printf("%s\n\n"
	       "usage:\n"
	       "  o11s_wmediumd \n\n", o11s_wmediumd_version);
}

int register_read_socket(int sock)
{
	FD_SET(sock, &rd_sock_set);
	max_fds = (sock >= max_fds) ? sock + 1 : max_fds;
}


static int send_testmode_init(uint32_t wiphy)
{
        struct nl_msg *msg;
        uint8_t cmd = NL80211_CMD_TESTMODE;
        int ret;
	char *pret;

        msg = nlmsg_alloc();
        if (!msg)
                return -ENOMEM;

	pret = genlmsg_put(msg, 0, 0,
		genl_family_get_id(nlcfg.nl80211), 0, 0, cmd, 0);

	if (pret == NULL)
		goto nla_put_failure;

	NLA_PUT_U32(msg, NL80211_ATTR_WIPHY, wiphy);
	{
		struct nlattr *container = nla_nest_start(msg,
				NL80211_ATTR_TESTDATA);

		if (!container)
			return -ENOBUFS;

		NLA_PUT_U32(msg, HWSIM_TM_ATTR_CMD, HWSIM_TM_CMD_REGISTER);
		NLA_PUT_U32(msg, HWSIM_TM_ATTR_REGISTER, 1);
		nla_nest_end(msg, container);
	}

        ret = send_and_recv_msgs(msg, NULL, NULL);
	if (ret)
		printf("send failed: %d (%s)\n", ret, strerror(-ret));

        return ret;

 nla_put_failure:
        return -ENOBUFS;
}


static int send_frame(uint32_t wiphy, void *header, uint32_t size, void *frame, uint32_t length)
{
	struct nl_msg *msg;
	uint8_t cmd = NL80211_CMD_TESTMODE;
	int ret;
	char *pret;

	if (NULL == header || size < sizeof(struct mac80211_hwsim_tx_header))
		return -ENOMEM;

	msg = nlmsg_alloc();
	if (!msg)
		return -ENOMEM;

	pret = genlmsg_put(msg, 0, 0,
	genl_family_get_id(nlcfg.nl80211), 0, 0, cmd, 0);

	if (pret == NULL)
		goto nla_put_failure;

	NLA_PUT_U32(msg, NL80211_ATTR_WIPHY, wiphy);
	{
		struct nlattr *container = nla_nest_start(msg,
				NL80211_ATTR_TESTDATA);

		if (!container)
			return -ENOBUFS;

		NLA_PUT_U32(msg, HWSIM_TM_ATTR_CMD, HWSIM_TM_CMD_FRAME);
		NLA_PUT(msg, HWSIM_TM_ATTR_STATUS, size, header);
		if (NULL != frame)
			NLA_PUT(msg, HWSIM_TM_ATTR_FRAME, length, frame);

		nla_nest_end(msg, container);
	}

	ret = send_and_recv_msgs(msg, NULL, NULL);

	if (ret)
		printf("send frame failed: %d (%s)\n", ret, strerror(-ret));

	return ret;

nla_put_failure:
	return -ENOBUFS;
}


static int receive_frame(uint32_t wiphy, void *header, uint32_t size, void *frame, uint32_t length)
{
        struct mac80211_hwsim_tx_header *hdr = header;
        int ret;

        if (NULL == header || size < sizeof(struct mac80211_hwsim_tx_header)) {
                printf("frame header missing /small: %p %d\n", header, size);
                return send_testmode_init(1);
        }

        memcpy(&status, header, size);
        memcpy(data, frame, length);

        return send_frame(wiphy, &status, size, data, length);
}


static int event_handler(struct nl_msg *msg, void *arg)
{
	struct genlmsghdr *gnlh = nlmsg_data(nlmsg_hdr(msg));
	struct nlattr *tb[NL80211_ATTR_MAX + 1];
	struct nlattr *wtb[HWSIM_TM_ATTR_MAX + 1];
	int cmd = gnlh->cmd, attr;
	uint32_t size = 0, length = 0, wiphy = 0, data = 0;
	void *frame = NULL, *header = NULL;

        nla_parse(tb, NL80211_ATTR_MAX, genlmsg_attrdata(gnlh, 0),
                  genlmsg_attrlen(gnlh, 0), NULL);

	switch (gnlh->cmd) {
		case NL80211_CMD_TESTMODE:
//			printf("NL80211_CMD_TESTMODE:\n");

			if (tb[NL80211_ATTR_WIPHY]) {
				wiphy = nla_get_u32(tb[NL80211_ATTR_WIPHY]);
//				printf("NL80211_ATTR_WIPHY: %d \n", data);
			}
			if (!tb[NL80211_ATTR_TESTDATA])
				break;
//			printf("NL80211_ATTR_TESTDATA: \n");

			nla_parse_nested(wtb, HWSIM_TM_ATTR_MAX,
				tb[NL80211_ATTR_TESTDATA], NULL);
			
			// HWSIM_TM_CMD_FRAME:
			if (wtb[HWSIM_TM_ATTR_FRAME]) {
				frame = nla_data(wtb[HWSIM_TM_ATTR_FRAME]);
				length = nla_len(wtb[HWSIM_TM_ATTR_FRAME]);
//				printf("HWSIM_TM_ATTR_FRAME: len=%d\n", length);
			}
			// HWSIM_TM_CMD_FRAME:
			if (wtb[HWSIM_TM_ATTR_STATUS]) {
				header = nla_data(wtb[HWSIM_TM_ATTR_STATUS]);
				size = nla_len(wtb[HWSIM_TM_ATTR_STATUS]);
//				printf("HWSIM_TM_ATTR_STATUS: len=%d\n", size);
				receive_frame(wiphy, (void*)header, size, (void*)frame, length);
				break;
			}
			// HWSIM_TM_CMD_REGISTER: 
			if (wtb[HWSIM_TM_ATTR_REGISTER]) {
				data = nla_get_u32(wtb[HWSIM_TM_ATTR_REGISTER]);
//				printf("HWSIM_TM_ATTR_REGISTER: %d\n", data);
			}
			break;

		default:
			printf("Ignored gnlh->cmd: %d, %x\n", gnlh->cmd, gnlh->cmd);
			break;
		}
	return NL_SKIP;
}


int wait_on_sockets()
{
	int retval;
	int s1, s2;
	while (1) {
		// s1 = nl_socket_get_fd(nlcfg.nl_sock_event);
		s2 = nl_socket_get_fd(nlcfg.nl_sock);
		max_fds = ( s1 > s2 ) ? s1 + 1 : s2 + 1;
		// FD_SET(s1, &rd_sock_set);
		FD_SET(s2, &rd_sock_set);
		retval = select(max_fds, &rd_sock_set, &wr_sock_set, NULL, NULL);
		//if (FD_ISSET(s1, &rd_sock_set)) {
        	//	nl_recvmsgs_default(nlcfg.nl_sock_event);
		//}
		if (FD_ISSET(s2, &rd_sock_set))
        		nl_recvmsgs_default(nlcfg.nl_sock);
	}
}


int main(int argc, char *argv[])
{
	int c;
	int exitcode = 0;

	FD_ZERO(&rd_sock_set);
	FD_ZERO(&wr_sock_set);
	max_fds = 0;

	for (;;) {
		c = getopt(argc, argv, "Bi:s:");
		if (c < 0)
			break;
		switch (c) {
		case 'B':
			/* TODO: background operation */
			break;
		case 'i':
			break;
		case 's':
			break;
		default:
			usage();
			goto out;
		}
	}

	if (netlink_init(event_handler)) {
		exitcode = -ESOCKTNOSUPPORT;
		goto out;
	}

	printf("\nWmediumd started successfully\n");
	send_testmode_init(0);
	wait_on_sockets();

out:
	if (exitcode)
		printf("\nWmediumd start failed: %d (%s)\n", exitcode,
			strerror(-exitcode));
	return exitcode;
}
