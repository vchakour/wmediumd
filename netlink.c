/*
 * Path Selection Daemon for open80211s
 * Copyright (c) 2010, cozybit Inc.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * See README and COPYING for more details.
 *
 * Functions from this file have been liberally copied from wpa_supplicant,
 * which is licensed under GPL as well but has the following copyrights:
 *
 *  * Copyright (c) 2002-2010, Jouni Malinen <j@w1.fi>
 *  * Copyright (c) 2003-2004, Instant802 Networks, Inc.
 *  * Copyright (c) 2005-2006, Devicescape Software, Inc.
 *  * Copyright (c) 2007, Johannes Berg <johannes@sipsolutions.net>
 *  * Copyright (c) 2009-2010, Atheros Communications
 */

#include "netlink.h"

struct netlink_config_s nlcfg;

static int ack_handler(struct nl_msg *msg, void *arg)
{
	int *err = arg;
	*err = 0;
	return NL_STOP;
}

static int finish_handler(struct nl_msg *msg, void *arg)
{
	int *ret = arg;
	*ret = 0;
	return NL_SKIP;
}

static int error_handler(struct sockaddr_nl *nla, struct nlmsgerr *err,
		void *arg)
{
	int *ret = arg;
	*ret = err->error;
	return NL_SKIP;
}

static int no_seq_check(struct nl_msg *msg, void *arg)
{
	return NL_OK;
}

static int send_and_recv(struct nl_sock *nl_sock, struct nl_msg *msg,
                         int (*valid_handler)(struct nl_msg *, void *),
                         void *valid_data)
{
        struct nl_cb *cb;
        int err = -ENOMEM;

        cb = nl_cb_clone(nlcfg.nl_cb);
        if (!cb)
                goto out;

        err = nl_send_auto_complete(nl_sock, msg);
        if (err < 0)
                goto out;

        err = 1;

        nl_cb_err(cb, NL_CB_CUSTOM, error_handler, &err);
        nl_cb_set(cb, NL_CB_FINISH, NL_CB_CUSTOM, finish_handler, &err);
        nl_cb_set(cb, NL_CB_ACK, NL_CB_CUSTOM, ack_handler, &err);

        if (valid_handler)
                nl_cb_set(cb, NL_CB_VALID, NL_CB_CUSTOM,
                          valid_handler, valid_data);

        while (err > 0)
                nl_recvmsgs(nl_sock, cb);
 out:
        nl_cb_put(cb);
        nlmsg_free(msg);
        return err;
}

int send_and_recv_msgs(struct nl_msg *msg,
                              int (*valid_handler)(struct nl_msg *, void *),
                              void *valid_data)
{
        return send_and_recv(nlcfg.nl_sock, msg, valid_handler,
                             valid_data);
}

struct family_data {
        const char *group;
        int id;
};

static int family_handler(struct nl_msg *msg, void *arg)
{
        struct family_data *res = arg;
        struct nlattr *tb[CTRL_ATTR_MAX + 1];
        struct genlmsghdr *gnlh = nlmsg_data(nlmsg_hdr(msg));
        struct nlattr *mcgrp;
        int i;

        nla_parse(tb, CTRL_ATTR_MAX, genlmsg_attrdata(gnlh, 0),
                  genlmsg_attrlen(gnlh, 0), NULL);
        if (!tb[CTRL_ATTR_MCAST_GROUPS])
                return NL_SKIP;

        nla_for_each_nested(mcgrp, tb[CTRL_ATTR_MCAST_GROUPS], i) {
                struct nlattr *tb2[CTRL_ATTR_MCAST_GRP_MAX + 1];
                nla_parse(tb2, CTRL_ATTR_MCAST_GRP_MAX, nla_data(mcgrp),
                          nla_len(mcgrp), NULL);
                if (!tb2[CTRL_ATTR_MCAST_GRP_NAME] ||
                    !tb2[CTRL_ATTR_MCAST_GRP_ID] ||
                    strncmp(nla_data(tb2[CTRL_ATTR_MCAST_GRP_NAME]),
                               res->group,
                               nla_len(tb2[CTRL_ATTR_MCAST_GRP_NAME])) != 0)
                        continue;
                res->id = nla_get_u32(tb2[CTRL_ATTR_MCAST_GRP_ID]);
                break;
        };

        return NL_SKIP;
}


static int nl_get_multicast_id(const char *family, const char *group)
{
	struct nl_msg *msg;
	int ret = -1;
	struct family_data res = { group, -ENOENT };

	msg = nlmsg_alloc();
	if (!msg)
		return -ENOMEM;
	genlmsg_put(msg, 0, 0, genl_ctrl_resolve(nlcfg.nl_sock,
		"nlctrl"), 0, 0, CTRL_CMD_GETFAMILY, 0);
	NLA_PUT_STRING(msg, CTRL_ATTR_FAMILY_NAME, family);

	ret = send_and_recv_msgs(msg, family_handler, &res);
	msg = NULL;
	if (ret == 0)
		ret = res.id;

nla_put_failure:
	nlmsg_free(msg);
	return ret;
}


int netlink_init(void *event_handler)
{
	int ret;

	/* Initialize generic netlink and nl80211 */

	nlcfg.nl_cb = nl_cb_alloc(NL_CB_CUSTOM);
	if (nlcfg.nl_cb == NULL) {
		printf("nl80211: Failed to allocate netlink callbacks");
		goto err1;
	}

	nlcfg.nl_sock = nl_socket_alloc_cb(nlcfg.nl_cb);
	if (nlcfg.nl_sock == NULL) {
		printf("nl80211: Failed to allocate netlink callbacks");
		goto err2;
	}

	nlcfg.nl_sock_event = nl_socket_alloc_cb(nlcfg.nl_cb);
	if (nlcfg.nl_sock_event == NULL) {
		printf("nl80211: Failed to allocate netlink callbacks (event)");
		goto err2b;
	}

	if (genl_connect(nlcfg.nl_sock)) {
		printf("nl80211: Failed to connect to generic netlink");
		goto err3;
	}

	if (genl_connect(nlcfg.nl_sock_event)) {
		printf("nl80211: Failed to connect to generic netlink (event)");
		goto err3;
	}

	if (genl_ctrl_alloc_cache(nlcfg.nl_sock, &nlcfg.nl_cache) < 0) {
		printf("nl80211: Failed to allocate generic netlink cache");
		goto err3;
	}

	if (genl_ctrl_alloc_cache(nlcfg.nl_sock_event, &nlcfg.nl_cache_event) <
	    0) {
		printf("nl80211: Failed to allocate generic "
			   "netlink cache (event)");
		goto err3b;
	}

	nlcfg.nl80211 = genl_ctrl_search_by_name(nlcfg.nl_cache, "nl80211");
	if (nlcfg.nl80211 == NULL) {
		printf("nl80211: 'nl80211' generic netlink not "
			   "found");
		goto err4;
	}

	ret = nl_get_multicast_id("nl80211", "testmode");
	if (ret >= 0)
		ret = nl_socket_add_membership(nlcfg.nl_sock_event, ret);
	if (ret < 0) {
		printf("nl80211: Could not add multicast "
			   "membership for testmode events: %d (%s)",
			   ret, strerror(-ret));
		goto err4;
	}

	nl_cb_set(nlcfg.nl_cb, NL_CB_SEQ_CHECK, NL_CB_CUSTOM, no_seq_check,
		NULL);
	nl_cb_set(nlcfg.nl_cb, NL_CB_VALID, NL_CB_CUSTOM, event_handler,
		&nlcfg);

	return 0;

err4:
	nl_cache_free(nlcfg.nl_cache_event);
err3b:
	nl_cache_free(nlcfg.nl_cache);
err3:
	nl_socket_free(nlcfg.nl_sock_event);
err2b:
	nl_socket_free(nlcfg.nl_sock);
err2:
	nl_cb_put(nlcfg.nl_cb);
err1:
	return -1;
}

