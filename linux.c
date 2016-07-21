/* Linux backend
 *
 * Copyright (C) 2008-2010  Robert Ernst <robert.ernst@linux-solutions.at>
 *
 * This file may be distributed and/or modified under the terms of the
 * GNU General Public License version 2 as published by the Free Software
 * Foundation and appearing in the file LICENSE.GPL included in the
 * packaging of this file.
 *
 * This file is provided AS IS with NO WARRANTY OF ANY KIND, INCLUDING THE
 * WARRANTY OF DESIGN, MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE.
 *
 * See COPYING for GPL licensing information.
 */
#ifdef __linux__

#include <sys/sysinfo.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/vfs.h>
#include <net/if.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <syslog.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <ctype.h>
#include <time.h>
#include <math.h>
#include <sys/stat.h>


#include "mini_snmpd.h"


/* We need the uptime in 1/100 seconds, so we can't use sysinfo() */
unsigned int get_process_uptime(void)
{
#ifndef NDM
	static unsigned int uptime_start = 0;
#endif
	unsigned int uptime_now = get_system_uptime();

#ifndef NDM
	if (uptime_start == 0)
		uptime_start = uptime_now;

	return uptime_now - uptime_start;
#endif
	return uptime_now;
}

/* We need the uptime in 1/100 seconds, so we can't use sysinfo() */
unsigned int get_system_uptime(void)
{
	char buf[128];

	if (read_file("/proc/uptime", buf, sizeof(buf)) == -1)
		return -1;

	return (unsigned int)(atof(buf) * 100);
}

void get_loadinfo(loadinfo_t *loadinfo)
{
	int i;
	char buf[128];
	char *ptr;

	if (read_file("/proc/loadavg", buf, sizeof(buf)) == -1) {
		memset(loadinfo, 0, sizeof(loadinfo_t));
		return;
	}

	ptr = buf;
	for (i = 0; i < 3; i++) {
		while (isspace(*ptr))
			ptr++;

		if (*ptr != 0)
			loadinfo->avg[i] = strtod(ptr, &ptr) * 100;
	}
}

void get_meminfo(meminfo_t *meminfo)
{
	field_t fields[] = {
		{ "MemTotal",  1, { &meminfo->total   }},
		{ "MemFree",   1, { &meminfo->free    }},
		{ "MemShared", 1, { &meminfo->shared  }},
		{ "Buffers",   1, { &meminfo->buffers }},
		{ "Cached",    1, { &meminfo->cached  }},
		{ NULL,        0, { NULL              }}
	};

	if (parse_file("/proc/meminfo", fields, 255))
		memset(meminfo, 0, sizeof(meminfo_t));
}

void get_cpuinfo(cpuinfo_t *cpuinfo)
{
	field_t fields[] = {
		{ "cpu ",  4, { &cpuinfo->user, &cpuinfo->nice, &cpuinfo->system, &cpuinfo->idle }},
		{ "intr ", 1, { &cpuinfo->irqs   }},
		{ "ctxt ", 1, { &cpuinfo->cntxts }},
		{ NULL,    0, { NULL             }}
	};

	if (parse_file("/proc/stat", fields, 255))
		memset(cpuinfo, 0, sizeof(cpuinfo_t));
}

void get_diskinfo(diskinfo_t *diskinfo)
{
	size_t i;
	struct statfs fs;
	struct stat st;

	memset(diskinfo, 0, sizeof(diskinfo_t));

	for (i = 0; i < g_disk_list_length; i++) {
		if (!stat(g_disk_list[i], &st)) {
			if (!S_ISDIR(st.st_mode)) {
				continue;
			}
		} else {
			continue;
		}

		if (statfs(g_disk_list[i], &fs) == -1) {
			diskinfo->total[i]               = 0;
			diskinfo->free[i]                = 0;
			diskinfo->used[i]                = 0;
			diskinfo->blocks_used_percent[i] = 0;
			diskinfo->inodes_used_percent[i] = 0;
			continue;
		}

		diskinfo->total[i] = ((float)fs.f_blocks * fs.f_bsize) / 1024;
		diskinfo->free[i]  = ((float)fs.f_bfree  * fs.f_bsize) / 1024;
		diskinfo->used[i]  = ((float)(fs.f_blocks - fs.f_bfree) * fs.f_bsize) / 1024;
		diskinfo->blocks_used_percent[i] =
			((float)(fs.f_blocks - fs.f_bfree) * 100 + fs.f_blocks - 1) / fs.f_blocks;
		if (fs.f_files <= 0)
			diskinfo->inodes_used_percent[i] = 0;
		else
			diskinfo->inodes_used_percent[i] =
				((float)(fs.f_files - fs.f_ffree) * 100 + fs.f_files - 1) / fs.f_files;
	}
}

#ifdef NDM
static void get_netinfo_loopback(netinfo_t *netinfo)
{
	int fd = socket(AF_INET, SOCK_DGRAM, 0);
	struct ifreq ifreq;
	field_t fields;

	memset(&fields, 0, sizeof(field_t));

	fields.prefix    = strdup("lo");
	fields.len       = 12;
	fields.value[0]  = &netinfo->rx_bytes[NDM_LOOPBACK_INDEX_];
	fields.value[1]  = &netinfo->rx_packets[NDM_LOOPBACK_INDEX_];
	fields.value[2]  = &netinfo->rx_errors[NDM_LOOPBACK_INDEX_];
	fields.value[3]  = &netinfo->rx_drops[NDM_LOOPBACK_INDEX_];
	fields.value[8]  = &netinfo->tx_bytes[NDM_LOOPBACK_INDEX_];
	fields.value[9]  = &netinfo->tx_packets[NDM_LOOPBACK_INDEX_];
	fields.value[10] = &netinfo->tx_errors[NDM_LOOPBACK_INDEX_];
	fields.value[11] = &netinfo->tx_drops[NDM_LOOPBACK_INDEX_];

	snprintf(ifreq.ifr_name, sizeof(ifreq.ifr_name), "lo");
	if (fd == -1 || ioctl(fd, SIOCGIFFLAGS, &ifreq) == -1) {
		netinfo->status[NDM_LOOPBACK_INDEX_] = 4;
	} else {
		if (ifreq.ifr_flags & IFF_UP)
			netinfo->status[NDM_LOOPBACK_INDEX_] = (ifreq.ifr_flags & IFF_RUNNING) ? 1 : 7;
		else
			netinfo->status[NDM_LOOPBACK_INDEX_] = 2;
	}

	netinfo->admin_status[NDM_LOOPBACK_INDEX_] = 1; // up
	netinfo->mtu[NDM_LOOPBACK_INDEX_] = g_interface_mtu[NDM_LOOPBACK_INDEX_];

	if (fd != -1)
		close(fd);

	if (parse_file("/proc/net/dev", &fields, 1))
		memset(netinfo, 0, sizeof(*netinfo));

	free(fields.prefix);
}


void get_netinfo(netinfo_t *netinfo)
{
	size_t i;

	memset(netinfo, 0, sizeof(netinfo_t));

	get_netinfo_loopback(netinfo);

	for (i = 0; i < g_interface_list_length; ++i) {
		char request[128];

		if( !strcmp(g_interface_list[i], NDM_LOOPBACK_IFACE_) )
		{
			continue;
		}

		/* Perform first 'show interface Iface0' request */

		snprintf(request, sizeof(request), "show interface %s", g_interface_list[i]);

		if ((g_ndmresp = ndm_core_request(g_ndmcore,
				NDM_CORE_REQUEST_PARSE, NDM_CORE_MODE_CACHE, NULL,
				request)) == NULL)
		{
			lprintf(LOG_ERR, "(%s:%d) ndm request failed: %s", __FILE__, __LINE__, strerror(errno));
			ndm_core_response_free(&g_ndmresp);

			return;
		}

		if (!ndm_core_response_is_ok(g_ndmresp)) {
			lprintf(LOG_ERR, "(%s:%d) ndm response is invalid", __FILE__, __LINE__);
			ndm_core_response_free(&g_ndmresp);

			return;
		} else
		{
			const struct ndm_xml_node_t* root = ndm_core_response_root(g_ndmresp);

			if (root == NULL) {
				lprintf(LOG_ERR, "(%s:%d) null ndm response", __FILE__, __LINE__);
				ndm_core_response_free(&g_ndmresp);

				return;
			} else {
				if( ndm_xml_node_type(root) == NDM_XML_NODE_TYPE_ELEMENT )
				{
					if( !strcmp(ndm_xml_node_name(root), "response") )
					{
						const struct ndm_xml_node_t* node =
							ndm_xml_node_first_child(root, NULL);
						int admin_status = 2; // down
						int ilink = 0;
						int connected = 0;
						int imtu = NDM_MIN_MTU_;

						while (node != NULL) {
							if( !strcmp(ndm_xml_node_name(node), "id") &&
								!strcmp(ndm_xml_node_name(node), g_interface_list[i]) )
							{
								lprintf(LOG_ERR, "(%s:%d) invalid interface returned", __FILE__, __LINE__);
								ndm_core_response_free(&g_ndmresp);

								return;
							}

							if( !strcmp(ndm_xml_node_name(node), "type") &&
								!strcmp(ndm_xml_node_value(node), "Port") )
							{
								imtu = NDM_ETH_MTU_;
								admin_status = 1; // up
								connected = 1; // connected
							}

							if( !strcmp(ndm_xml_node_name(node), "state") &&
								!strcmp(ndm_xml_node_value(node), "up") )
							{
								admin_status = 1; // up
							}

							if( !strcmp(ndm_xml_node_name(node), "link") &&
								!strcmp(ndm_xml_node_value(node), "up") )
							{
								ilink = 1;
							}

							if( !strcmp(ndm_xml_node_name(node), "connected") &&
								!strcmp(ndm_xml_node_value(node), "yes") )
							{
								connected = 1;
							}

							if( !strcmp(ndm_xml_node_name(node), "speed") )
							{
								long speed = atol(ndm_xml_node_value(node));

								if (speed >= 10 && speed <= 1000)
								{
									netinfo->speed[i] = speed * 1000 * 1000;
								}
							}

							if( !strcmp(ndm_xml_node_name(node), "last-change") )
							{
								double timef = atof(ndm_xml_node_value(node));
								long timel = timef * 100;

								if( timel >= 0 && timel <= INT_MAX )
								{
									netinfo->last_change[i] = timel;
								}
							}

							if( !strcmp(ndm_xml_node_name(node), "mtu") )
							{
								long lmtu = atol(ndm_xml_node_value(node));

								if( lmtu >= NDM_MIN_MTU_ && lmtu <= NDM_MAX_MTU_ && imtu == NDM_MIN_MTU_ )
								{
									imtu = lmtu;
								}
							}

							node = ndm_xml_node_next_sibling(node, NULL);
						}

						netinfo->mtu[i] = imtu;
						netinfo->admin_status[i] = admin_status;

						if( ilink == 1 && connected == 1 ) {
							netinfo->status[i] = 1; // up
						} else {
							netinfo->status[i] = 2; // down
						}
					}
				}
			}
		}
		ndm_core_response_free(&g_ndmresp);

		/* Perform second 'show interface Iface0 stat' request */

		snprintf(request, sizeof(request), "show interface %s stat", g_interface_list[i]);

		if ((g_ndmresp = ndm_core_request(g_ndmcore,
				NDM_CORE_REQUEST_PARSE, NDM_CORE_MODE_CACHE, NULL,
				request)) == NULL)
		{
			lprintf(LOG_ERR, "(%s:%d) ndm request failed: %s", __FILE__, __LINE__, strerror(errno));
			ndm_core_response_free(&g_ndmresp);

			return;
		}

		if (!ndm_core_response_is_ok(g_ndmresp)) {
			lprintf(LOG_ERR, "(%s:%d) ndm response is invalid", __FILE__, __LINE__);
			ndm_core_response_free(&g_ndmresp);

			return;
		} else
		{
			const struct ndm_xml_node_t* root = ndm_core_response_root(g_ndmresp);

			if (root == NULL) {
				lprintf(LOG_ERR, "(%s:%d) null ndm response", __FILE__, __LINE__);
				ndm_core_response_free(&g_ndmresp);

				return;
			} else {
				if( ndm_xml_node_type(root) == NDM_XML_NODE_TYPE_ELEMENT )
				{
					if( !strcmp(ndm_xml_node_name(root), "response") )
					{
						const struct ndm_xml_node_t* node =
							ndm_xml_node_first_child(root, NULL);

						while (node != NULL) {

							if( !strcmp(ndm_xml_node_name(node), "rxpackets") )
							{
								long long rxp = atoll(ndm_xml_node_value(node));

								if( rxp >= 0 )
								{
									netinfo->rx_packets[i] = rxp % UINT_MAX;
								}
							}

							if( !strcmp(ndm_xml_node_name(node), "rxbytes") )
							{
								long long rxb = atoll(ndm_xml_node_value(node));

								if( rxb >= 0 )
								{
									netinfo->rx_bytes[i] = rxb % UINT_MAX;
								}
							}

							if( !strcmp(ndm_xml_node_name(node), "rxerrors") )
							{
								long long rxe = atoll(ndm_xml_node_value(node));

								if( rxe >= 0 )
								{
									netinfo->rx_errors[i] = rxe % UINT_MAX;
								}
							}

							if( !strcmp(ndm_xml_node_name(node), "rxdropped") )
							{
								long long rxd = atoll(ndm_xml_node_value(node));

								if( rxd >= 0 )
								{
									netinfo->rx_drops[i] = rxd % UINT_MAX;
								}
							}

							if( !strcmp(ndm_xml_node_name(node), "txpackets") )
							{
								long long txp = atoll(ndm_xml_node_value(node));

								if( txp >= 0 )
								{
									netinfo->tx_packets[i] = txp % UINT_MAX;
								}
							}

							if( !strcmp(ndm_xml_node_name(node), "txbytes") )
							{
								long long txb = atoll(ndm_xml_node_value(node));

								if( txb >= 0 )
								{
									netinfo->tx_bytes[i] = txb % UINT_MAX;
								}
							}

							if( !strcmp(ndm_xml_node_name(node), "txerrors") )
							{
								long long txe = atoll(ndm_xml_node_value(node));

								if( txe >= 0 )
								{
									netinfo->tx_errors[i] = txe % UINT_MAX;
								}
							}

							if( !strcmp(ndm_xml_node_name(node), "txdropped") )
							{
								long long txd = atoll(ndm_xml_node_value(node));

								if( txd >= 0 )
								{
									netinfo->tx_drops[i] = txd % UINT_MAX;
								}
							}

							node = ndm_xml_node_next_sibling(node, NULL);
						}
					}
				}
			}
		}
		ndm_core_response_free(&g_ndmresp);
	}
}
#else
void get_netinfo(netinfo_t *netinfo)
{
	int fd = socket(AF_INET, SOCK_DGRAM, 0);
	size_t i;
	struct ifreq ifreq;
	field_t fields[MAX_NR_INTERFACES + 1];

	memset(fields, 0, (MAX_NR_INTERFACES + 1) * sizeof(field_t));
	for (i = 0; i < g_interface_list_length; i++) {
		fields[i].prefix    = g_interface_list[i];
		fields[i].len       = 12;
		fields[i].value[0]  = &netinfo->rx_bytes[i];
		fields[i].value[1]  = &netinfo->rx_packets[i];
		fields[i].value[2]  = &netinfo->rx_errors[i];
		fields[i].value[3]  = &netinfo->rx_drops[i];
		fields[i].value[8]  = &netinfo->tx_bytes[i];
		fields[i].value[9]  = &netinfo->tx_packets[i];
		fields[i].value[10] = &netinfo->tx_errors[i];
		fields[i].value[11] = &netinfo->tx_drops[i];

		snprintf(ifreq.ifr_name, sizeof(ifreq.ifr_name), "%s", g_interface_list[i]);
		if (fd == -1 || ioctl(fd, SIOCGIFFLAGS, &ifreq) == -1) {
			netinfo->status[i] = 4;
			continue;
		}

		if (ifreq.ifr_flags & IFF_UP)
			netinfo->status[i] = (ifreq.ifr_flags & IFF_RUNNING) ? 1 : 7;
		else
			netinfo->status[i] = 2;
	}
	if (fd != -1)
		close(fd);

	if (parse_file("/proc/net/dev", fields, 255))
		memset(netinfo, 0, sizeof(*netinfo));
}
#endif

#endif /* __linux__ */

/* vim: ts=4 sts=4 sw=4 nowrap
 */
