/*
 * libwifi-direct
 *
 * Copyright (c) 2000 - 2012 Samsung Electronics Co., Ltd. All rights reserved.
 *
 * Contact: Sungsik Jang <sungsik.jang@samsung.com>, Dongwook Lee <dwmax.lee@samsung.com> 
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */



/*****************************************************************************
 * 	Standard headers
 *****************************************************************************/
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <netdb.h>
#include <sys/socket.h>
#include <string.h>
#include <unistd.h>
#include <sys/un.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <signal.h>
#include <glib.h>
#include <linux/unistd.h>
#include <sys/poll.h>

/*****************************************************************************
 * 	Wi-Fi Direct Service headers
 *****************************************************************************/
#include "wifi-direct.h"
#include "wifi-direct-client-proxy.h"
#include "wifi-direct-internal.h"

/*****************************************************************************
 * 	Macros and Typedefs
 *****************************************************************************/


/*****************************************************************************
 * 	Global Variables
 *****************************************************************************/
wifi_direct_client_info_s g_client_info = {
	.is_registered = FALSE,
	.client_id = -1,
	.sync_sockfd = -1,
	.async_sockfd = -1,
	.activation_cb = NULL,
	.discover_cb = NULL,
	.connection_cb = NULL,
	.user_data_for_cb_activation = NULL,
	.user_data_for_cb_discover = NULL,
	.user_data_for_cb_connection = NULL
};

/*****************************************************************************
 * 	Local Functions Definition
 *****************************************************************************/
static int __wfd_client_read_socket(int sockfd, char *dataptr, int datalen);

#ifdef __NR_gettid
pid_t gettid(void)
{
	return syscall(__NR_gettid);
}
#else
#error "__NR_gettid is not defined, please include linux/unistd.h "
#endif

static wifi_direct_client_info_s *__wfd_get_control()
{
	return &g_client_info;
}

static void __wfd_reset_control()
{

	if (g_client_info.g_source_id > 0)
		g_source_remove(g_client_info.g_source_id);
	g_client_info.g_source_id = -1;

	// Protect standard input / output / error
	if (g_client_info.sync_sockfd > 2)
		close(g_client_info.sync_sockfd);
	g_client_info.sync_sockfd = -1;

	if (g_client_info.async_sockfd > 2)
		close(g_client_info.async_sockfd);
	g_client_info.async_sockfd = -1;

	g_client_info.is_registered = FALSE;

	// Initialize callbacks
	g_client_info.activation_cb = NULL;
	g_client_info.discover_cb = NULL;
	g_client_info.connection_cb = NULL;
	g_client_info.user_data_for_cb_activation = NULL;
	g_client_info.user_data_for_cb_discover = NULL;
	g_client_info.user_data_for_cb_connection = NULL;
}


static int macaddr_atoe(char *p, unsigned char mac[])
{
	int i = 0;

	WFD_CLIENT_LOG(WFD_LOG_LOW, "macaddr_atoe : input MAC = [%s]\n", p);

	for (;;)
	{
		mac[i++] = (char) strtoul(p, &p, 16);
		if (!*p++ || i == 6)
			break;
	}

	return (i == 6);
}


static char *__wfd_print_event(wfd_client_event_e event)
{
	switch (event)
	{
	case WIFI_DIRECT_CLI_EVENT_ACTIVATION:
		return "ACTIVATION";
		break;
	case WIFI_DIRECT_CLI_EVENT_DEACTIVATION:
		return "DEACTIVATION";
		break;
	case WIFI_DIRECT_CLI_EVENT_INVALID:
		return "WIFI_DIRECT_CLI_EVENT_INVALID";
		break;
	case WIFI_DIRECT_CLI_EVENT_DISCOVER_START:
		return "WIFI_DIRECT_CLI_EVENT_DISCOVER_START";
		break;
	case WIFI_DIRECT_CLI_EVENT_DISCOVER_START_LISTEN_ONLY:
		return "WIFI_DIRECT_CLI_EVENT_DISCOVER_START_LISTEN_ONLY";
		break;
	case WIFI_DIRECT_CLI_EVENT_DISCOVER_START_SEARCH_LISTEN:
		return "WIFI_DIRECT_CLI_EVENT_DISCOVER_START_SEARCH_LISTEN";
		break;
	case WIFI_DIRECT_CLI_EVENT_DISCOVER_END:
		return "WIFI_DIRECT_CLI_EVENT_DISCOVER_END";
		break;
	case WIFI_DIRECT_CLI_EVENT_DISCOVER_FOUND_PEERS:
		return "WIFI_DIRECT_CLI_EVENT_DISCOVER_FOUND_PEERS";
		break;

	case WIFI_DIRECT_CLI_EVENT_CONNECTION_REQ:
		return "WIFI_DIRECT_CLI_EVENT_CONNECTION_REQ";
		break;

	case WIFI_DIRECT_CLI_EVENT_CONNECTION_START:
		return "WIFI_DIRECT_CLI_EVENT_CONNECTION_START";
		break;

	case WIFI_DIRECT_CLI_EVENT_CONNECTION_RSP:
		return "WIFI_DIRECT_CLI_EVENT_CONNECTION_RSP";
		break;
	case WIFI_DIRECT_CLI_EVENT_CONNECTION_WPS_REQ:
		return "WIFI_DIRECT_CLI_EVENT_CONNECTION_WPS_REQ";
		break;

	case WIFI_DIRECT_CLI_EVENT_DISCONNECTION_RSP:
		return "WIFI_DIRECT_CLI_EVENT_DISCONNECTION_RSP";
		break;
	case WIFI_DIRECT_CLI_EVENT_DISCONNECTION_IND:
		return "WIFI_DIRECT_CLI_EVENT_DISCONNECTION_IND";
		break;

	case WIFI_DIRECT_CLI_EVENT_GROUP_CREATE_RSP:
		return "WIFI_DIRECT_CLI_EVENT_GROUP_CREATE_RSP";
		break;
	case WIFI_DIRECT_CLI_EVENT_GROUP_DESTROY_RSP:
		return "WIFI_DIRECT_CLI_EVENT_GROUP_DESTROY_RSP";
		break;
	case WIFI_DIRECT_CLI_EVENT_IP_LEASED_IND:
		return "WIFI_DIRECT_CLI_EVENT_IP_LEASED_IND";
		break;

	default:
		return "WIFI_DIRECT_CLI_EVENT_unknown";
		break;
	}
}

static char *__wfd_print_error(wifi_direct_error_e error)
{
	switch (error)
	{
	case WIFI_DIRECT_ERROR_OPERATION_FAILED:
		return "WIFI_DIRECT_ERROR_OPERATION_FAILED";
	case WIFI_DIRECT_ERROR_OUT_OF_MEMORY:
		return "WIFI_DIRECT_ERROR_OUT_OF_MEMORY";
	case WIFI_DIRECT_ERROR_COMMUNICATION_FAILED:
		return "WIFI_DIRECT_ERROR_COMMUNICATION_FAILED";
	case WIFI_DIRECT_ERROR_NOT_PERMITTED:
		return "WIFI_DIRECT_ERROR_NOT_PERMITTED";
	case WIFI_DIRECT_ERROR_INVALID_PARAMETER:
		return "WIFI_DIRECT_ERROR_INVALID_PARAMETER";
	case WIFI_DIRECT_ERROR_NOT_INITIALIZED:
		return "WIFI_DIRECT_ERROR_NOT_INITIALIZED";
	case WIFI_DIRECT_ERROR_TOO_MANY_CLIENT:
		return "WIFI_DIRECT_ERROR_TOO_MANY_CLIENT";
	case WIFI_DIRECT_ERROR_RESOURCE_BUSY:
		return "WIFI_DIRECT_ERROR_RESOURCE_BUSY";
	case WIFI_DIRECT_ERROR_NONE:
		return "WIFI_DIRECT_ERROR_NONE";
	default:
		WFD_CLIENT_LOG(WFD_LOG_LOW, "Invalid error value: [%d]\n", error);
		return "Invalid error";
	}
}

static int __wfd_convert_client_event(wfd_client_event_e event)
{
	__WFD_CLIENT_FUNC_START__;

	switch (event)
	{
	case WIFI_DIRECT_CLI_EVENT_ACTIVATION:
		return WIFI_DIRECT_DEVICE_STATE_ACTIVATED;
		break;
	case WIFI_DIRECT_CLI_EVENT_DEACTIVATION:
		return WIFI_DIRECT_DEVICE_STATE_DEACTIVATED;
		break;

	case WIFI_DIRECT_CLI_EVENT_DISCOVER_START_LISTEN_ONLY:
		return WIFI_DIRECT_ONLY_LISTEN_STARTED;
		break;
	case WIFI_DIRECT_CLI_EVENT_DISCOVER_START:
		return WIFI_DIRECT_DISCOVERY_STARTED;
		break;
	case WIFI_DIRECT_CLI_EVENT_DISCOVER_END:
		return WIFI_DIRECT_DISCOVERY_FINISHED;
		break;
	case WIFI_DIRECT_CLI_EVENT_DISCOVER_FOUND_PEERS:
		return WIFI_DIRECT_DISCOVERY_FOUND;
		break;

	case WIFI_DIRECT_CLI_EVENT_CONNECTION_START:
		return WIFI_DIRECT_CONNECTION_IN_PROGRESS;
		break;
	case WIFI_DIRECT_CLI_EVENT_CONNECTION_REQ:
		return WIFI_DIRECT_CONNECTION_REQ;
		break;
	case WIFI_DIRECT_CLI_EVENT_CONNECTION_RSP:
		return WIFI_DIRECT_CONNECTION_RSP;
		break;
	case WIFI_DIRECT_CLI_EVENT_DISCONNECTION_RSP:
		return WIFI_DIRECT_DISCONNECTION_RSP;
		break;
	case WIFI_DIRECT_CLI_EVENT_CONNECTION_WPS_REQ:
		return WIFI_DIRECT_CONNECTION_WPS_REQ;
		break;
	case WIFI_DIRECT_CLI_EVENT_DISCONNECTION_IND:
		return WIFI_DIRECT_DISCONNECTION_IND;
		break;
	case WIFI_DIRECT_CLI_EVENT_DISASSOCIATION_IND:
		return WIFI_DIRECT_DISASSOCIATION_IND;
		break;
	case WIFI_DIRECT_CLI_EVENT_GROUP_CREATE_RSP:
		return WIFI_DIRECT_GROUP_CREATED;
		break;
	case WIFI_DIRECT_CLI_EVENT_GROUP_DESTROY_RSP:
		return WIFI_DIRECT_GROUP_DESTROYED;
		break;

	default:
		WFD_CLIENT_LOG(WFD_LOG_LOW, "Invalid event : [%d]\n", event);
		break;
	}

	__WFD_CLIENT_FUNC_END__;

}

static gboolean __wfd_client_process_event(GIOChannel * source,
										   GIOCondition condition,
										   gpointer data)
{
	wfd_client_event_e event = WIFI_DIRECT_CLI_EVENT_INVALID;
	wifi_direct_client_info_s *client = __wfd_get_control();
	int sockfd = client->async_sockfd;
	wifi_direct_client_noti_s client_noti;
	wifi_direct_error_e error = WIFI_DIRECT_ERROR_NONE;
	char param1[64] = { 0, };
	char param2[64] = { 0, };

	memset(&client_noti, 0, sizeof(wifi_direct_client_noti_s));

	// 1.Read socket
	if ((__wfd_client_read_socket
		 (sockfd, (char *) &client_noti,
		  sizeof(wifi_direct_client_noti_s))) <= 0)
	{
		WFD_CLIENT_LOG(WFD_LOG_ERROR, "Error!!! Reading Async Event[%d]\n",
					   sockfd);
		//close(sockfd);
		__wfd_reset_control();
		__WFD_CLIENT_FUNC_END__;
		return false;
	}

	WFD_CLIENT_LOG(WFD_LOG_LOW, "Received Event is [%d,%s], error[%d]\n",
				   client_noti.event, __wfd_print_event(client_noti.event),
				   client_noti.error);

	event = client_noti.event;
	error = client_noti.error;
	memcpy(param1, client_noti.param1, sizeof(client_noti.param1));
	memcpy(param2, client_noti.param2, sizeof(client_noti.param2));


	// 2. dispatch event

	switch (event)
	{
	case WIFI_DIRECT_CLI_EVENT_ACTIVATION:
	case WIFI_DIRECT_CLI_EVENT_DEACTIVATION:
		if (client->activation_cb != NULL)
			client->activation_cb(error,
								  (wifi_direct_device_state_e)
								  __wfd_convert_client_event(event),
								  client->user_data_for_cb_activation);
		else
			WFD_CLIENT_LOG(WFD_LOG_ERROR, "activation_cb is NULL!!\n");
		break;

	case WIFI_DIRECT_CLI_EVENT_DISCOVER_START:
	case WIFI_DIRECT_CLI_EVENT_DISCOVER_START_LISTEN_ONLY:
	case WIFI_DIRECT_CLI_EVENT_DISCOVER_START_SEARCH_LISTEN:
	case WIFI_DIRECT_CLI_EVENT_DISCOVER_END:
	case WIFI_DIRECT_CLI_EVENT_DISCOVER_FOUND_PEERS:
		if (client->discover_cb != NULL)
			client->discover_cb(error,
								(wifi_direct_discovery_state_e)
								__wfd_convert_client_event(event),
								client->user_data_for_cb_discover);
		else
			WFD_CLIENT_LOG(WFD_LOG_ERROR, "discover_cb is NULL!!\n");
		break;

	case WIFI_DIRECT_CLI_EVENT_CONNECTION_START:
	case WIFI_DIRECT_CLI_EVENT_CONNECTION_REQ:
	case WIFI_DIRECT_CLI_EVENT_CONNECTION_RSP:
	case WIFI_DIRECT_CLI_EVENT_DISCONNECTION_RSP:
	case WIFI_DIRECT_CLI_EVENT_CONNECTION_WPS_REQ:
	case WIFI_DIRECT_CLI_EVENT_DISCONNECTION_IND:
	case WIFI_DIRECT_CLI_EVENT_DISASSOCIATION_IND:
	case WIFI_DIRECT_CLI_EVENT_GROUP_CREATE_RSP:
	case WIFI_DIRECT_CLI_EVENT_GROUP_DESTROY_RSP:
		if (client->connection_cb != NULL)
			client->connection_cb(error,
					  (wifi_direct_connection_state_e)
					  __wfd_convert_client_event(event), param1,
					  client->user_data_for_cb_connection);
		else
			WFD_CLIENT_LOG(WFD_LOG_ERROR, "connection_cb is NULL!!\n");
		break;

	// ToDo:  Handling IP lease event...
	case WIFI_DIRECT_CLI_EVENT_IP_LEASED_IND:
		if (client->ip_assigned_cb != NULL)
		{
			char* ifname = NULL;
			ifname = vconf_get_str(VCONFKEY_IFNAME);

			if (ifname == NULL)
				WFD_CLIENT_LOG(WFD_LOG_LOW, "vconf (%s) value is NULL!!!\n", VCONFKEY_IFNAME);
			else
				WFD_CLIENT_LOG(WFD_LOG_LOW, "VCONFKEY_IFNAME(%s) : %s\n", VCONFKEY_IFNAME, ifname);

				client->ip_assigned_cb(param1,
								  param2,
								  ifname,
								  client->user_data_for_cb_ip_assigned);

		}
		else
			WFD_CLIENT_LOG(WFD_LOG_ERROR, "ip_assigned_cb is NULL!!\n");
		break;

	default:
		break;
	}

	__WFD_CLIENT_FUNC_END__;

	return TRUE;
}

static wifi_direct_error_e __wfd_client_send_request(int sockfd, void *req_data, int dataLength)
{
	int retval = 0;

	__WFD_CLIENT_FUNC_START__;

	if (sockfd > 0)
	{
		WFD_CLIENT_LOG(WFD_LOG_LOW, "Write [%d] bytes to socket [%d].\n",
					   dataLength, sockfd);
		errno = 0;
		retval = write(sockfd, (char *) req_data, dataLength);

		if (retval <= 0)
		{
			WFD_CLIENT_LOG(WFD_LOG_ERROR,
						   "Error!!! writing to the socket. Error = %s \n",
						   strerror(errno));
			__WFD_CLIENT_FUNC_END__;
			return WIFI_DIRECT_ERROR_NONE;
		}

		__WFD_CLIENT_FUNC_END__;
		return WIFI_DIRECT_ERROR_NONE;
	}

	WFD_CLIENT_LOG(WFD_LOG_ERROR, "Error!!! Invalid sockfd [%d]\n", sockfd);
	__WFD_CLIENT_FUNC_END__;
	return WIFI_DIRECT_ERROR_NONE;
}

static wifi_direct_error_e __wfd_client_async_event_init(int clientid)
{
	int len = 0;
	int sockfd = 0;
	struct sockaddr_un servAddr;
	char *path = "/tmp/wfd_client_socket";

	wifi_direct_client_info_s *client_info = __wfd_get_control();

	__WFD_CLIENT_FUNC_START__;

	errno = 0;
	if ((sockfd = socket(AF_UNIX, SOCK_STREAM, 0)) < 0)
	{
		WFD_CLIENT_LOG(WFD_LOG_ERROR,
					   "Error!!! creating async socket. Error = [%s].\n",
					   strerror(errno));
		__WFD_CLIENT_FUNC_END__;
		return WIFI_DIRECT_ERROR_COMMUNICATION_FAILED;
	}

	WFD_CLIENT_LOG(WFD_LOG_LOW, "Created async socket [%d]\n", sockfd);

	memset(&servAddr, 0, sizeof(servAddr));
	servAddr.sun_family = AF_UNIX;
	strcpy(servAddr.sun_path, path);
	len = sizeof(servAddr.sun_family) + strlen(path);

	WFD_CLIENT_LOG(WFD_LOG_LOW,
				   "Connecting to server socket to register async socket [%d]\n",
				   sockfd);
	errno = 0;
	if ((connect(sockfd, (struct sockaddr *) &servAddr, len)) < 0)
	{
		WFD_CLIENT_LOG(WFD_LOG_ERROR,
					   "Error!!! connecting to server socket. Error = [%s].\n",
					   strerror(errno));
		close(sockfd);
		__WFD_CLIENT_FUNC_END__;
		return WIFI_DIRECT_ERROR_COMMUNICATION_FAILED;
	}
	else
	{
		wifi_direct_client_request_s req;
		int result = WIFI_DIRECT_ERROR_NONE;

		memset(&req, 0, sizeof(wifi_direct_client_request_s));

		req.cmd = WIFI_DIRECT_CMD_INIT_ASYNC_SOCKET;
		req.client_id = clientid;

		result =
			__wfd_client_send_request(sockfd, &req, sizeof(wifi_direct_client_request_s));

		if (result != WIFI_DIRECT_ERROR_NONE)
		{
			WFD_CLIENT_LOG(WFD_LOG_ERROR,
						   "Error!!! writing to socket, Errno = %s\n",
						   strerror(errno));
			WFD_CLIENT_LOG(WFD_LOG_ERROR, "Error!!! [%s]\n",
						   __wfd_print_error(result));
			close(sockfd);
			__WFD_CLIENT_FUNC_END__;
			return result;
		}

		client_info->async_sockfd = sockfd;

		WFD_CLIENT_LOG(WFD_LOG_ERROR, "Async socket is created= %d\n", sockfd);

	}

	return (sockfd);
}


static int __wfd_client_read_socket(int sockfd, char *dataptr, int datalen)
{
	int pollret = 0;
	struct pollfd pollfd;
	int timeout = 60000; /** for 60 sec */
	int retval = 0;
	int total_data_recd = 0;

	__WFD_CLIENT_FUNC_START__;

	if (sockfd <= 0)
	{
		WFD_CLIENT_LOG(WFD_LOG_ERROR, "Error!!! Invalid socket FD [%d]\n",
					   sockfd);
		__WFD_CLIENT_FUNC_END__;
		return -1;
	}

	if ((dataptr == NULL) || (datalen <= 0))
	{
		WFD_CLIENT_LOG(WFD_LOG_ERROR, "Error!!! Invalid parameter\n");
		__WFD_CLIENT_FUNC_END__;
		return -1;
	}

	WFD_CLIENT_LOG(WFD_LOG_ERROR, "@@@@@@@ len = %d  @@@@@@@@@@@\n", datalen);

	pollfd.fd = sockfd;
	pollfd.events = POLLIN | POLLERR | POLLHUP;
	pollret = poll(&pollfd, 1, timeout);

	WFD_CLIENT_LOG(WFD_LOG_ERROR, "POLL ret = %d,  \n", pollret);

	if (pollret > 0)
	{
		if (pollfd.revents == POLLIN)
		{
			WFD_CLIENT_LOG(WFD_LOG_ERROR, "POLLIN \n");

			while (datalen)
			{
				errno = 0;
				retval = read(sockfd, (char *) dataptr, datalen);
				WFD_CLIENT_LOG(WFD_LOG_ERROR, "sockfd %d retval %d\n", sockfd,
							   retval);
				if (retval <= 0)
				{
					WFD_CLIENT_LOG(WFD_LOG_ERROR,
								   "Error!!! reading data, error [%s]\n",
								   strerror(errno));
					__WFD_CLIENT_FUNC_END__;
					return retval;
				}
				total_data_recd += retval;
				dataptr += retval;
				datalen -= retval;
			}
			__WFD_CLIENT_FUNC_END__;
			return total_data_recd;
		}
		else if (pollfd.revents & POLLHUP)
		{
			WFD_CLIENT_LOG(WFD_LOG_ERROR, "POLLHUP\n");
			__WFD_CLIENT_FUNC_END__;
			return 0;
		}
		else if (pollfd.revents & POLLERR)
		{
			WFD_CLIENT_LOG(WFD_LOG_ERROR, "POLLERR\n");
			__WFD_CLIENT_FUNC_END__;
			return 0;
		}
	}
	else if (pollret == 0)
	{
		WFD_CLIENT_LOG(WFD_LOG_ERROR, "POLLing timeout  \n");
		__WFD_CLIENT_FUNC_END__;
		return 0;
	}
	else
	{
		WFD_CLIENT_LOG(WFD_LOG_ERROR, "Polling unknown error \n");
		__WFD_CLIENT_FUNC_END__;
		return -1;
	}
	__WFD_CLIENT_FUNC_END__;
	return 1;
}


static int __wfd_client_read_more_data(int sockfd, void *pData, int Datalen)
{
	int retval = 0;

	__WFD_CLIENT_FUNC_START__;

	if (sockfd < 0)
	{
		WFD_CLIENT_LOG(WFD_LOG_ERROR, "Error!!! Inavlid argument passed\n");
		__WFD_CLIENT_FUNC_END__;
		return WIFI_DIRECT_ERROR_INVALID_PARAMETER;
	}

	if (pData == NULL)
	{
		WFD_CLIENT_LOG(WFD_LOG_ERROR, "Error!!! Inavlid argument passed\n");
		__WFD_CLIENT_FUNC_END__;
		return WIFI_DIRECT_ERROR_INVALID_PARAMETER;
	}

	if (Datalen <= 0)
	{
		WFD_CLIENT_LOG(WFD_LOG_ERROR, "Error!!! Inavlid argument passed\n");
		__WFD_CLIENT_FUNC_END__;
		return WIFI_DIRECT_ERROR_INVALID_PARAMETER;
	}

	/** Initialising the structure variable */
	memset(pData, 0, Datalen);
	errno = 0;
	retval = __wfd_client_read_socket(sockfd, (char *) pData, Datalen);
	if (retval <= 0)
	{
		WFD_CLIENT_LOG(WFD_LOG_ERROR,
					   "Error!!! reading response from CM. errno = [%d] \n",
					   errno);
		__WFD_CLIENT_FUNC_END__;
		return WIFI_DIRECT_ERROR_OPERATION_FAILED;
	}

	__WFD_CLIENT_FUNC_END__;
	return WIFI_DIRECT_ERROR_NONE;
}

void __wfd_client_print_entry_list(wfd_discovery_entry_s * list, int num)
{
	int i = 0;

	WFD_CLIENT_LOG(WFD_LOG_LOW, "------------------------------------------\n");
	for (i = 0; i < num; i++)
	{
		WFD_CLIENT_LOG(WFD_LOG_LOW, "== Peer index : %d ==\n", i);
		WFD_CLIENT_LOG(WFD_LOG_LOW, "is Group Owner ? %s\n",
					   list[i].is_group_owner ? "YES" : "NO");
		WFD_CLIENT_LOG(WFD_LOG_LOW, "SSID : %s\n", list[i].ssid);
		WFD_CLIENT_LOG(WFD_LOG_LOW, "MAC address : " MACSTR "\n",
					   MAC2STR(list[i].mac_address));
		WFD_CLIENT_LOG(WFD_LOG_LOW, "wps cfg method : %x\n", list[i].wps_cfg_methods);
	}
	WFD_CLIENT_LOG(WFD_LOG_ERROR,
				   "------------------------------------------\n");
}

void __wfd_client_print_connected_peer_info(wfd_connected_peer_info_s * list, int num)
{
	int i = 0;

	WFD_CLIENT_LOG(WFD_LOG_LOW, "------------------------------------------\n");
	for (i = 0; i < num; i++)
	{
		WFD_CLIENT_LOG(WFD_LOG_LOW, "== Peer index : %d ==\n", i);
		WFD_CLIENT_LOG(WFD_LOG_LOW, "ssid : %s\n", list[i].ssid);
		WFD_CLIENT_LOG(WFD_LOG_LOW, "Device MAC : " MACSTR "\n",
					   MAC2STR(list[i].mac_address));
		WFD_CLIENT_LOG(WFD_LOG_LOW, "Interface MAC : " MACSTR "\n",
					   MAC2STR(list[i].intf_mac_address));
		WFD_CLIENT_LOG(WFD_LOG_LOW, "services : %d\n", list[i].services);
		WFD_CLIENT_LOG(WFD_LOG_LOW, "is_p2p : %d\n", list[i].is_p2p);
		WFD_CLIENT_LOG(WFD_LOG_LOW, "category : %d\n", list[i].category);
		WFD_CLIENT_LOG(WFD_LOG_LOW, "channel : %d\n", list[i].channel);
		WFD_CLIENT_LOG(WFD_LOG_LOW, "IP ["IPSTR"]\n", IP2STR(list[i].ip_address));
	}
	WFD_CLIENT_LOG(WFD_LOG_ERROR,
				   "------------------------------------------\n");
}


void __wfd_client_print_config_data(wfd_config_data_s * config)
{
	if (config == NULL)
		return;

	WFD_CLIENT_LOG(WFD_LOG_LOW, "Operating channel = [%d]\n", config->channel);
	WFD_CLIENT_LOG(WFD_LOG_LOW, "WPS method = [%d, %s]\n", config->wps_config,
				   (config->wps_config ==
					WIFI_DIRECT_WPS_TYPE_PBC) ? 
						"Pushbutton" : (config-> wps_config == WIFI_DIRECT_WPS_TYPE_PIN_DISPLAY)
				   			? "Display" : "Keypad");

	WFD_CLIENT_LOG(WFD_LOG_LOW, "Max client = [%d]\n", config->max_clients);
	WFD_CLIENT_LOG(WFD_LOG_LOW, "grp_owner_intent = [%d]\n",
				   config->group_owner_intent);
	WFD_CLIENT_LOG(WFD_LOG_LOW, "hide-SSID = [%d]\n", config->hide_SSID);
	WFD_CLIENT_LOG(WFD_LOG_LOW, "want_persistent_group = [%d]\n",
				   config->want_persistent_group);
	WFD_CLIENT_LOG(WFD_LOG_LOW, "auto_connection = [%d]\n",
				   config->auto_connection);
	WFD_CLIENT_LOG(WFD_LOG_LOW, "primary_dev_type = [%d]\n",
				   config->primary_dev_type);
	WFD_CLIENT_LOG(WFD_LOG_LOW, "secondary_dev_type = [%d]\n",
				   config->secondary_dev_type);

}


int wifi_direct_initialize(void)
{
	struct sockaddr_un servAddr;
	char *path = "/tmp/wfd_client_socket";
	wifi_direct_client_info_s *client_info = __wfd_get_control();
	int sockfd = 0;
	int len = 0;
	int ret = 0;

	__WFD_CLIENT_FUNC_START__;

	if (client_info->is_registered == TRUE)
	{
		WFD_CLIENT_LOG(WFD_LOG_ERROR,
					   "Warning!!! Already registered\nUpdate user data and callback!\n");
		__WFD_CLIENT_FUNC_END__;
		return WIFI_DIRECT_ERROR_NONE;
	}

	errno = 0;
	if ((sockfd = socket(AF_UNIX, SOCK_STREAM, 0)) < 0)
	{
		WFD_CLIENT_LOG(WFD_LOG_ERROR,
					   "Error!!! creating sync socket. Error = [%s].\n",
					   strerror(errno));
		return WIFI_DIRECT_ERROR_COMMUNICATION_FAILED;
	}

	WFD_CLIENT_LOG(WFD_LOG_LOW, "Created sync socket [%d]\n", sockfd);

	memset(&servAddr, 0, sizeof(servAddr));
	servAddr.sun_family = AF_UNIX;
	strcpy(servAddr.sun_path, path);
	len = sizeof(servAddr.sun_family) + strlen(path);

	WFD_CLIENT_LOG(WFD_LOG_LOW,
				   "Connecting to server socket to register sync socket [%d]\n",
				   sockfd);



	int retry_count = 2;
	while (retry_count > 0)
	{
		errno = 0;
		if ((ret = connect(sockfd, (struct sockaddr *) &servAddr, len)) < 0)
		{
			WFD_CLIENT_LOG(WFD_LOG_LOW, "Launching wfd-server..\n");
			system
				("dbus-send --system --print-reply --dest=net.netconfig /net/netconfig/wifi net.netconfig.wifi.LaunchDirect");
			retry_count--;
		}
		else
		{
			break;
		}
	}

	if (ret < 0)
	{
		WFD_CLIENT_LOG(WFD_LOG_ERROR,
					   "Error!!! connecting to server socket. Error = [%d] %s.\n",
					   errno, strerror(errno));
		if (sockfd > 0)
			close(sockfd);

		__WFD_CLIENT_FUNC_END__;
		return WIFI_DIRECT_ERROR_COMMUNICATION_FAILED;
	}
	else
	{
		wifi_direct_client_request_s req;
		wifi_direct_client_response_s resp;

		int status = WIFI_DIRECT_ERROR_NONE;

		memset(&req, 0, sizeof(wifi_direct_client_request_s));
		memset(&resp, 0, sizeof(wifi_direct_client_response_s));

		req.cmd = WIFI_DIRECT_CMD_REGISTER;
		req.client_id = gettid();
		WFD_CLIENT_LOG(WFD_LOG_LOW, "Client ID = %d\n", req.client_id);

		status = __wfd_client_send_request(sockfd, &req, sizeof(wifi_direct_client_request_s));

		if (status != WIFI_DIRECT_ERROR_NONE)
		{
			WFD_CLIENT_LOG(WFD_LOG_ERROR,
						   "Error!!! writing to socket, Errno = %s\n",
						   strerror(errno));
			WFD_CLIENT_LOG(WFD_LOG_ERROR, "Error!!! [%s]\n",
						   __wfd_print_error(status));
			close(sockfd);
			__WFD_CLIENT_FUNC_END__;
			return WIFI_DIRECT_ERROR_COMMUNICATION_FAILED;
		}

		/*Get client id */
		if ((status = __wfd_client_read_socket(sockfd, (char *) &resp, 
			sizeof(wifi_direct_client_response_s))) <= 0)
		{
			WFD_CLIENT_LOG(WFD_LOG_ERROR,
						   "Error!!! reading socket, status = %d errno = %s\n",
						   status, strerror(errno));
			__WFD_CLIENT_FUNC_END__;
			return WIFI_DIRECT_ERROR_COMMUNICATION_FAILED;
		}
		else
		{
			if (resp.cmd == WIFI_DIRECT_CMD_REGISTER)
			{
				if (resp.result == WIFI_DIRECT_ERROR_NONE)
				{
					WFD_CLIENT_LOG(WFD_LOG_LOW, "Client ID received = %d \n",
								   resp.client_id);
					WFD_CLIENT_LOG(WFD_LOG_LOW,
								   "Connected sync socket %d to the wifi direct server socket\n",
								   sockfd);
					client_info->sync_sockfd = sockfd;
					client_info->client_id = resp.client_id;
					client_info->is_registered = TRUE;
				}
				else
				{
					WFD_CLIENT_LOG(WFD_LOG_ERROR,
								   "Error!!! Client Register = %d\n",
								   resp.result);
					close(sockfd);
					__WFD_CLIENT_FUNC_END__;
					return resp.result;
				}

				int async_sockfd = -1;
				/* Send request for establishing async communication channel */
				if ((async_sockfd =
					 __wfd_client_async_event_init(client_info->client_id)) ==
					WIFI_DIRECT_ERROR_COMMUNICATION_FAILED)
				{
					WFD_CLIENT_LOG(WFD_LOG_ERROR,
								   "Error!!! creating Async Socket \n");
					__wfd_reset_control();
					__WFD_CLIENT_FUNC_END__;
					return WIFI_DIRECT_ERROR_COMMUNICATION_FAILED;
				}

				client_info->async_sockfd = async_sockfd;
			}
			else
			{
				WFD_CLIENT_LOG(WFD_LOG_ERROR,
							   "Error!!! Invalid Response received from wfd Server. cmd = %d \n",
							   resp.cmd);
				close(sockfd);
				__WFD_CLIENT_FUNC_END__;
				return WIFI_DIRECT_ERROR_COMMUNICATION_FAILED;
			}
		}
	}

	GIOChannel *gio = g_io_channel_unix_new(client_info->async_sockfd);

	int g_source_id =
		g_io_add_watch(gio, G_IO_IN | G_IO_ERR | G_IO_HUP,
					   (GIOFunc) __wfd_client_process_event, NULL);

	g_io_channel_unref(gio);

	WFD_CLIENT_LOG(WFD_LOG_LOW,
				   "Scoket is successfully registered to g_main_loop.\n");

	client_info->g_source_id = g_source_id;

	// Initialize callbacks
	client_info->activation_cb = NULL;
	client_info->discover_cb = NULL;
	client_info->connection_cb = NULL;
	client_info->user_data_for_cb_activation = NULL;
	client_info->user_data_for_cb_discover = NULL;
	client_info->user_data_for_cb_connection = NULL;

	__WFD_CLIENT_FUNC_END__;

	return WIFI_DIRECT_ERROR_NONE;
}



int wifi_direct_deinitialize(void)
{
	wifi_direct_client_info_s *client_info = __wfd_get_control();

	__WFD_CLIENT_FUNC_START__;

	if (client_info->is_registered == false)
	{
		WFD_CLIENT_LOG(WFD_LOG_ERROR, "Client is already deregistered.\n");
		__WFD_CLIENT_FUNC_END__;
		return WIFI_DIRECT_ERROR_OPERATION_FAILED;
	}

	client_info->activation_cb = NULL;
	client_info->discover_cb = NULL;
	client_info->connection_cb = NULL;
	client_info->user_data_for_cb_activation = NULL;
	client_info->user_data_for_cb_discover = NULL;
	client_info->user_data_for_cb_connection = NULL;

	wifi_direct_client_request_s req;
	wifi_direct_client_response_s rsp;

	int status = WIFI_DIRECT_ERROR_NONE;

	memset(&req, 0, sizeof(wifi_direct_client_request_s));
	memset(&rsp, 0, sizeof(wifi_direct_client_response_s));

	req.cmd = WIFI_DIRECT_CMD_DEREGISTER;
	req.client_id = client_info->client_id;

	status =
		__wfd_client_send_request(client_info->sync_sockfd, &req,
								  sizeof(wifi_direct_client_request_s));
	if (status != WIFI_DIRECT_ERROR_NONE)
	{
		WFD_CLIENT_LOG(WFD_LOG_ERROR,
					   "Error!!! writing to socket, Errno = %s\n",
					   strerror(errno));
		WFD_CLIENT_LOG(WFD_LOG_ERROR, "Error!!! [%s]\n",
					   __wfd_print_error(status));
		client_info->sync_sockfd = -1;
		__wfd_reset_control();
		__WFD_CLIENT_FUNC_END__;
		return WIFI_DIRECT_ERROR_COMMUNICATION_FAILED;
	}

	//
	// Deinit protocol: Send the deregister cmd and wait for socket close...
	//
	if ((status =
		 __wfd_client_read_socket(client_info->sync_sockfd, (char *) &rsp,
								  sizeof(wifi_direct_client_response_s))) <= 0)
	{
		WFD_CLIENT_LOG(WFD_LOG_LOW, "Deinit Successfull\n");

		if (client_info->g_source_id > 0)
			g_source_remove(client_info->g_source_id);
		client_info->g_source_id = -1;

		close(client_info->sync_sockfd);
		client_info->sync_sockfd = -1;
		__wfd_reset_control();
		__WFD_CLIENT_FUNC_END__;
		return WIFI_DIRECT_ERROR_NONE;
	}
	else
	{
		WFD_CLIENT_LOG(WFD_LOG_LOW, "Error.. Something wrong...!!!\n");
	}

	__wfd_reset_control();

	__WFD_CLIENT_FUNC_END__;
	return WIFI_DIRECT_ERROR_NONE;
}


int wifi_direct_set_device_state_changed_cb(wifi_direct_device_state_changed_cb
											cb, void *user_data)
{
	wifi_direct_client_info_s *client_info = __wfd_get_control();

	__WFD_CLIENT_FUNC_START__;

	if (NULL == cb)
	{
		WFD_CLIENT_LOG(WFD_LOG_ERROR, "Callback is NULL.\n");
		__WFD_CLIENT_FUNC_END__;
		return WIFI_DIRECT_ERROR_INVALID_PARAMETER;
	}

	if (client_info->is_registered == false)
	{
		WFD_CLIENT_LOG(WFD_LOG_ERROR, "Client is not initialized.\n");
		__WFD_CLIENT_FUNC_END__;
		return WIFI_DIRECT_ERROR_NOT_INITIALIZED;
	}

	client_info->activation_cb = cb;
	client_info->user_data_for_cb_activation = user_data;

	return WIFI_DIRECT_ERROR_NONE;
}


int wifi_direct_unset_device_state_changed_cb(void)
{
	wifi_direct_client_info_s *client_info = __wfd_get_control();

	__WFD_CLIENT_FUNC_START__;

	if (client_info->is_registered == false)
	{
		WFD_CLIENT_LOG(WFD_LOG_ERROR, "Client is not initialized.\n");
		__WFD_CLIENT_FUNC_END__;
		return WIFI_DIRECT_ERROR_NOT_INITIALIZED;
	}

	client_info->activation_cb = NULL;
	client_info->user_data_for_cb_activation = NULL;

	return WIFI_DIRECT_ERROR_NONE;
}


int
wifi_direct_set_discovery_state_changed_cb
(wifi_direct_discovery_state_chagned_cb cb, void *user_data)
{
	wifi_direct_client_info_s *client_info = __wfd_get_control();

	__WFD_CLIENT_FUNC_START__;

	if (NULL == cb)
	{
		WFD_CLIENT_LOG(WFD_LOG_ERROR, "Callback is NULL.\n");
		__WFD_CLIENT_FUNC_END__;
		return WIFI_DIRECT_ERROR_INVALID_PARAMETER;
	}

	if (client_info->is_registered == false)
	{
		WFD_CLIENT_LOG(WFD_LOG_ERROR, "Client is not initialized.\n");
		__WFD_CLIENT_FUNC_END__;
		return WIFI_DIRECT_ERROR_NOT_INITIALIZED;
	}

	client_info->discover_cb = cb;
	client_info->user_data_for_cb_discover = user_data;

	return WIFI_DIRECT_ERROR_NONE;
}


int wifi_direct_unset_discovery_state_changed_cb(void)
{
	wifi_direct_client_info_s *client_info = __wfd_get_control();

	__WFD_CLIENT_FUNC_START__;

	if (client_info->is_registered == false)
	{
		WFD_CLIENT_LOG(WFD_LOG_ERROR, "Client is not initialized.\n");
		__WFD_CLIENT_FUNC_END__;
		return WIFI_DIRECT_ERROR_NOT_INITIALIZED;
	}

	client_info->discover_cb = NULL;
	client_info->user_data_for_cb_discover = NULL;

	return WIFI_DIRECT_ERROR_NONE;
}


int
wifi_direct_set_connection_state_changed_cb
(wifi_direct_connection_state_changed_cb cb, void *user_data)
{
	wifi_direct_client_info_s *client_info = __wfd_get_control();

	__WFD_CLIENT_FUNC_START__;

	if (NULL == cb)
	{
		WFD_CLIENT_LOG(WFD_LOG_ERROR, "Callback is NULL.\n");
		__WFD_CLIENT_FUNC_END__;
		return WIFI_DIRECT_ERROR_INVALID_PARAMETER;
	}

	if (client_info->is_registered == false)
	{
		WFD_CLIENT_LOG(WFD_LOG_ERROR, "Client is not initialized.\n");
		__WFD_CLIENT_FUNC_END__;
		return WIFI_DIRECT_ERROR_NOT_INITIALIZED;
	}

	client_info->connection_cb = cb;
	client_info->user_data_for_cb_connection = user_data;

	return WIFI_DIRECT_ERROR_NONE;
}


int wifi_direct_unset_connection_state_changed_cb(void)
{
	wifi_direct_client_info_s *client_info = __wfd_get_control();

	__WFD_CLIENT_FUNC_START__;

	if (client_info->is_registered == false)
	{
		WFD_CLIENT_LOG(WFD_LOG_ERROR, "Client is not initialized.\n");
		__WFD_CLIENT_FUNC_END__;
		return WIFI_DIRECT_ERROR_NOT_INITIALIZED;
	}

	client_info->connection_cb = NULL;
	client_info->user_data_for_cb_connection = NULL;

	return WIFI_DIRECT_ERROR_NONE;
}


int wifi_direct_set_client_ip_address_assigned_cb(wifi_direct_client_ip_address_assigned_cb cb, void* user_data)
{
	wifi_direct_client_info_s *client_info = __wfd_get_control();

	__WFD_CLIENT_FUNC_START__;

	if (NULL == cb)
	{
		WFD_CLIENT_LOG(WFD_LOG_ERROR, "Callback is NULL.\n");
		__WFD_CLIENT_FUNC_END__;
		return WIFI_DIRECT_ERROR_INVALID_PARAMETER;
	}

	if (client_info->is_registered == false)
	{
		WFD_CLIENT_LOG(WFD_LOG_ERROR, "Client is not initialized.\n");
		__WFD_CLIENT_FUNC_END__;
		return WIFI_DIRECT_ERROR_NOT_INITIALIZED;
	}

	client_info->ip_assigned_cb = cb;
	client_info->user_data_for_cb_ip_assigned = user_data;

	return WIFI_DIRECT_ERROR_NONE;
}

int wifi_direct_unset_client_ip_address_assigned_cb(void)
{
	wifi_direct_client_info_s *client_info = __wfd_get_control();

	__WFD_CLIENT_FUNC_START__;

	if (client_info->is_registered == false)
	{
		WFD_CLIENT_LOG(WFD_LOG_ERROR, "Client is not initialized.\n");
		__WFD_CLIENT_FUNC_END__;
		return WIFI_DIRECT_ERROR_NOT_INITIALIZED;
	}

	client_info->ip_assigned_cb = NULL;
	client_info->user_data_for_cb_ip_assigned = NULL;

	return WIFI_DIRECT_ERROR_NONE;
}


int wifi_direct_activate(void)
{
	wifi_direct_client_info_s *client_info = __wfd_get_control();

	__WFD_CLIENT_FUNC_START__;

	if ((client_info->is_registered == false)
		|| (client_info->client_id == WFD_INVALID_ID))
	{
		WFD_CLIENT_LOG(WFD_LOG_ERROR, "Client is NOT registered.\n");
		__WFD_CLIENT_FUNC_END__;
		return WIFI_DIRECT_ERROR_NOT_INITIALIZED;
	}

	wifi_direct_client_request_s req;
	wifi_direct_client_response_s rsp;

	int status = WIFI_DIRECT_ERROR_NONE;

	memset(&req, 0, sizeof(wifi_direct_client_request_s));
	memset(&rsp, 0, sizeof(wifi_direct_client_response_s));

	req.cmd = WIFI_DIRECT_CMD_ACTIVATE;
	req.client_id = client_info->client_id;

	status =
		__wfd_client_send_request(client_info->sync_sockfd, &req,
								  sizeof(wifi_direct_client_request_s));
	if (status != WIFI_DIRECT_ERROR_NONE)
	{
		WFD_CLIENT_LOG(WFD_LOG_ERROR,
					   "Error!!! writing to socket, Errno = %s\n",
					   strerror(errno));
		WFD_CLIENT_LOG(WFD_LOG_ERROR, "Error!!! [%s]\n",
					   __wfd_print_error(status));
		client_info->sync_sockfd = -1;
		__wfd_reset_control();
		__WFD_CLIENT_FUNC_END__;
		return WIFI_DIRECT_ERROR_COMMUNICATION_FAILED;
	}

	if ((status =
		 __wfd_client_read_socket(client_info->sync_sockfd, (char *) &rsp,
								  sizeof(wifi_direct_client_response_s))) <= 0)
	{
		WFD_CLIENT_LOG(WFD_LOG_ERROR,
					   "Error!!! reading socket, status = %d errno = %s\n",
					   status, strerror(errno));
		client_info->sync_sockfd = -1;
		__wfd_reset_control();
		__WFD_CLIENT_FUNC_END__;
		return WIFI_DIRECT_ERROR_COMMUNICATION_FAILED;
	}
	else
	{
		if (rsp.cmd == WIFI_DIRECT_CMD_ACTIVATE)
		{
			if (rsp.result != WIFI_DIRECT_ERROR_NONE)
			{
				WFD_CLIENT_LOG(WFD_LOG_ERROR,
							   "Error!!! Result received = %d \n", rsp.result);
				WFD_CLIENT_LOG(WFD_LOG_ERROR, "Error!!! [%s]\n",
							   __wfd_print_error(rsp.result));
				__WFD_CLIENT_FUNC_END__;
				return rsp.result;
			}
			else
			{
				WFD_CLIENT_LOG(WFD_LOG_ERROR,
							   "Activating device is successfull.\n");
			}
		}
		else
		{
			WFD_CLIENT_LOG(WFD_LOG_ERROR, "Error!!! Invalid resp cmd = %d\n",
						   rsp.cmd);
			return WIFI_DIRECT_ERROR_OPERATION_FAILED;
		}
	}

	__WFD_CLIENT_FUNC_END__;
	return WIFI_DIRECT_ERROR_NONE;
}

int wifi_direct_deactivate(void)
{
	wifi_direct_client_info_s *client_info = __wfd_get_control();

	__WFD_CLIENT_FUNC_START__;

	if ((client_info->is_registered == false)
		|| (client_info->client_id == WFD_INVALID_ID))
	{
		WFD_CLIENT_LOG(WFD_LOG_ERROR, "Client is NOT registered.\n");
		__WFD_CLIENT_FUNC_END__;
		return WIFI_DIRECT_ERROR_NOT_INITIALIZED;
	}

	wifi_direct_client_request_s req;
	wifi_direct_client_response_s rsp;

	int status = WIFI_DIRECT_ERROR_NONE;

	memset(&req, 0, sizeof(wifi_direct_client_request_s));
	memset(&rsp, 0, sizeof(wifi_direct_client_response_s));

	req.cmd = WIFI_DIRECT_CMD_DEACTIVATE;
	req.client_id = client_info->client_id;

	status =
		__wfd_client_send_request(client_info->sync_sockfd, &req,
								  sizeof(wifi_direct_client_request_s));
	if (status != WIFI_DIRECT_ERROR_NONE)
	{
		WFD_CLIENT_LOG(WFD_LOG_ERROR,
					   "Error!!! writing to socket, Errno = %s\n",
					   strerror(errno));
		WFD_CLIENT_LOG(WFD_LOG_ERROR, "Error!!! [%s]\n",
					   __wfd_print_error(status));
		client_info->sync_sockfd = -1;
		__wfd_reset_control();
		__WFD_CLIENT_FUNC_END__;
		return WIFI_DIRECT_ERROR_COMMUNICATION_FAILED;
	}

	if ((status =
		 __wfd_client_read_socket(client_info->sync_sockfd, (char *) &rsp,
								  sizeof(wifi_direct_client_response_s))) <= 0)
	{
		WFD_CLIENT_LOG(WFD_LOG_ERROR,
					   "Error!!! reading socket, status = %d errno = %s\n",
					   status, strerror(errno));
		client_info->sync_sockfd = -1;
		__wfd_reset_control();
		__WFD_CLIENT_FUNC_END__;
		return WIFI_DIRECT_ERROR_COMMUNICATION_FAILED;
	}
	else
	{
		if (rsp.cmd == WIFI_DIRECT_CMD_DEACTIVATE)
		{
			if (rsp.result != WIFI_DIRECT_ERROR_NONE)
			{
				WFD_CLIENT_LOG(WFD_LOG_ERROR,
							   "Error!!! Result received = %d \n", rsp.result);
				WFD_CLIENT_LOG(WFD_LOG_ERROR, "Error!!! [%s]\n",
							   __wfd_print_error(rsp.result));
				__WFD_CLIENT_FUNC_END__;
				return rsp.result;
			}
			else
			{
				WFD_CLIENT_LOG(WFD_LOG_ERROR, "Device Deactivated! \n");
			}
		}
		else
		{
			WFD_CLIENT_LOG(WFD_LOG_ERROR, "Error!!! Invalid resp cmd = %d\n",
						   rsp.cmd);
			return WIFI_DIRECT_ERROR_OPERATION_FAILED;
		}
	}

	__WFD_CLIENT_FUNC_END__;
	return WIFI_DIRECT_ERROR_NONE;
}

int wifi_direct_start_discovery(bool listen_only, int timeout)
{
	wifi_direct_client_info_s *client_info = __wfd_get_control();

	__WFD_CLIENT_FUNC_START__;

	if ((client_info->is_registered == false)
		|| (client_info->client_id == WFD_INVALID_ID))
	{
		WFD_CLIENT_LOG(WFD_LOG_ERROR, "Client is NOT registered.\n");
		__WFD_CLIENT_FUNC_END__;
		return WIFI_DIRECT_ERROR_NOT_INITIALIZED;
	}

	if (timeout < 0)
	{
		WFD_CLIENT_LOG(WFD_LOG_ERROR, "Nagative value. Param [timeout]!\n");
		__WFD_CLIENT_FUNC_END__;
		return WIFI_DIRECT_ERROR_INVALID_PARAMETER;
	}

	wifi_direct_client_request_s req;
	wifi_direct_client_response_s rsp;

	int status = WIFI_DIRECT_ERROR_NONE;

	memset(&req, 0, sizeof(wifi_direct_client_request_s));
	memset(&rsp, 0, sizeof(wifi_direct_client_response_s));

	req.cmd = WIFI_DIRECT_CMD_START_DISCOVERY;
	req.client_id = client_info->client_id;
	req.data.listen_only = listen_only;
	req.data.timeout = timeout;

	WFD_CLIENT_LOG(WFD_LOG_ERROR, "listen only (%d) timeout (%d) \n",
				   listen_only, timeout);

	status =
		__wfd_client_send_request(client_info->sync_sockfd, &req,
								  sizeof(wifi_direct_client_request_s));
	if (status != WIFI_DIRECT_ERROR_NONE)
	{
		WFD_CLIENT_LOG(WFD_LOG_ERROR,
					   "Error!!! writing to socket, Errno = %s\n",
					   strerror(errno));
		WFD_CLIENT_LOG(WFD_LOG_ERROR, "Error!!! [%s]\n",
					   __wfd_print_error(status));
		client_info->sync_sockfd = -1;
		__wfd_reset_control();
		__WFD_CLIENT_FUNC_END__;
		return WIFI_DIRECT_ERROR_COMMUNICATION_FAILED;
	}

	if ((status =
		 __wfd_client_read_socket(client_info->sync_sockfd, (char *) &rsp,
								  sizeof(wifi_direct_client_response_s))) <= 0)
	{
		WFD_CLIENT_LOG(WFD_LOG_ERROR,
					   "Error!!! reading socket, status = %d errno = %s\n",
					   status, strerror(errno));
		client_info->sync_sockfd = -1;
		__wfd_reset_control();
		return WIFI_DIRECT_ERROR_COMMUNICATION_FAILED;
	}
	else
	{
		if (rsp.cmd == WIFI_DIRECT_CMD_START_DISCOVERY)
		{
			if (rsp.result != WIFI_DIRECT_ERROR_NONE)
			{
				WFD_CLIENT_LOG(WFD_LOG_ERROR,
							   "Error!!! Result received = %d \n", rsp.result);
				WFD_CLIENT_LOG(WFD_LOG_ERROR, "Error!!! [%s]\n",
							   __wfd_print_error(rsp.result));
				__WFD_CLIENT_FUNC_END__;
				return rsp.result;
			}
			else
			{
				WFD_CLIENT_LOG(WFD_LOG_ERROR,
							   "wifi_direct_start_discovery() SUCCESS \n");
			}
		}
		else
		{
			WFD_CLIENT_LOG(WFD_LOG_ERROR, "Error!!! Invalid resp cmd = %d\n",
						   rsp.cmd);
			return WIFI_DIRECT_ERROR_OPERATION_FAILED;
		}
	}

	__WFD_CLIENT_FUNC_END__;

	return WIFI_DIRECT_ERROR_NONE;
}

int wifi_direct_cancel_discovery(void)
{
	wifi_direct_client_info_s *client_info = __wfd_get_control();

	__WFD_CLIENT_FUNC_START__;

	if ((client_info->is_registered == false)
		|| (client_info->client_id == WFD_INVALID_ID))
	{
		WFD_CLIENT_LOG(WFD_LOG_ERROR, "Client is NOT registered.\n");
		__WFD_CLIENT_FUNC_END__;
		return WIFI_DIRECT_ERROR_NOT_INITIALIZED;
	}

	wifi_direct_client_request_s req;
	wifi_direct_client_response_s rsp;

	int status = WIFI_DIRECT_ERROR_NONE;

	memset(&req, 0, sizeof(wifi_direct_client_request_s));
	memset(&rsp, 0, sizeof(wifi_direct_client_response_s));

	req.cmd = WIFI_DIRECT_CMD_CANCEL_DISCOVERY;
	req.client_id = client_info->client_id;

	status =
		__wfd_client_send_request(client_info->sync_sockfd, &req,
								  sizeof(wifi_direct_client_request_s));
	if (status != WIFI_DIRECT_ERROR_NONE)
	{
		WFD_CLIENT_LOG(WFD_LOG_ERROR,
					   "Error!!! writing to socket, Errno = %s\n",
					   strerror(errno));
		WFD_CLIENT_LOG(WFD_LOG_ERROR, "Error!!! [%s]\n",
					   __wfd_print_error(status));
		client_info->sync_sockfd = -1;
		__wfd_reset_control();
		__WFD_CLIENT_FUNC_END__;
		return WIFI_DIRECT_ERROR_COMMUNICATION_FAILED;
	}

	if ((status =
		 __wfd_client_read_socket(client_info->sync_sockfd, (char *) &rsp,
								  sizeof(wifi_direct_client_response_s))) <= 0)
	{
		WFD_CLIENT_LOG(WFD_LOG_ERROR,
					   "Error!!! reading socket, status = %d errno = %s\n",
					   status, strerror(errno));
		client_info->sync_sockfd = -1;
		__wfd_reset_control();
		__WFD_CLIENT_FUNC_END__;
		return WIFI_DIRECT_ERROR_COMMUNICATION_FAILED;
	}
	else
	{
		if (rsp.cmd == WIFI_DIRECT_CMD_CANCEL_DISCOVERY)
		{
			if (rsp.result != WIFI_DIRECT_ERROR_NONE)
			{
				WFD_CLIENT_LOG(WFD_LOG_ERROR,
							   "Error!!! Result received = %d \n", rsp.result);
				WFD_CLIENT_LOG(WFD_LOG_ERROR, "Error!!! [%s]\n",
							   __wfd_print_error(rsp.result));
				__WFD_CLIENT_FUNC_END__;
				return rsp.result;
			}
			else
			{
				WFD_CLIENT_LOG(WFD_LOG_ERROR,
							   "wifi_direct_cancel_discovery() SUCCESS \n");
			}
		}
		else
		{
			WFD_CLIENT_LOG(WFD_LOG_ERROR, "Error!!! Invalid resp cmd = %d\n",
						   rsp.cmd);
			return WIFI_DIRECT_ERROR_OPERATION_FAILED;
		}
	}

	__WFD_CLIENT_FUNC_END__;

	return WIFI_DIRECT_ERROR_NONE;
}


int wifi_direct_foreach_discovered_peers(wifi_direct_discovered_peer_cb callback, void *user_data)
{
	wifi_direct_client_info_s *client_info = __wfd_get_control();

	__WFD_CLIENT_FUNC_START__;

	if ((client_info->is_registered == false)
		|| (client_info->client_id == WFD_INVALID_ID))
	{
		WFD_CLIENT_LOG(WFD_LOG_ERROR, "Client is NOT registered.\n");
		__WFD_CLIENT_FUNC_END__;
		return WIFI_DIRECT_ERROR_NOT_INITIALIZED;
	}

	if (callback == NULL)
	{
		WFD_CLIENT_LOG(WFD_LOG_ERROR, "NULL Param [callback]!\n");
		__WFD_CLIENT_FUNC_END__;
		return WIFI_DIRECT_ERROR_INVALID_PARAMETER;
	}

	wifi_direct_client_request_s req;
	wifi_direct_client_response_s rsp;
	int i;

	int status = WIFI_DIRECT_ERROR_NONE;

	memset(&req, 0, sizeof(wifi_direct_client_request_s));
	memset(&rsp, 0, sizeof(wifi_direct_client_response_s));

	req.cmd = WIFI_DIRECT_CMD_GET_DISCOVERY_RESULT;
	req.client_id = client_info->client_id;

	status =
		__wfd_client_send_request(client_info->sync_sockfd, &req,
								  sizeof(wifi_direct_client_request_s));
	if (status != WIFI_DIRECT_ERROR_NONE)
	{
		WFD_CLIENT_LOG(WFD_LOG_ERROR,
					   "Error!!! writing to socket, Errno = %s\n",
					   strerror(errno));
		WFD_CLIENT_LOG(WFD_LOG_ERROR, "Error!!! [%s]\n",
					   __wfd_print_error(status));
		client_info->sync_sockfd = -1;
		__wfd_reset_control();
		__WFD_CLIENT_FUNC_END__;
		return WIFI_DIRECT_ERROR_COMMUNICATION_FAILED;
	}

	if ((status =
		 __wfd_client_read_socket(client_info->sync_sockfd, (char *) &rsp,
								  sizeof(wifi_direct_client_response_s))) <= 0)
	{
		WFD_CLIENT_LOG(WFD_LOG_ERROR,
					   "Error!!! reading socket, status = %d errno = %s\n",
					   status, strerror(errno));
		client_info->sync_sockfd = -1;
		__wfd_reset_control();
		__WFD_CLIENT_FUNC_END__;
		return WIFI_DIRECT_ERROR_COMMUNICATION_FAILED;
	}
	else
	{
		if (rsp.cmd == WIFI_DIRECT_CMD_GET_DISCOVERY_RESULT)
		{
			if (rsp.result != WIFI_DIRECT_ERROR_NONE)
			{
				WFD_CLIENT_LOG(WFD_LOG_ERROR, "Error!!! Result received = %d \n", rsp.result);
				WFD_CLIENT_LOG(WFD_LOG_ERROR, "Error!!! [%s]\n", __wfd_print_error(rsp.result));
				__WFD_CLIENT_FUNC_END__;
				return rsp.result;
			}
			else
			{
				int num = rsp.param1;
				int status = 0;
				wfd_discovery_entry_s *buff = NULL;

				WFD_CLIENT_LOG(WFD_LOG_LOW, "Num of found peers = %d \n",
							   (int) rsp.param1);

				if (num > 0)
				{
					buff =
						(wfd_discovery_entry_s *) malloc(num * sizeof (wfd_discovery_entry_s));
					if (buff == NULL)
					{
						WFD_CLIENT_LOG(WFD_LOG_ERROR, "malloc() failed!!!.\n");
						return WIFI_DIRECT_ERROR_OPERATION_FAILED;
					}

					status =
						__wfd_client_read_more_data(client_info->sync_sockfd,
											buff,
											num *
											sizeof
											(wfd_discovery_entry_s));
					if (status != WIFI_DIRECT_ERROR_NONE)
					{
						if (NULL != buff)
							free(buff);
						//peer_list = NULL;
						WFD_CLIENT_LOG(WFD_LOG_ERROR, "socket read error.\n");
						return WIFI_DIRECT_ERROR_OPERATION_FAILED;
					}
				}

				__wfd_client_print_entry_list(buff, num);

				WFD_CLIENT_LOG(WFD_LOG_LOW,
							   "wifi_direct_foreach_discovered_peers() SUCCESS\n");


				wifi_direct_discovered_peer_info_s *peer_list;

				for (i = 0; i < num; i++)
				{
					peer_list = (wifi_direct_discovered_peer_info_s *) calloc(1, sizeof(wifi_direct_discovered_peer_info_s));
					peer_list->is_group_owner = buff[i].is_group_owner;
					peer_list->ssid = strdup(buff[i].ssid);
					peer_list->mac_address = (char *) calloc(1, 18);
					snprintf(peer_list->mac_address, 18, MACSTR, MAC2STR(buff[i].mac_address));
					peer_list->channel = buff[i].channel;
					peer_list->is_connected = buff[i].is_connected;
					peer_list->is_persistent_group_owner = buff[i].is_persistent_go;
					peer_list->interface_address = (char *) calloc(1, 18);
					snprintf(peer_list->interface_address, 18, MACSTR, MAC2STR(buff[i].intf_mac_address));
					peer_list->supported_wps_types= buff[i].wps_cfg_methods;
					peer_list->primary_device_type = buff[i].category;
					peer_list->secondary_device_type = buff[i].subcategory;

					if (!callback(peer_list, user_data))
						break;
				}

				if (NULL != buff)
					free(buff);

			}
		}
		else
		{
			WFD_CLIENT_LOG(WFD_LOG_ERROR, "Error!!! Invalid resp cmd = %d\n",
						   rsp.cmd);
			return WIFI_DIRECT_ERROR_OPERATION_FAILED;
		}
	}

	__WFD_CLIENT_FUNC_END__;

	return WIFI_DIRECT_ERROR_NONE;
}


int wifi_direct_connect(const char *mac_address)
{
	wifi_direct_client_info_s *client_info = __wfd_get_control();
	unsigned char la_mac_addr[6];

	__WFD_CLIENT_FUNC_START__;

	if ((client_info->is_registered == false)
		|| (client_info->client_id == WFD_INVALID_ID))
	{
		WFD_CLIENT_LOG(WFD_LOG_ERROR, "Client is NOT registered.\n");
		__WFD_CLIENT_FUNC_END__;
		return WIFI_DIRECT_ERROR_NOT_INITIALIZED;
	}

	if (mac_address == NULL)
	{
		WFD_CLIENT_LOG(WFD_LOG_ERROR, "mac_addr is NULL.\n");
		__WFD_CLIENT_FUNC_END__;
		return WIFI_DIRECT_ERROR_INVALID_PARAMETER;
	}

	wifi_direct_client_request_s req;
	wifi_direct_client_response_s rsp;

	int status = WIFI_DIRECT_ERROR_NONE;

	memset(&req, 0, sizeof(wifi_direct_client_request_s));
	memset(&rsp, 0, sizeof(wifi_direct_client_response_s));

	req.cmd = WIFI_DIRECT_CMD_CONNECT;
	req.client_id = client_info->client_id;

	macaddr_atoe(mac_address, la_mac_addr);

	req.data.mac_addr[0] = la_mac_addr[0];
	req.data.mac_addr[1] = la_mac_addr[1];
	req.data.mac_addr[2] = la_mac_addr[2];
	req.data.mac_addr[3] = la_mac_addr[3];
	req.data.mac_addr[4] = la_mac_addr[4];
	req.data.mac_addr[5] = la_mac_addr[5];


	status =
		__wfd_client_send_request(client_info->sync_sockfd, &req,
								  sizeof(wifi_direct_client_request_s));
	if (status != WIFI_DIRECT_ERROR_NONE)
	{
		WFD_CLIENT_LOG(WFD_LOG_ERROR,
					   "Error!!! writing to socket, Errno = %s\n",
					   strerror(errno));
		WFD_CLIENT_LOG(WFD_LOG_ERROR, "Error!!! [%s]\n",
					   __wfd_print_error(status));
		client_info->sync_sockfd = -1;
		__wfd_reset_control();
		__WFD_CLIENT_FUNC_END__;
		return WIFI_DIRECT_ERROR_COMMUNICATION_FAILED;
	}

	if ((status =
		 __wfd_client_read_socket(client_info->sync_sockfd, (char *) &rsp,
								  sizeof(wifi_direct_client_response_s))) <= 0)
	{
		WFD_CLIENT_LOG(WFD_LOG_ERROR,
					   "Error!!! reading socket, status = %d errno = %s\n",
					   status, strerror(errno));
		client_info->sync_sockfd = -1;
		__wfd_reset_control();
		__WFD_CLIENT_FUNC_END__;
		return WIFI_DIRECT_ERROR_COMMUNICATION_FAILED;
	}
	else
	{
		if (rsp.cmd == WIFI_DIRECT_CMD_CONNECT)
		{
			if (rsp.result != WIFI_DIRECT_ERROR_NONE)
			{
				WFD_CLIENT_LOG(WFD_LOG_ERROR,
							   "Error!!! Result received = %d \n", rsp.result);
				WFD_CLIENT_LOG(WFD_LOG_ERROR, "Error!!! [%s]\n",
							   __wfd_print_error(rsp.result));
				__WFD_CLIENT_FUNC_END__;
				return rsp.result;
			}
			else
			{
				WFD_CLIENT_LOG(WFD_LOG_ERROR,
							   "wifi_direct_connect() SUCCESS \n");
			}
		}
		else
		{
			WFD_CLIENT_LOG(WFD_LOG_ERROR, "Error!!! Invalid resp cmd = %d\n",
						   rsp.cmd);
			return WIFI_DIRECT_ERROR_OPERATION_FAILED;
		}
	}

	__WFD_CLIENT_FUNC_END__;

	return WIFI_DIRECT_ERROR_NONE;
}


int wifi_direct_disconnect_all(void)
{
	wifi_direct_client_info_s *client_info = __wfd_get_control();

	__WFD_CLIENT_FUNC_START__;

	if ((client_info->is_registered == false)
		|| (client_info->client_id == WFD_INVALID_ID))
	{
		WFD_CLIENT_LOG(WFD_LOG_ERROR, "Client is NOT registered.\n");
		__WFD_CLIENT_FUNC_END__;
		return WIFI_DIRECT_ERROR_NOT_INITIALIZED;
	}

	wifi_direct_client_request_s req;
	wifi_direct_client_response_s rsp;

	int status = WIFI_DIRECT_ERROR_NONE;

	memset(&req, 0, sizeof(wifi_direct_client_request_s));
	memset(&rsp, 0, sizeof(wifi_direct_client_response_s));

	req.cmd = WIFI_DIRECT_CMD_DISCONNECT_ALL;
	req.client_id = client_info->client_id;

	status =
		__wfd_client_send_request(client_info->sync_sockfd, &req,
								  sizeof(wifi_direct_client_request_s));
	if (status != WIFI_DIRECT_ERROR_NONE)
	{
		WFD_CLIENT_LOG(WFD_LOG_ERROR,
					   "Error!!! writing to socket, Errno = %s\n",
					   strerror(errno));
		WFD_CLIENT_LOG(WFD_LOG_ERROR, "Error!!! [%s]\n",
					   __wfd_print_error(status));
		client_info->sync_sockfd = -1;
		__wfd_reset_control();
		__WFD_CLIENT_FUNC_END__;
		return WIFI_DIRECT_ERROR_COMMUNICATION_FAILED;
	}

	if ((status =
		 __wfd_client_read_socket(client_info->sync_sockfd, (char *) &rsp,
								  sizeof(wifi_direct_client_response_s))) <= 0)
	{
		WFD_CLIENT_LOG(WFD_LOG_ERROR,
					   "Error!!! reading socket, status = %d errno = %s\n",
					   status, strerror(errno));
		client_info->sync_sockfd = -1;
		__wfd_reset_control();
		__WFD_CLIENT_FUNC_END__;
		return WIFI_DIRECT_ERROR_COMMUNICATION_FAILED;
	}
	else
	{
		if (rsp.cmd == WIFI_DIRECT_CMD_DISCONNECT_ALL)
		{
			if (rsp.result != WIFI_DIRECT_ERROR_NONE)
			{
				WFD_CLIENT_LOG(WFD_LOG_ERROR,
							   "Error!!! Result received = %d \n", rsp.result);
				WFD_CLIENT_LOG(WFD_LOG_ERROR, "Error!!! [%s]\n",
							   __wfd_print_error(rsp.result));
				__WFD_CLIENT_FUNC_END__;
				return rsp.result;
			}
			else
			{
				WFD_CLIENT_LOG(WFD_LOG_ERROR,
							   "wifi_direct_disconnect_all() SUCCESS \n");
			}
		}
		else
		{
			WFD_CLIENT_LOG(WFD_LOG_ERROR, "Error!!! Invalid resp cmd = %d\n",
						   rsp.cmd);
			return WIFI_DIRECT_ERROR_OPERATION_FAILED;
		}
	}

	__WFD_CLIENT_FUNC_END__;

	return WIFI_DIRECT_ERROR_NONE;
}


int wifi_direct_disconnect(const char *mac_address)
{
	wifi_direct_client_info_s *client_info = __wfd_get_control();
	unsigned char la_mac_addr[6];

	__WFD_CLIENT_FUNC_START__;

	if (mac_address == NULL)
	{
		WFD_CLIENT_LOG(WFD_LOG_ERROR, "mac_address is NULL.\n");
		__WFD_CLIENT_FUNC_END__;
		return WIFI_DIRECT_ERROR_INVALID_PARAMETER;
	}

	if ((client_info->is_registered == false)
		|| (client_info->client_id == WFD_INVALID_ID))
	{
		WFD_CLIENT_LOG(WFD_LOG_ERROR, "Client is NOT registered.\n");
		__WFD_CLIENT_FUNC_END__;
		return WIFI_DIRECT_ERROR_NOT_INITIALIZED;
	}

	wifi_direct_client_request_s req;
	wifi_direct_client_response_s rsp;

	int status = WIFI_DIRECT_ERROR_NONE;

	memset(&req, 0, sizeof(wifi_direct_client_request_s));
	memset(&rsp, 0, sizeof(wifi_direct_client_response_s));

	req.cmd = WIFI_DIRECT_CMD_DISCONNECT;
	req.client_id = client_info->client_id;

	macaddr_atoe(mac_address, la_mac_addr);

	req.data.mac_addr[0] = la_mac_addr[0];
	req.data.mac_addr[1] = la_mac_addr[1];
	req.data.mac_addr[2] = la_mac_addr[2];
	req.data.mac_addr[3] = la_mac_addr[3];
	req.data.mac_addr[4] = la_mac_addr[4];
	req.data.mac_addr[5] = la_mac_addr[5];

	status =
		__wfd_client_send_request(client_info->sync_sockfd, &req,
								  sizeof(wifi_direct_client_request_s));
	if (status != WIFI_DIRECT_ERROR_NONE)
	{
		WFD_CLIENT_LOG(WFD_LOG_ERROR,
					   "Error!!! writing to socket, Errno = %s\n",
					   strerror(errno));
		WFD_CLIENT_LOG(WFD_LOG_ERROR, "Error!!! [%s]\n",
					   __wfd_print_error(status));
		client_info->sync_sockfd = -1;
		__wfd_reset_control();
		__WFD_CLIENT_FUNC_END__;
		return WIFI_DIRECT_ERROR_COMMUNICATION_FAILED;
	}

	if ((status =
		 __wfd_client_read_socket(client_info->sync_sockfd, (char *) &rsp,
								  sizeof(wifi_direct_client_response_s))) <= 0)
	{
		WFD_CLIENT_LOG(WFD_LOG_ERROR,
					   "Error!!! reading socket, status = %d errno = %s\n",
					   status, strerror(errno));
		client_info->sync_sockfd = -1;
		__wfd_reset_control();
		__WFD_CLIENT_FUNC_END__;
		return WIFI_DIRECT_ERROR_COMMUNICATION_FAILED;
	}
	else
	{
		if (rsp.cmd == WIFI_DIRECT_CMD_DISCONNECT)
		{
			if (rsp.result != WIFI_DIRECT_ERROR_NONE)
			{
				WFD_CLIENT_LOG(WFD_LOG_ERROR,
							   "Error!!! Result received = %d \n", rsp.result);
				WFD_CLIENT_LOG(WFD_LOG_ERROR, "Error!!! [%s]\n",
							   __wfd_print_error(rsp.result));
				__WFD_CLIENT_FUNC_END__;
				return rsp.result;
			}
			else
			{
				WFD_CLIENT_LOG(WFD_LOG_ERROR,
							   "wifi_direct_disconnect() SUCCESS \n");
			}
		}
		else
		{
			WFD_CLIENT_LOG(WFD_LOG_ERROR, "Error!!! Invalid resp cmd = %d\n",
						   rsp.cmd);
			return WIFI_DIRECT_ERROR_OPERATION_FAILED;
		}
	}

	__WFD_CLIENT_FUNC_END__;

	return WIFI_DIRECT_ERROR_NONE;

}



int wifi_direct_accept_connection(char *mac_address)
{
	wifi_direct_client_info_s *client_info = __wfd_get_control();
	unsigned char la_mac_addr[6];

	__WFD_CLIENT_FUNC_START__;

	if ((client_info->is_registered == false)
		|| (client_info->client_id == WFD_INVALID_ID))
	{
		WFD_CLIENT_LOG(WFD_LOG_ERROR, "Client is NOT registered.\n");
		__WFD_CLIENT_FUNC_END__;
		return WIFI_DIRECT_ERROR_NOT_INITIALIZED;
	}

	if (mac_address == NULL)
	{
		WFD_CLIENT_LOG(WFD_LOG_ERROR, "mac_addr is NULL.\n");
		__WFD_CLIENT_FUNC_END__;
		return WIFI_DIRECT_ERROR_INVALID_PARAMETER;
	}

	wifi_direct_client_request_s req;
	wifi_direct_client_response_s rsp;

	int status = WIFI_DIRECT_ERROR_NONE;

	memset(&req, 0, sizeof(wifi_direct_client_request_s));
	memset(&rsp, 0, sizeof(wifi_direct_client_response_s));

	req.cmd = WIFI_DIRECT_CMD_SEND_CONNECT_REQ;
	req.client_id = client_info->client_id;

	macaddr_atoe(mac_address, la_mac_addr);

	req.data.mac_addr[0] = la_mac_addr[0];
	req.data.mac_addr[1] = la_mac_addr[1];
	req.data.mac_addr[2] = la_mac_addr[2];
	req.data.mac_addr[3] = la_mac_addr[3];
	req.data.mac_addr[4] = la_mac_addr[4];
	req.data.mac_addr[5] = la_mac_addr[5];

	status =
		__wfd_client_send_request(client_info->sync_sockfd, &req,
								  sizeof(wifi_direct_client_request_s));
	if (status != WIFI_DIRECT_ERROR_NONE)
	{
		WFD_CLIENT_LOG(WFD_LOG_ERROR,
					   "Error!!! writing to socket, Errno = %s\n",
					   strerror(errno));
		WFD_CLIENT_LOG(WFD_LOG_ERROR, "Error!!! [%s]\n",
					   __wfd_print_error(status));
		client_info->sync_sockfd = -1;
		__wfd_reset_control();
		__WFD_CLIENT_FUNC_END__;
		return WIFI_DIRECT_ERROR_COMMUNICATION_FAILED;
	}

	if ((status =
		 __wfd_client_read_socket(client_info->sync_sockfd, (char *) &rsp,
								  sizeof(wifi_direct_client_response_s))) <= 0)
	{
		WFD_CLIENT_LOG(WFD_LOG_ERROR,
					   "Error!!! reading socket, status = %d errno = %s\n",
					   status, strerror(errno));
		client_info->sync_sockfd = -1;
		__wfd_reset_control();
		__WFD_CLIENT_FUNC_END__;
		return WIFI_DIRECT_ERROR_COMMUNICATION_FAILED;
	}
	else
	{
		if (rsp.cmd == WIFI_DIRECT_CMD_SEND_CONNECT_REQ)
		{
			if (rsp.result != WIFI_DIRECT_ERROR_NONE)
			{
				WFD_CLIENT_LOG(WFD_LOG_ERROR,
							   "Error!!! Result received = %d \n", rsp.result);
				WFD_CLIENT_LOG(WFD_LOG_ERROR, "Error!!! [%s]\n",
							   __wfd_print_error(rsp.result));
				__WFD_CLIENT_FUNC_END__;
				return rsp.result;
			}
			else
			{
				WFD_CLIENT_LOG(WFD_LOG_ERROR,
							   "wifi_direct_connect() SUCCESS \n");
			}
		}
		else
		{
			WFD_CLIENT_LOG(WFD_LOG_ERROR, "Error!!! Invalid resp cmd = %d\n",
						   rsp.cmd);
			return WIFI_DIRECT_ERROR_OPERATION_FAILED;
		}
	}

	__WFD_CLIENT_FUNC_END__;

	return WIFI_DIRECT_ERROR_NONE;
}


int wifi_direct_foreach_connected_peers(wifi_direct_connected_peer_cb callback, void *user_data)
{
	wifi_direct_client_info_s *client_info = __wfd_get_control();

	__WFD_CLIENT_FUNC_START__;

	if ((client_info->is_registered == false)
		|| (client_info->client_id == WFD_INVALID_ID))
	{
		WFD_CLIENT_LOG(WFD_LOG_ERROR, "Client is NOT registered.\n");
		__WFD_CLIENT_FUNC_END__;
		return WIFI_DIRECT_ERROR_NOT_INITIALIZED;
	}

	if (callback == NULL)
	{
		WFD_CLIENT_LOG(WFD_LOG_ERROR, "NULL Param [callback]!\n");
		__WFD_CLIENT_FUNC_END__;
		return WIFI_DIRECT_ERROR_INVALID_PARAMETER;
	}

	wifi_direct_client_request_s req;
	wifi_direct_client_response_s rsp;
	int i;

	int status = WIFI_DIRECT_ERROR_NONE;

	memset(&req, 0, sizeof(wifi_direct_client_request_s));
	memset(&rsp, 0, sizeof(wifi_direct_client_response_s));

	req.cmd = WIFI_DIRECT_CMD_GET_CONNECTED_PEERS_INFO;
	req.client_id = client_info->client_id;

	status =
		__wfd_client_send_request(client_info->sync_sockfd, &req,
								  sizeof(wifi_direct_client_request_s));
	if (status != WIFI_DIRECT_ERROR_NONE)
	{
		WFD_CLIENT_LOG(WFD_LOG_ERROR,
					   "Error!!! writing to socket, Errno = %s\n",
					   strerror(errno));
		WFD_CLIENT_LOG(WFD_LOG_ERROR, "Error!!! [%s]\n",
					   __wfd_print_error(status));
		client_info->sync_sockfd = -1;
		__wfd_reset_control();
		__WFD_CLIENT_FUNC_END__;
		return WIFI_DIRECT_ERROR_COMMUNICATION_FAILED;
	}

	if ((status =
		 __wfd_client_read_socket(client_info->sync_sockfd, (char *) &rsp,
								  sizeof(wifi_direct_client_response_s))) <= 0)
	{
		WFD_CLIENT_LOG(WFD_LOG_ERROR,
					   "Error!!! reading socket, status = %d errno = %s\n",
					   status, strerror(errno));
		client_info->sync_sockfd = -1;
		__wfd_reset_control();
		__WFD_CLIENT_FUNC_END__;
		return WIFI_DIRECT_ERROR_COMMUNICATION_FAILED;
	}
	else
	{
		if (rsp.cmd == WIFI_DIRECT_CMD_GET_CONNECTED_PEERS_INFO)
		{
			if (rsp.result != WIFI_DIRECT_ERROR_NONE)
			{
				WFD_CLIENT_LOG(WFD_LOG_ERROR,
							   "Error!!! Result received = %d \n", rsp.result);
				WFD_CLIENT_LOG(WFD_LOG_ERROR, "Error!!! [%s]\n",
							   __wfd_print_error(rsp.result));
				__WFD_CLIENT_FUNC_END__;
				return rsp.result;
			}
			else
			{

				int num = rsp.param1;
				int status = 0;
				wfd_connected_peer_info_s *buff = NULL;

				WFD_CLIENT_LOG(WFD_LOG_LOW, "Num of connected peers = %d \n",
							   (int) rsp.param1);

				if (num > 0)
				{
					buff =
						(wfd_connected_peer_info_s *) malloc(num *
															 sizeof
															 (wfd_connected_peer_info_s));
					if (buff == NULL)
					{
						WFD_CLIENT_LOG(WFD_LOG_ERROR, "malloc() failed!!!.\n");
						return WIFI_DIRECT_ERROR_OPERATION_FAILED;
					}

					status =
						__wfd_client_read_more_data(client_info->sync_sockfd,
													buff,
													num *
													sizeof
													(wfd_connected_peer_info_s));
					if (status != WIFI_DIRECT_ERROR_NONE)
					{
						if (NULL != buff)
							free(buff);
						WFD_CLIENT_LOG(WFD_LOG_ERROR, "socket read error.\n");
						return WIFI_DIRECT_ERROR_OPERATION_FAILED;
					}
				}

				__wfd_client_print_connected_peer_info(buff, num);

				WFD_CLIENT_LOG(WFD_LOG_LOW,
							   "wifi_direct_foreach_connected_peers() SUCCESS\n");

				wifi_direct_connected_peer_info_s *peer_list;

				for (i = 0; i < num; i++)
				{
					peer_list = (wifi_direct_connected_peer_info_s *) calloc(1, sizeof(wifi_direct_connected_peer_info_s));
					peer_list->ssid = strdup(buff[i].ssid);
					peer_list->ip_address= (char *) calloc(1, 16);
					snprintf(peer_list->ip_address, 16, IPSTR, IP2STR(buff[i].ip_address));
					peer_list->mac_address = (char *) calloc(1, 18);
					snprintf(peer_list->mac_address, 18, MACSTR, MAC2STR(buff[i].mac_address));
					peer_list->interface_address = (char *) calloc(1, 18);
					snprintf(peer_list->interface_address, 18, MACSTR, MAC2STR(buff[i].intf_mac_address));
					peer_list->p2p_supported = buff[i].is_p2p;
					peer_list->primary_device_type = buff[i].category;
					peer_list->channel = buff[i].channel;
					
					if (!callback(peer_list, user_data))
						break;
				}

				if (NULL != buff)
					free(buff);

			}
		}
		else
		{
			WFD_CLIENT_LOG(WFD_LOG_ERROR, "Error!!! Invalid resp cmd = %d\n",
						   rsp.cmd);
			return WIFI_DIRECT_ERROR_OPERATION_FAILED;
		}
	}

	__WFD_CLIENT_FUNC_END__;

	return WIFI_DIRECT_ERROR_NONE;
}


int wifi_direct_create_group(void)
{
	wifi_direct_client_info_s *client_info = __wfd_get_control();

	__WFD_CLIENT_FUNC_START__;

	if ((client_info->is_registered == false)
		|| (client_info->client_id == WFD_INVALID_ID))
	{
		WFD_CLIENT_LOG(WFD_LOG_ERROR, "Client is NOT registered.\n");
		__WFD_CLIENT_FUNC_END__;
		return WIFI_DIRECT_ERROR_NOT_INITIALIZED;
	}

	wifi_direct_client_request_s req;
	wifi_direct_client_response_s rsp;

	int status = WIFI_DIRECT_ERROR_NONE;

	memset(&req, 0, sizeof(wifi_direct_client_request_s));
	memset(&rsp, 0, sizeof(wifi_direct_client_response_s));

	req.cmd = WIFI_DIRECT_CMD_CREATE_GROUP;
	req.client_id = client_info->client_id;

	status =
		__wfd_client_send_request(client_info->sync_sockfd, &req,
								  sizeof(wifi_direct_client_request_s));
	if (status != WIFI_DIRECT_ERROR_NONE)
	{
		WFD_CLIENT_LOG(WFD_LOG_ERROR,
					   "Error!!! writing to socket, Errno = %s\n",
					   strerror(errno));
		WFD_CLIENT_LOG(WFD_LOG_ERROR, "Error!!! [%s]\n",
					   __wfd_print_error(status));
		client_info->sync_sockfd = -1;
		__wfd_reset_control();
		__WFD_CLIENT_FUNC_END__;
		return WIFI_DIRECT_ERROR_COMMUNICATION_FAILED;
	}

	if ((status =
		 __wfd_client_read_socket(client_info->sync_sockfd, (char *) &rsp,
								  sizeof(wifi_direct_client_response_s))) <= 0)
	{
		WFD_CLIENT_LOG(WFD_LOG_ERROR,
					   "Error!!! reading socket, status = %d errno = %s\n",
					   status, strerror(errno));
		client_info->sync_sockfd = -1;
		__wfd_reset_control();
		__WFD_CLIENT_FUNC_END__;
		return WIFI_DIRECT_ERROR_COMMUNICATION_FAILED;
	}
	else
	{
		if (rsp.cmd == WIFI_DIRECT_CMD_CREATE_GROUP)
		{
			if (rsp.result != WIFI_DIRECT_ERROR_NONE)
			{
				WFD_CLIENT_LOG(WFD_LOG_ERROR,
							   "Error!!! Result received = %d \n", rsp.result);
				WFD_CLIENT_LOG(WFD_LOG_ERROR, "Error!!! [%s]\n",
							   __wfd_print_error(rsp.result));
				__WFD_CLIENT_FUNC_END__;
				return rsp.result;
			}
			else
			{
				WFD_CLIENT_LOG(WFD_LOG_ERROR,
							   "wifi_direct_create_group() SUCCESS \n");
			}
		}
		else
		{
			WFD_CLIENT_LOG(WFD_LOG_ERROR, "Error!!! Invalid resp cmd = %d\n",
						   rsp.cmd);
			return WIFI_DIRECT_ERROR_OPERATION_FAILED;
		}
	}

	__WFD_CLIENT_FUNC_END__;

	return WIFI_DIRECT_ERROR_NONE;
}


int wifi_direct_destroy_group(void)
{
	wifi_direct_client_info_s *client_info = __wfd_get_control();

	__WFD_CLIENT_FUNC_START__;

	if ((client_info->is_registered == false)
		|| (client_info->client_id == WFD_INVALID_ID))
	{
		WFD_CLIENT_LOG(WFD_LOG_ERROR, "Client is NOT registered.\n");
		__WFD_CLIENT_FUNC_END__;
		return WIFI_DIRECT_ERROR_NOT_INITIALIZED;
	}

	wifi_direct_client_request_s req;
	wifi_direct_client_response_s rsp;

	int status = WIFI_DIRECT_ERROR_NONE;

	memset(&req, 0, sizeof(wifi_direct_client_request_s));
	memset(&rsp, 0, sizeof(wifi_direct_client_response_s));

	req.cmd = WIFI_DIRECT_CMD_CANCEL_GROUP;
	req.client_id = client_info->client_id;

	status =
		__wfd_client_send_request(client_info->sync_sockfd, &req,
								  sizeof(wifi_direct_client_request_s));
	if (status != WIFI_DIRECT_ERROR_NONE)
	{
		WFD_CLIENT_LOG(WFD_LOG_ERROR,
					   "Error!!! writing to socket, Errno = %s\n",
					   strerror(errno));
		WFD_CLIENT_LOG(WFD_LOG_ERROR, "Error!!! [%s]\n",
					   __wfd_print_error(status));
		client_info->sync_sockfd = -1;
		__wfd_reset_control();
		__WFD_CLIENT_FUNC_END__;
		return WIFI_DIRECT_ERROR_COMMUNICATION_FAILED;
	}

	if ((status =
		 __wfd_client_read_socket(client_info->sync_sockfd, (char *) &rsp,
								  sizeof(wifi_direct_client_response_s))) <= 0)
	{
		WFD_CLIENT_LOG(WFD_LOG_ERROR,
					   "Error!!! reading socket, status = %d errno = %s\n",
					   status, strerror(errno));
		client_info->sync_sockfd = -1;
		__wfd_reset_control();
		__WFD_CLIENT_FUNC_END__;
		return WIFI_DIRECT_ERROR_COMMUNICATION_FAILED;
	}
	else
	{
		if (rsp.cmd == WIFI_DIRECT_CMD_CANCEL_GROUP)
		{
			if (rsp.result != WIFI_DIRECT_ERROR_NONE)
			{
				WFD_CLIENT_LOG(WFD_LOG_ERROR,
							   "Error!!! Result received = %d \n", rsp.result);
				WFD_CLIENT_LOG(WFD_LOG_ERROR, "Error!!! [%s]\n",
							   __wfd_print_error(rsp.result));
				__WFD_CLIENT_FUNC_END__;
				return rsp.result;
			}
			else
			{
				WFD_CLIENT_LOG(WFD_LOG_ERROR,
							   "wifi_direct_destroy_group() SUCCESS \n");
			}
		}
		else
		{
			WFD_CLIENT_LOG(WFD_LOG_ERROR, "Error!!! Invalid resp cmd = %d\n",
						   rsp.cmd);
			return WIFI_DIRECT_ERROR_OPERATION_FAILED;
		}
	}

	__WFD_CLIENT_FUNC_END__;

	return WIFI_DIRECT_ERROR_NONE;
}


int wifi_direct_is_group_owner(bool * owner)
{
	wifi_direct_client_info_s *client_info = __wfd_get_control();

	__WFD_CLIENT_FUNC_START__;

	if (owner == NULL)
	{
		WFD_CLIENT_LOG(WFD_LOG_ERROR, "NULL Param [owner]!\n");
		__WFD_CLIENT_FUNC_END__;
		return WIFI_DIRECT_ERROR_INVALID_PARAMETER;
	}

	if ((client_info->is_registered == false)
		|| (client_info->client_id == WFD_INVALID_ID))
	{
		WFD_CLIENT_LOG(WFD_LOG_ERROR, "Client is NOT registered.\n");
		__WFD_CLIENT_FUNC_END__;
		return WIFI_DIRECT_ERROR_NOT_INITIALIZED;
	}

	wifi_direct_client_request_s req;
	wifi_direct_client_response_s rsp;

	int status = WIFI_DIRECT_ERROR_NONE;

	memset(&req, 0, sizeof(wifi_direct_client_request_s));
	memset(&rsp, 0, sizeof(wifi_direct_client_response_s));

	req.cmd = WIFI_DIRECT_CMD_IS_GROUPOWNER;
	req.client_id = client_info->client_id;

	status =
		__wfd_client_send_request(client_info->sync_sockfd, &req,
								  sizeof(wifi_direct_client_request_s));
	if (status != WIFI_DIRECT_ERROR_NONE)
	{
		WFD_CLIENT_LOG(WFD_LOG_ERROR,
					   "Error!!! writing to socket, Errno = %s\n",
					   strerror(errno));
		WFD_CLIENT_LOG(WFD_LOG_ERROR, "Error!!! [%s]\n",
					   __wfd_print_error(status));
		client_info->sync_sockfd = -1;
		__wfd_reset_control();
		__WFD_CLIENT_FUNC_END__;
		return WIFI_DIRECT_ERROR_COMMUNICATION_FAILED;
	}

	if ((status =
		 __wfd_client_read_socket(client_info->sync_sockfd, (char *) &rsp,
								  sizeof(wifi_direct_client_response_s))) <= 0)
	{
		WFD_CLIENT_LOG(WFD_LOG_ERROR,
					   "Error!!! reading socket, status = %d errno = %s\n",
					   status, strerror(errno));
		client_info->sync_sockfd = -1;
		__wfd_reset_control();
		__WFD_CLIENT_FUNC_END__;
		return WIFI_DIRECT_ERROR_COMMUNICATION_FAILED;
	}
	else
	{
		if (rsp.cmd == WIFI_DIRECT_CMD_IS_GROUPOWNER)
		{
			if (rsp.result != WIFI_DIRECT_ERROR_NONE)
			{
				WFD_CLIENT_LOG(WFD_LOG_LOW, "Error!!! Result received = %d \n",
							   rsp.result);
				WFD_CLIENT_LOG(WFD_LOG_LOW, "Error!!! [%s]\n",
							   __wfd_print_error(rsp.result));
				__WFD_CLIENT_FUNC_END__;
				return rsp.result;
			}
			else
			{
				WFD_CLIENT_LOG(WFD_LOG_LOW,
							   "wifi_direct_is_group_owner() %s SUCCESS \n",
							   rsp.param2);
				*owner = (bool) rsp.param1;
			}
		}
		else
		{
			WFD_CLIENT_LOG(WFD_LOG_ERROR, "Error!!! Invalid resp cmd = %d\n",
						   rsp.cmd);
			return WIFI_DIRECT_ERROR_OPERATION_FAILED;
		}
	}

	__WFD_CLIENT_FUNC_END__;

	return WIFI_DIRECT_ERROR_NONE;

}


int wifi_direct_is_autonomous_group(bool * autonomous_group)
{
	wifi_direct_client_info_s *client_info = __wfd_get_control();

	__WFD_CLIENT_FUNC_START__;

	if (autonomous_group == NULL)
	{
		WFD_CLIENT_LOG(WFD_LOG_ERROR, "NULL Param [autonomous_group]!\n");
		__WFD_CLIENT_FUNC_END__;
		return WIFI_DIRECT_ERROR_INVALID_PARAMETER;
	}

	if ((client_info->is_registered == false)
		|| (client_info->client_id == WFD_INVALID_ID))
	{
		WFD_CLIENT_LOG(WFD_LOG_ERROR, "Client is NOT registered.\n");
		__WFD_CLIENT_FUNC_END__;
		return WIFI_DIRECT_ERROR_NOT_INITIALIZED;
	}

	wifi_direct_client_request_s req;
	wifi_direct_client_response_s rsp;

	int status = WIFI_DIRECT_ERROR_NONE;

	memset(&req, 0, sizeof(wifi_direct_client_request_s));
	memset(&rsp, 0, sizeof(wifi_direct_client_response_s));

	req.cmd = WIFI_DIRECT_CMD_IS_AUTONOMOUS_GROUP;
	req.client_id = client_info->client_id;

	status =
		__wfd_client_send_request(client_info->sync_sockfd, &req,
								  sizeof(wifi_direct_client_request_s));
	if (status != WIFI_DIRECT_ERROR_NONE)
	{
		WFD_CLIENT_LOG(WFD_LOG_ERROR,
					   "Error!!! writing to socket, Errno = %s\n",
					   strerror(errno));
		WFD_CLIENT_LOG(WFD_LOG_ERROR, "Error!!! [%s]\n",
					   __wfd_print_error(status));
		client_info->sync_sockfd = -1;
		__wfd_reset_control();
		__WFD_CLIENT_FUNC_END__;
		return WIFI_DIRECT_ERROR_COMMUNICATION_FAILED;
	}

	if ((status =
		 __wfd_client_read_socket(client_info->sync_sockfd, (char *) &rsp,
								  sizeof(wifi_direct_client_response_s))) <= 0)
	{
		WFD_CLIENT_LOG(WFD_LOG_ERROR,
					   "Error!!! reading socket, status = %d errno = %s\n",
					   status, strerror(errno));
		client_info->sync_sockfd = -1;
		__wfd_reset_control();
		__WFD_CLIENT_FUNC_END__;
		return WIFI_DIRECT_ERROR_COMMUNICATION_FAILED;
	}
	else
	{
		if (rsp.cmd == WIFI_DIRECT_CMD_IS_AUTONOMOUS_GROUP)
		{
			if (rsp.result != WIFI_DIRECT_ERROR_NONE)
			{
				WFD_CLIENT_LOG(WFD_LOG_LOW, "Error!!! Result received = %d \n",
							   rsp.result);
				WFD_CLIENT_LOG(WFD_LOG_LOW, "Error!!! [%s]\n",
							   __wfd_print_error(rsp.result));
				__WFD_CLIENT_FUNC_END__;
				return rsp.result;
			}
			else
			{
				WFD_CLIENT_LOG(WFD_LOG_LOW,
							   "wifi_direct_is_autonomous_group() %s SUCCESS \n",
							   rsp.param2);
				*autonomous_group = (bool) rsp.param1;
			}
		}
		else
		{
			WFD_CLIENT_LOG(WFD_LOG_ERROR, "Error!!! Invalid resp cmd = %d\n",
						   rsp.cmd);
			return WIFI_DIRECT_ERROR_OPERATION_FAILED;
		}
	}

	__WFD_CLIENT_FUNC_END__;

	return WIFI_DIRECT_ERROR_NONE;

}


int wifi_direct_set_group_owner_intent(int intent)
{
	wifi_direct_client_info_s *client_info = __wfd_get_control();

	__WFD_CLIENT_FUNC_START__;

	if ((client_info->is_registered == false)
		|| (client_info->client_id == WFD_INVALID_ID))
	{
		WFD_CLIENT_LOG(WFD_LOG_ERROR, "Client is NOT registered.\n");
		__WFD_CLIENT_FUNC_END__;
		return WIFI_DIRECT_ERROR_NOT_INITIALIZED;
	}

	if (intent < 0 || intent > 15)
	{
		WFD_CLIENT_LOG(WFD_LOG_ERROR, "Invalid Param : intent[%d]\n", intent);
		__WFD_CLIENT_FUNC_END__;
		return WIFI_DIRECT_ERROR_INVALID_PARAMETER;
	}

	wifi_direct_client_request_s req;
	wifi_direct_client_response_s rsp;

	int status = WIFI_DIRECT_ERROR_NONE;

	memset(&req, 0, sizeof(wifi_direct_client_request_s));
	memset(&rsp, 0, sizeof(wifi_direct_client_response_s));

	req.cmd = WIFI_DIRECT_CMD_SET_GO_INTENT;
	req.client_id = client_info->client_id;

	status =__wfd_client_send_request(client_info->sync_sockfd, &req,
								  sizeof(wifi_direct_client_request_s));
	if (status != WIFI_DIRECT_ERROR_NONE)
	{
		WFD_CLIENT_LOG(WFD_LOG_ERROR,
					   "Error!!! writing to socket, Errno = %s\n",
					   strerror(errno));
		WFD_CLIENT_LOG(WFD_LOG_ERROR, "Error!!! [%s]\n",
					   __wfd_print_error(status));
		client_info->sync_sockfd = -1;
		__wfd_reset_control();
		__WFD_CLIENT_FUNC_END__;
		return WIFI_DIRECT_ERROR_COMMUNICATION_FAILED;
	}

	WFD_CLIENT_LOG(WFD_LOG_LOW, "writing msg hdr is success!\n");

	status =
		__wfd_client_send_request(client_info->sync_sockfd, &intent,
								  sizeof(int));
	if (status != WIFI_DIRECT_ERROR_NONE)
	{
		WFD_CLIENT_LOG(WFD_LOG_ERROR,
					   "Error!!! writing to socket, Errno = %s\n",
					   strerror(errno));
		WFD_CLIENT_LOG(WFD_LOG_ERROR, "Error!!! [%s]\n",
					   __wfd_print_error(status));
		client_info->sync_sockfd = -1;
		__wfd_reset_control();
		__WFD_CLIENT_FUNC_END__;
		return WIFI_DIRECT_ERROR_COMMUNICATION_FAILED;
	}

	if ((status =
		 __wfd_client_read_socket(client_info->sync_sockfd, (char *) &rsp,
								  sizeof(wifi_direct_client_response_s))) <= 0)
	{
		WFD_CLIENT_LOG(WFD_LOG_ERROR,
					   "Error!!! reading socket, status = %d errno = %s\n",
					   status, strerror(errno));
		client_info->sync_sockfd = -1;
		__wfd_reset_control();
		__WFD_CLIENT_FUNC_END__;
		return WIFI_DIRECT_ERROR_COMMUNICATION_FAILED;
	}
	else
	{
		if (rsp.cmd == WIFI_DIRECT_CMD_SET_GO_INTENT)
		{
			if (rsp.result != WIFI_DIRECT_ERROR_NONE)
			{
				WFD_CLIENT_LOG(WFD_LOG_LOW, "Error!!! Result received = %d \n",
							   rsp.result);
				WFD_CLIENT_LOG(WFD_LOG_LOW, "Error!!! [%s]\n",
							   __wfd_print_error(rsp.result));
				__WFD_CLIENT_FUNC_END__;
				return rsp.result;
			}
		}
		else
		{
			WFD_CLIENT_LOG(WFD_LOG_ERROR, "Error!!! Invalid resp cmd = %d\n",
						   rsp.cmd);
			return WIFI_DIRECT_ERROR_OPERATION_FAILED;
		}
	}

	__WFD_CLIENT_FUNC_END__;

	return WIFI_DIRECT_ERROR_NONE;
}


int wifi_direct_get_group_owner_intent(int* intent)
{
	wifi_direct_client_info_s *client_info = __wfd_get_control();

	__WFD_CLIENT_FUNC_START__;

	if ((client_info->is_registered == false)
		|| (client_info->client_id == WFD_INVALID_ID))
	{
		WFD_CLIENT_LOG(WFD_LOG_ERROR, "Client is NOT registered.\n");
		__WFD_CLIENT_FUNC_END__;
		return WIFI_DIRECT_ERROR_NOT_INITIALIZED;
	}

	wifi_direct_client_request_s req;
	wifi_direct_client_response_s rsp;

	int status = WIFI_DIRECT_ERROR_NONE;

	memset(&req, 0, sizeof(wifi_direct_client_request_s));
	memset(&rsp, 0, sizeof(wifi_direct_client_response_s));

	req.cmd = WIFI_DIRECT_CMD_GET_GO_INTENT;
	req.client_id = client_info->client_id;

	status =
		__wfd_client_send_request(client_info->sync_sockfd, &req,
								  sizeof(wifi_direct_client_request_s));
	if (status != WIFI_DIRECT_ERROR_NONE)
	{
		WFD_CLIENT_LOG(WFD_LOG_ERROR,
					   "Error!!! writing to socket, Errno = %s\n",
					   strerror(errno));
		WFD_CLIENT_LOG(WFD_LOG_ERROR, "Error!!! [%s]\n",
					   __wfd_print_error(status));
		client_info->sync_sockfd = -1;
		__wfd_reset_control();
		__WFD_CLIENT_FUNC_END__;
		return WIFI_DIRECT_ERROR_COMMUNICATION_FAILED;
	}

	if ((status =
		 __wfd_client_read_socket(client_info->sync_sockfd, (char *) &rsp,
								  sizeof(wifi_direct_client_response_s))) <= 0)
	{
		WFD_CLIENT_LOG(WFD_LOG_ERROR,
					   "Error!!! reading socket, status = %d errno = %s\n",
					   status, strerror(errno));
		client_info->sync_sockfd = -1;
		__wfd_reset_control();
		__WFD_CLIENT_FUNC_END__;
		return WIFI_DIRECT_ERROR_COMMUNICATION_FAILED;
	}
	else
	{
		if (rsp.cmd == WIFI_DIRECT_CMD_GET_GO_INTENT)
		{
			if (rsp.result != WIFI_DIRECT_ERROR_NONE)
			{
				WFD_CLIENT_LOG(WFD_LOG_LOW, "Error!!! Result received = %d \n",
							   rsp.result);
				WFD_CLIENT_LOG(WFD_LOG_LOW, "Error!!! [%s]\n",
							   __wfd_print_error(rsp.result));
				__WFD_CLIENT_FUNC_END__;
				return rsp.result;
			}
			else
			{
				WFD_CLIENT_LOG(WFD_LOG_LOW,
							   "int wifi_direct_get_group_owner_intent() intent[%d] SUCCESS \n",
							   rsp.param1);
				*intent = rsp.param1;
			}
		}
		else
		{
			WFD_CLIENT_LOG(WFD_LOG_ERROR, "Error!!! Invalid resp cmd = %d\n",
						   rsp.cmd);
			return WIFI_DIRECT_ERROR_OPERATION_FAILED;
		}
	}

	__WFD_CLIENT_FUNC_END__;

	return WIFI_DIRECT_ERROR_NONE;
}

int wifi_direct_set_max_clients(int max)
{
	wifi_direct_client_info_s *client_info = __wfd_get_control();

	__WFD_CLIENT_FUNC_START__;

	if ((client_info->is_registered == false)
		|| (client_info->client_id == WFD_INVALID_ID))
	{
		WFD_CLIENT_LOG(WFD_LOG_ERROR, "Client is NOT registered.\n");
		__WFD_CLIENT_FUNC_END__;
		return WIFI_DIRECT_ERROR_NOT_INITIALIZED;
	}

	WFD_CLIENT_LOG(WFD_LOG_LOW, "max client [%d]\n", max);

	wifi_direct_client_request_s req;
	wifi_direct_client_response_s rsp;

	int status = WIFI_DIRECT_ERROR_NONE;

	memset(&req, 0, sizeof(wifi_direct_client_request_s));
	memset(&rsp, 0, sizeof(wifi_direct_client_response_s));

	req.cmd = WIFI_DIRECT_CMD_SET_MAX_CLIENT;
	req.client_id = client_info->client_id;

	status =__wfd_client_send_request(client_info->sync_sockfd, &req,
								  sizeof(wifi_direct_client_request_s));
	if (status != WIFI_DIRECT_ERROR_NONE)
	{
		WFD_CLIENT_LOG(WFD_LOG_ERROR,
					   "Error!!! writing to socket, Errno = %s\n",
					   strerror(errno));
		WFD_CLIENT_LOG(WFD_LOG_ERROR, "Error!!! [%s]\n",
					   __wfd_print_error(status));
		client_info->sync_sockfd = -1;
		__wfd_reset_control();
		__WFD_CLIENT_FUNC_END__;
		return WIFI_DIRECT_ERROR_COMMUNICATION_FAILED;
	}

	WFD_CLIENT_LOG(WFD_LOG_LOW, "writing msg hdr is success!\n");

	status =
		__wfd_client_send_request(client_info->sync_sockfd, &max,
								  sizeof(int));
	if (status != WIFI_DIRECT_ERROR_NONE)
	{
		WFD_CLIENT_LOG(WFD_LOG_ERROR,
					   "Error!!! writing to socket, Errno = %s\n",
					   strerror(errno));
		WFD_CLIENT_LOG(WFD_LOG_ERROR, "Error!!! [%s]\n",
					   __wfd_print_error(status));
		client_info->sync_sockfd = -1;
		__wfd_reset_control();
		__WFD_CLIENT_FUNC_END__;
		return WIFI_DIRECT_ERROR_COMMUNICATION_FAILED;
	}

	if ((status =
		 __wfd_client_read_socket(client_info->sync_sockfd, (char *) &rsp,
								  sizeof(wifi_direct_client_response_s))) <= 0)
	{
		WFD_CLIENT_LOG(WFD_LOG_ERROR,
					   "Error!!! reading socket, status = %d errno = %s\n",
					   status, strerror(errno));
		client_info->sync_sockfd = -1;
		__wfd_reset_control();
		__WFD_CLIENT_FUNC_END__;
		return WIFI_DIRECT_ERROR_COMMUNICATION_FAILED;
	}
	else
	{
		if (rsp.cmd == WIFI_DIRECT_CMD_SET_MAX_CLIENT)
		{
			if (rsp.result != WIFI_DIRECT_ERROR_NONE)
			{
				WFD_CLIENT_LOG(WFD_LOG_LOW, "Error!!! Result received = %d \n",
							   rsp.result);
				WFD_CLIENT_LOG(WFD_LOG_LOW, "Error!!! [%s]\n",
							   __wfd_print_error(rsp.result));
				__WFD_CLIENT_FUNC_END__;
				return rsp.result;
			}
		}
		else
		{
			WFD_CLIENT_LOG(WFD_LOG_ERROR, "Error!!! Invalid resp cmd = %d\n",
						   rsp.cmd);
			return WIFI_DIRECT_ERROR_OPERATION_FAILED;
		}
	}

	__WFD_CLIENT_FUNC_END__;

	return WIFI_DIRECT_ERROR_NONE;
}

int wifi_direct_get_max_clients(int* max)
{
	wifi_direct_client_info_s *client_info = __wfd_get_control();

	__WFD_CLIENT_FUNC_START__;

	if ((client_info->is_registered == false)
		|| (client_info->client_id == WFD_INVALID_ID))
	{
		WFD_CLIENT_LOG(WFD_LOG_ERROR, "Client is NOT registered.\n");
		__WFD_CLIENT_FUNC_END__;
		return WIFI_DIRECT_ERROR_NOT_INITIALIZED;
	}

	wifi_direct_client_request_s req;
	wifi_direct_client_response_s rsp;

	int status = WIFI_DIRECT_ERROR_NONE;

	memset(&req, 0, sizeof(wifi_direct_client_request_s));
	memset(&rsp, 0, sizeof(wifi_direct_client_response_s));

	req.cmd = WIFI_DIRECT_CMD_GET_MAX_CLIENT;
	req.client_id = client_info->client_id;

	status =
		__wfd_client_send_request(client_info->sync_sockfd, &req,
								  sizeof(wifi_direct_client_request_s));
	if (status != WIFI_DIRECT_ERROR_NONE)
	{
		WFD_CLIENT_LOG(WFD_LOG_ERROR,
					   "Error!!! writing to socket, Errno = %s\n",
					   strerror(errno));
		WFD_CLIENT_LOG(WFD_LOG_ERROR, "Error!!! [%s]\n",
					   __wfd_print_error(status));
		client_info->sync_sockfd = -1;
		__wfd_reset_control();
		__WFD_CLIENT_FUNC_END__;
		return WIFI_DIRECT_ERROR_COMMUNICATION_FAILED;
	}

	if ((status =
		 __wfd_client_read_socket(client_info->sync_sockfd, (char *) &rsp,
								  sizeof(wifi_direct_client_response_s))) <= 0)
	{
		WFD_CLIENT_LOG(WFD_LOG_ERROR,
					   "Error!!! reading socket, status = %d errno = %s\n",
					   status, strerror(errno));
		client_info->sync_sockfd = -1;
		__wfd_reset_control();
		__WFD_CLIENT_FUNC_END__;
		return WIFI_DIRECT_ERROR_COMMUNICATION_FAILED;
	}
	else
	{
		if (rsp.cmd == WIFI_DIRECT_CMD_GET_MAX_CLIENT)
		{
			if (rsp.result != WIFI_DIRECT_ERROR_NONE)
			{
				WFD_CLIENT_LOG(WFD_LOG_LOW, "Error!!! Result received = %d \n",
							   rsp.result);
				WFD_CLIENT_LOG(WFD_LOG_LOW, "Error!!! [%s]\n",
							   __wfd_print_error(rsp.result));
				__WFD_CLIENT_FUNC_END__;
				return rsp.result;
			}
			else
			{
				WFD_CLIENT_LOG(WFD_LOG_LOW,
							   "int wifi_direct_get_max_clients() max_client[%d] SUCCESS \n",
							   rsp.param1);
				*max = rsp.param1;
			}
		}
		else
		{
			WFD_CLIENT_LOG(WFD_LOG_ERROR, "Error!!! Invalid resp cmd = %d\n",
						   rsp.cmd);
			return WIFI_DIRECT_ERROR_OPERATION_FAILED;
		}
	}

	__WFD_CLIENT_FUNC_END__;

	return WIFI_DIRECT_ERROR_NONE;
}

int wifi_direct_get_own_group_channel(int* channel)
{
	wifi_direct_client_info_s *client_info = __wfd_get_control();

	__WFD_CLIENT_FUNC_START__;

	if ((client_info->is_registered == false)
		|| (client_info->client_id == WFD_INVALID_ID))
	{
		WFD_CLIENT_LOG(WFD_LOG_ERROR, "Client is NOT registered.\n");
		__WFD_CLIENT_FUNC_END__;
		return WIFI_DIRECT_ERROR_NOT_INITIALIZED;
	}

	wifi_direct_client_request_s req;
	wifi_direct_client_response_s rsp;

	int ret = WIFI_DIRECT_ERROR_NONE;

	memset(&req, 0, sizeof(wifi_direct_client_request_s));
	memset(&rsp, 0, sizeof(wifi_direct_client_response_s));

	req.cmd = WIFI_DIRECT_CMD_GET_OWN_GROUP_CHANNEL;
	req.client_id = client_info->client_id;

	ret =
		__wfd_client_send_request(client_info->sync_sockfd, &req,
								  sizeof(wifi_direct_client_request_s));
	if (ret != WIFI_DIRECT_ERROR_NONE)
	{
		WFD_CLIENT_LOG(WFD_LOG_ERROR,
					   "Error!!! writing to socket, Errno = %s\n",
					   strerror(errno));
		WFD_CLIENT_LOG(WFD_LOG_ERROR, "Error!!! [%s]\n",
					   __wfd_print_error(ret));
		client_info->sync_sockfd = -1;
		__wfd_reset_control();
		__WFD_CLIENT_FUNC_END__;
		return WIFI_DIRECT_ERROR_COMMUNICATION_FAILED;
	}

	if ((ret =
		 __wfd_client_read_socket(client_info->sync_sockfd, (char *) &rsp,
								  sizeof(wifi_direct_client_response_s))) <= 0)
	{
		WFD_CLIENT_LOG(WFD_LOG_ERROR,
					   "Error!!! reading socket, status = %d errno = %s\n", ret,
					   strerror(errno));
		client_info->sync_sockfd = -1;
		__wfd_reset_control();
		__WFD_CLIENT_FUNC_END__;
		return WIFI_DIRECT_ERROR_COMMUNICATION_FAILED;
	}
	else
	{
		if (rsp.cmd == WIFI_DIRECT_CMD_GET_OWN_GROUP_CHANNEL)
		{
			if (rsp.result != WIFI_DIRECT_ERROR_NONE)
			{
				WFD_CLIENT_LOG(WFD_LOG_LOW, "Error!!! Result received = %d \n",
							   rsp.result);
				WFD_CLIENT_LOG(WFD_LOG_LOW, "Error!!! [%s]\n",
							   __wfd_print_error(rsp.result));
				__WFD_CLIENT_FUNC_END__;
				return rsp.result;
			}
			else
			{
				WFD_CLIENT_LOG(WFD_LOG_LOW, "channel = [%d]\n",
							   (int) rsp.param1);
				*channel = rsp.param1;
			}
		}
		else
		{
			WFD_CLIENT_LOG(WFD_LOG_ERROR, "Error!!! Invalid resp cmd = %d\n",
						   rsp.cmd);
			return WIFI_DIRECT_ERROR_OPERATION_FAILED;
		}
	}

	__WFD_CLIENT_FUNC_END__;

	return WIFI_DIRECT_ERROR_NONE;

}

int wifi_direct_set_wpa_passphrase(char *passphrase)
{
	wifi_direct_client_info_s *client_info = __wfd_get_control();

	__WFD_CLIENT_FUNC_START__;

	if ((client_info->is_registered == false)
		|| (client_info->client_id == WFD_INVALID_ID))
	{
		WFD_CLIENT_LOG(WFD_LOG_ERROR, "Client is NOT registered.\n");
		__WFD_CLIENT_FUNC_END__;
		return WIFI_DIRECT_ERROR_NOT_INITIALIZED;
	}

	if (NULL == passphrase)
	{
		WFD_CLIENT_LOG(WFD_LOG_ERROR, "NULL Param [passphrase]!\n");
		__WFD_CLIENT_FUNC_END__;
		return WIFI_DIRECT_ERROR_INVALID_PARAMETER;
	}

	WFD_CLIENT_LOG(WFD_LOG_ERROR, "passphrase = [%s]\n", passphrase);

	wifi_direct_client_request_s req;
	wifi_direct_client_response_s rsp;

	int status = WIFI_DIRECT_ERROR_NONE;

	memset(&req, 0, sizeof(wifi_direct_client_request_s));
	memset(&rsp, 0, sizeof(wifi_direct_client_response_s));

	req.cmd = WIFI_DIRECT_CMD_SET_WPA;
	req.client_id = client_info->client_id;

	status =
		__wfd_client_send_request(client_info->sync_sockfd, &req,
								  sizeof(wifi_direct_client_request_s));
	if (status != WIFI_DIRECT_ERROR_NONE)
	{
		WFD_CLIENT_LOG(WFD_LOG_ERROR,
					   "Error!!! writing to socket, Errno = %s\n",
					   strerror(errno));
		WFD_CLIENT_LOG(WFD_LOG_ERROR, "Error!!! [%s]\n",
					   __wfd_print_error(status));
		client_info->sync_sockfd = -1;
		__wfd_reset_control();
		__WFD_CLIENT_FUNC_END__;
		return WIFI_DIRECT_ERROR_COMMUNICATION_FAILED;
	}

	WFD_CLIENT_LOG(WFD_LOG_LOW, "writing msg hdr is success!\n");

	status =
		__wfd_client_send_request(client_info->sync_sockfd, passphrase, 64);
	if (status != WIFI_DIRECT_ERROR_NONE)
	{
		WFD_CLIENT_LOG(WFD_LOG_ERROR,
					   "Error!!! writing to socket, Errno = %s\n",
					   strerror(errno));
		WFD_CLIENT_LOG(WFD_LOG_ERROR, "Error!!! [%s]\n",
					   __wfd_print_error(status));
		client_info->sync_sockfd = -1;
		__wfd_reset_control();
		__WFD_CLIENT_FUNC_END__;
		return WIFI_DIRECT_ERROR_COMMUNICATION_FAILED;
	}

	if ((status =
		 __wfd_client_read_socket(client_info->sync_sockfd, (char *) &rsp,
								  sizeof(wifi_direct_client_response_s))) <= 0)
	{
		WFD_CLIENT_LOG(WFD_LOG_ERROR,
					   "Error!!! reading socket, status = %d errno = %s\n",
					   status, strerror(errno));
		client_info->sync_sockfd = -1;
		__wfd_reset_control();
		__WFD_CLIENT_FUNC_END__;
		return WIFI_DIRECT_ERROR_COMMUNICATION_FAILED;
	}
	else
	{
		if (rsp.cmd == WIFI_DIRECT_CMD_SET_WPA)
		{
			if (rsp.result != WIFI_DIRECT_ERROR_NONE)
			{
				WFD_CLIENT_LOG(WFD_LOG_ERROR,
							   "Error!!! Result received = %d \n", rsp.result);
				WFD_CLIENT_LOG(WFD_LOG_ERROR, "Error!!! [%s]\n",
							   __wfd_print_error(rsp.result));
				__WFD_CLIENT_FUNC_END__;
				return rsp.result;
			}
		}
		else
		{
			WFD_CLIENT_LOG(WFD_LOG_ERROR, "Error!!! Invalid resp cmd = %d\n",
						   rsp.cmd);
			return WIFI_DIRECT_ERROR_OPERATION_FAILED;
		}
	}

	__WFD_CLIENT_FUNC_END__;

	return WIFI_DIRECT_ERROR_NONE;
}


int wifi_direct_activate_pushbutton(void)
{
	wifi_direct_client_info_s *client_info = __wfd_get_control();

	__WFD_CLIENT_FUNC_START__;

	if ((client_info->is_registered == false)
		|| (client_info->client_id == WFD_INVALID_ID))
	{
		WFD_CLIENT_LOG(WFD_LOG_ERROR, "Client is NOT registered.\n");
		__WFD_CLIENT_FUNC_END__;
		return WIFI_DIRECT_ERROR_NOT_INITIALIZED;
	}

	wifi_direct_client_request_s req;
	wifi_direct_client_response_s rsp;

	int status = WIFI_DIRECT_ERROR_NONE;

	memset(&req, 0, sizeof(wifi_direct_client_request_s));
	memset(&rsp, 0, sizeof(wifi_direct_client_response_s));

	req.cmd = WIFI_DIRECT_CMD_ACTIVATE_PUSHBUTTON;
	req.client_id = client_info->client_id;

	status =
		__wfd_client_send_request(client_info->sync_sockfd, &req,
								  sizeof(wifi_direct_client_request_s));
	if (status != WIFI_DIRECT_ERROR_NONE)
	{
		WFD_CLIENT_LOG(WFD_LOG_ERROR,
					   "Error!!! writing to socket, Errno = %s\n",
					   strerror(errno));
		WFD_CLIENT_LOG(WFD_LOG_ERROR, "Error!!! [%s]\n",
					   __wfd_print_error(status));
		client_info->sync_sockfd = -1;
		__wfd_reset_control();
		__WFD_CLIENT_FUNC_END__;
		return WIFI_DIRECT_ERROR_COMMUNICATION_FAILED;
	}

	if ((status =
		 __wfd_client_read_socket(client_info->sync_sockfd, (char *) &rsp,
								  sizeof(wifi_direct_client_response_s))) <= 0)
	{
		WFD_CLIENT_LOG(WFD_LOG_ERROR,
					   "Error!!! reading socket, status = %d errno = %s\n",
					   status, strerror(errno));
		client_info->sync_sockfd = -1;
		__wfd_reset_control();
		__WFD_CLIENT_FUNC_END__;
		return WIFI_DIRECT_ERROR_COMMUNICATION_FAILED;
	}
	else
	{
		if (rsp.cmd == WIFI_DIRECT_CMD_ACTIVATE_PUSHBUTTON)
		{
			if (rsp.result != WIFI_DIRECT_ERROR_NONE)
			{
				WFD_CLIENT_LOG(WFD_LOG_LOW, "Error!!! Result received = %d \n",
							   rsp.result);
				WFD_CLIENT_LOG(WFD_LOG_LOW, "Error!!! [%s]\n",
							   __wfd_print_error(rsp.result));
				__WFD_CLIENT_FUNC_END__;
				return rsp.result;
			}
			else
			{
				WFD_CLIENT_LOG(WFD_LOG_LOW,
							   "wifi_direct_activate_pushbutton() SUCCESS \n");
			}
		}
		else
		{
			WFD_CLIENT_LOG(WFD_LOG_ERROR, "Error!!! Invalid resp cmd = %d\n",
						   rsp.cmd);
			return WIFI_DIRECT_ERROR_OPERATION_FAILED;
		}
	}

	__WFD_CLIENT_FUNC_END__;

	return WIFI_DIRECT_ERROR_NONE;
}


int wifi_direct_set_wps_pin(char *pin)
{

	wifi_direct_client_info_s *client_info = __wfd_get_control();

	__WFD_CLIENT_FUNC_START__;

	if ((client_info->is_registered == false)
		|| (client_info->client_id == WFD_INVALID_ID))
	{
		WFD_CLIENT_LOG(WFD_LOG_ERROR, "Client is NOT registered.\n");
		__WFD_CLIENT_FUNC_END__;
		return WIFI_DIRECT_ERROR_NOT_INITIALIZED;
	}

	if (NULL == pin)
	{
		WFD_CLIENT_LOG(WFD_LOG_ERROR, "NULL Param [pin]!\n");
		__WFD_CLIENT_FUNC_END__;
		return WIFI_DIRECT_ERROR_INVALID_PARAMETER;
	}
	WFD_CLIENT_LOG(WFD_LOG_ERROR, "pin = [%s]\n", pin);

	wifi_direct_client_request_s req;
	wifi_direct_client_response_s rsp;

	int status = WIFI_DIRECT_ERROR_NONE;

	memset(&req, 0, sizeof(wifi_direct_client_request_s));
	memset(&rsp, 0, sizeof(wifi_direct_client_response_s));

	req.cmd = WIFI_DIRECT_CMD_SET_WPS_PIN;
	req.client_id = client_info->client_id;

	status =
		__wfd_client_send_request(client_info->sync_sockfd, &req,
								  sizeof(wifi_direct_client_request_s));
	if (status != WIFI_DIRECT_ERROR_NONE)
	{
		WFD_CLIENT_LOG(WFD_LOG_ERROR,
					   "Error!!! writing to socket, Errno = %s\n",
					   strerror(errno));
		WFD_CLIENT_LOG(WFD_LOG_ERROR, "Error!!! [%s]\n",
					   __wfd_print_error(status));
		client_info->sync_sockfd = -1;
		__wfd_reset_control();
		__WFD_CLIENT_FUNC_END__;
		return WIFI_DIRECT_ERROR_COMMUNICATION_FAILED;
	}

	WFD_CLIENT_LOG(WFD_LOG_LOW, "writing msg hdr is success!\n");

	status =
		__wfd_client_send_request(client_info->sync_sockfd, pin,
								  WIFI_DIRECT_WPS_PIN_LEN);
	if (status != WIFI_DIRECT_ERROR_NONE)
	{
		WFD_CLIENT_LOG(WFD_LOG_ERROR,
					   "Error!!! writing to socket, Errno = %s\n",
					   strerror(errno));
		WFD_CLIENT_LOG(WFD_LOG_ERROR, "Error!!! [%s]\n",
					   __wfd_print_error(status));
		client_info->sync_sockfd = -1;
		__wfd_reset_control();
		__WFD_CLIENT_FUNC_END__;
		return WIFI_DIRECT_ERROR_COMMUNICATION_FAILED;
	}

	if ((status =
		 __wfd_client_read_socket(client_info->sync_sockfd, (char *) &rsp,
								  sizeof(wifi_direct_client_response_s))) <= 0)
	{
		WFD_CLIENT_LOG(WFD_LOG_ERROR,
					   "Error!!! reading socket, status = %d errno = %s\n",
					   status, strerror(errno));
		__WFD_CLIENT_FUNC_END__;
		return WIFI_DIRECT_ERROR_COMMUNICATION_FAILED;
	}
	else
	{
		if (rsp.cmd == WIFI_DIRECT_CMD_SET_WPS_PIN)
		{
			if (rsp.result != WIFI_DIRECT_ERROR_NONE)
			{
				WFD_CLIENT_LOG(WFD_LOG_LOW, "Error!!! Result received = %d \n",
							   rsp.result);
				WFD_CLIENT_LOG(WFD_LOG_LOW, "Error!!! [%s]\n",
							   __wfd_print_error(rsp.result));
				__WFD_CLIENT_FUNC_END__;
				return rsp.result;
			}
		}
		else
		{
			WFD_CLIENT_LOG(WFD_LOG_ERROR, "Error!!! Invalid resp cmd = %d\n",
						   rsp.cmd);
			return WIFI_DIRECT_ERROR_OPERATION_FAILED;
		}
	}

	__WFD_CLIENT_FUNC_END__;

	return WIFI_DIRECT_ERROR_NONE;
}


int wifi_direct_get_wps_pin(char **pin)
{
	wifi_direct_client_info_s *client_info = __wfd_get_control();

	__WFD_CLIENT_FUNC_START__;

	if ((client_info->is_registered == false)
		|| (client_info->client_id == WFD_INVALID_ID))
	{
		WFD_CLIENT_LOG(WFD_LOG_ERROR, "Client is NOT registered.\n");
		__WFD_CLIENT_FUNC_END__;
		return WIFI_DIRECT_ERROR_NOT_INITIALIZED;
	}

	wifi_direct_client_request_s req;
	wifi_direct_client_response_s rsp;
	char la_pin[WIFI_DIRECT_WPS_PIN_LEN + 1] = { 0, };

	int status = WIFI_DIRECT_ERROR_NONE;

	memset(&req, 0, sizeof(wifi_direct_client_request_s));
	memset(&rsp, 0, sizeof(wifi_direct_client_response_s));

	req.cmd = WIFI_DIRECT_CMD_GET_WPS_PIN;
	req.client_id = client_info->client_id;

	status =
		__wfd_client_send_request(client_info->sync_sockfd, &req,
								  sizeof(wifi_direct_client_request_s));
	if (status != WIFI_DIRECT_ERROR_NONE)
	{
		WFD_CLIENT_LOG(WFD_LOG_ERROR,
					   "Error!!! writing to socket, Errno = %s\n",
					   strerror(errno));
		WFD_CLIENT_LOG(WFD_LOG_ERROR, "Error!!! [%s]\n",
					   __wfd_print_error(status));
		client_info->sync_sockfd = -1;
		__wfd_reset_control();
		__WFD_CLIENT_FUNC_END__;
		return WIFI_DIRECT_ERROR_COMMUNICATION_FAILED;
	}

	if ((status =
		 __wfd_client_read_socket(client_info->sync_sockfd, (char *) &rsp,
								  sizeof(wifi_direct_client_response_s))) <= 0)
	{
		WFD_CLIENT_LOG(WFD_LOG_ERROR,
					   "Error!!! reading socket, status = %d errno = %s\n",
					   status, strerror(errno));
		client_info->sync_sockfd = -1;
		__wfd_reset_control();
		__WFD_CLIENT_FUNC_END__;
		return WIFI_DIRECT_ERROR_COMMUNICATION_FAILED;
	}
	else
	{
		if (rsp.cmd == WIFI_DIRECT_CMD_GET_WPS_PIN)
		{
			if (rsp.result != WIFI_DIRECT_ERROR_NONE)
			{
				WFD_CLIENT_LOG(WFD_LOG_LOW, "Error!!! Result received = %d \n",
							   rsp.result);
				WFD_CLIENT_LOG(WFD_LOG_LOW, "Error!!! [%s]\n",
							   __wfd_print_error(rsp.result));
				__WFD_CLIENT_FUNC_END__;
				return rsp.result;
			}
			else
			{
				WFD_CLIENT_LOG(WFD_LOG_LOW,
							   "wifi_direct_get_wps_pin() SUCCESS \n");
				strncpy(la_pin, rsp.param2, WIFI_DIRECT_WPS_PIN_LEN);

				char *temp_pin;
				temp_pin = strdup(la_pin);

				*pin = temp_pin;
			}
		}
		else
		{
			WFD_CLIENT_LOG(WFD_LOG_ERROR, "Error!!! Invalid resp cmd = %d\n",
						   rsp.cmd);
			return WIFI_DIRECT_ERROR_OPERATION_FAILED;
		}
	}

	__WFD_CLIENT_FUNC_END__;

	return WIFI_DIRECT_ERROR_NONE;
}


int wifi_direct_generate_wps_pin(void)
{
	wifi_direct_client_info_s *client_info = __wfd_get_control();

	__WFD_CLIENT_FUNC_START__;

	if ((client_info->is_registered == false)
		|| (client_info->client_id == WFD_INVALID_ID))
	{
		WFD_CLIENT_LOG(WFD_LOG_ERROR, "Client is NOT registered.\n");
		__WFD_CLIENT_FUNC_END__;
		return WIFI_DIRECT_ERROR_NOT_INITIALIZED;
	}

	wifi_direct_client_request_s req;
	wifi_direct_client_response_s rsp;

	int status = WIFI_DIRECT_ERROR_NONE;

	memset(&req, 0, sizeof(wifi_direct_client_request_s));
	memset(&rsp, 0, sizeof(wifi_direct_client_response_s));

	req.cmd = WIFI_DIRECT_CMD_GENERATE_WPS_PIN;
	req.client_id = client_info->client_id;

	status =
		__wfd_client_send_request(client_info->sync_sockfd, &req,
								  sizeof(wifi_direct_client_request_s));
	if (status != WIFI_DIRECT_ERROR_NONE)
	{
		WFD_CLIENT_LOG(WFD_LOG_ERROR,
					   "Error!!! writing to socket, Errno = %s\n",
					   strerror(errno));
		WFD_CLIENT_LOG(WFD_LOG_ERROR, "Error!!! [%s]\n",
					   __wfd_print_error(status));
		client_info->sync_sockfd = -1;
		__wfd_reset_control();
		__WFD_CLIENT_FUNC_END__;
		return WIFI_DIRECT_ERROR_COMMUNICATION_FAILED;
	}

	if ((status =
		 __wfd_client_read_socket(client_info->sync_sockfd, (char *) &rsp,
								  sizeof(wifi_direct_client_response_s))) <= 0)
	{
		WFD_CLIENT_LOG(WFD_LOG_ERROR,
					   "Error!!! reading socket, status = %d errno = %s\n",
					   status, strerror(errno));
		client_info->sync_sockfd = -1;
		__wfd_reset_control();
		__WFD_CLIENT_FUNC_END__;
		return WIFI_DIRECT_ERROR_COMMUNICATION_FAILED;
	}
	else
	{
		if (rsp.cmd == WIFI_DIRECT_CMD_GENERATE_WPS_PIN)
		{
			if (rsp.result != WIFI_DIRECT_ERROR_NONE)
			{
				WFD_CLIENT_LOG(WFD_LOG_LOW, "Error!!! Result received = %d \n",
							   rsp.result);
				WFD_CLIENT_LOG(WFD_LOG_LOW, "Error!!! [%s]\n",
							   __wfd_print_error(rsp.result));
				__WFD_CLIENT_FUNC_END__;
				return rsp.result;
			}
			else
			{
				WFD_CLIENT_LOG(WFD_LOG_LOW,
							   "wifi_direct_generate_wps_pin() SUCCESS \n");
			}
		}
		else
		{
			WFD_CLIENT_LOG(WFD_LOG_ERROR, "Error!!! Invalid resp cmd = %d\n",
						   rsp.cmd);
			return WIFI_DIRECT_ERROR_OPERATION_FAILED;
		}
	}

	__WFD_CLIENT_FUNC_END__;

	return WIFI_DIRECT_ERROR_NONE;
}


int wifi_direct_get_supported_wps_mode(int *wps_mode)
{
	wifi_direct_client_info_s *client_info = __wfd_get_control();

	__WFD_CLIENT_FUNC_START__;

	if ((client_info->is_registered == false)
		|| (client_info->client_id == WFD_INVALID_ID))
	{
		WFD_CLIENT_LOG(WFD_LOG_ERROR, "Client is NOT registered.\n");
		__WFD_CLIENT_FUNC_END__;
		return WIFI_DIRECT_ERROR_NOT_INITIALIZED;
	}

	wifi_direct_client_request_s req;
	wifi_direct_client_response_s rsp;

	int ret = WIFI_DIRECT_ERROR_NONE;

	memset(&req, 0, sizeof(wifi_direct_client_request_s));
	memset(&rsp, 0, sizeof(wifi_direct_client_response_s));

	req.cmd = WIFI_DIRECT_CMD_GET_SUPPORTED_WPS_MODE;
	req.client_id = client_info->client_id;

	ret =
		__wfd_client_send_request(client_info->sync_sockfd, &req,
								  sizeof(wifi_direct_client_request_s));
	if (ret != WIFI_DIRECT_ERROR_NONE)
	{
		WFD_CLIENT_LOG(WFD_LOG_ERROR,
					   "Error!!! writing to socket, Errno = %s\n",
					   strerror(errno));
		WFD_CLIENT_LOG(WFD_LOG_ERROR, "Error!!! [%s]\n",
					   __wfd_print_error(ret));
		client_info->sync_sockfd = -1;
		__wfd_reset_control();
		__WFD_CLIENT_FUNC_END__;
		return WIFI_DIRECT_ERROR_COMMUNICATION_FAILED;
	}

	if ((ret =
		 __wfd_client_read_socket(client_info->sync_sockfd, (char *) &rsp,
								  sizeof(wifi_direct_client_response_s))) <= 0)
	{
		WFD_CLIENT_LOG(WFD_LOG_ERROR,
					   "Error!!! reading socket, status = %d errno = %s\n", ret,
					   strerror(errno));
		client_info->sync_sockfd = -1;
		__wfd_reset_control();
		__WFD_CLIENT_FUNC_END__;
		return WIFI_DIRECT_ERROR_COMMUNICATION_FAILED;
	}
	else
	{
		if (rsp.cmd == WIFI_DIRECT_CMD_GET_SUPPORTED_WPS_MODE)
		{
			if (rsp.result != WIFI_DIRECT_ERROR_NONE)
			{
				WFD_CLIENT_LOG(WFD_LOG_LOW, "Error!!! Result received = %d \n",
							   rsp.result);
				WFD_CLIENT_LOG(WFD_LOG_LOW, "Error!!! [%s]\n",
							   __wfd_print_error(rsp.result));
				__WFD_CLIENT_FUNC_END__;
				return rsp.result;
			}
			else
			{
				WFD_CLIENT_LOG(WFD_LOG_LOW, "Supported wps config = [%d]\n",
							   (int) rsp.param1);
				*wps_mode = rsp.param1;
			}
		}
		else
		{
			WFD_CLIENT_LOG(WFD_LOG_ERROR, "Error!!! Invalid resp cmd = %d\n",
						   rsp.cmd);
			return WIFI_DIRECT_ERROR_OPERATION_FAILED;
		}
	}

	__WFD_CLIENT_FUNC_END__;

	return WIFI_DIRECT_ERROR_NONE;

}


int wifi_direct_foreach_supported_wps_types(wifi_direct_supported_wps_type_cb callback, void* user_data)
{
	wifi_direct_client_info_s *client_info = __wfd_get_control();

	__WFD_CLIENT_FUNC_START__;

	if ((client_info->is_registered == false)
		|| (client_info->client_id == WFD_INVALID_ID))
	{
		WFD_CLIENT_LOG(WFD_LOG_ERROR, "Client is NOT registered.\n");
		__WFD_CLIENT_FUNC_END__;
		return WIFI_DIRECT_ERROR_NOT_INITIALIZED;
	}

	if (callback == NULL)
	{
		WFD_CLIENT_LOG(WFD_LOG_ERROR, "NULL Param [callback]!\n");
		__WFD_CLIENT_FUNC_END__;
		return WIFI_DIRECT_ERROR_INVALID_PARAMETER;
	}

	wifi_direct_client_request_s req;
	wifi_direct_client_response_s rsp;

	int ret = WIFI_DIRECT_ERROR_NONE;

	memset(&req, 0, sizeof(wifi_direct_client_request_s));
	memset(&rsp, 0, sizeof(wifi_direct_client_response_s));

	req.cmd = WIFI_DIRECT_CMD_GET_SUPPORTED_WPS_MODE;
	req.client_id = client_info->client_id;

	ret =
		__wfd_client_send_request(client_info->sync_sockfd, &req,
								  sizeof(wifi_direct_client_request_s));
	if (ret != WIFI_DIRECT_ERROR_NONE)
	{
		WFD_CLIENT_LOG(WFD_LOG_ERROR,
					   "Error!!! writing to socket, Errno = %s\n",
					   strerror(errno));
		WFD_CLIENT_LOG(WFD_LOG_ERROR, "Error!!! [%s]\n",
					   __wfd_print_error(ret));
		client_info->sync_sockfd = -1;
		__wfd_reset_control();
		__WFD_CLIENT_FUNC_END__;
		return WIFI_DIRECT_ERROR_COMMUNICATION_FAILED;
	}

	if ((ret =
		 __wfd_client_read_socket(client_info->sync_sockfd, (char *) &rsp,
								  sizeof(wifi_direct_client_response_s))) <= 0)
	{
		WFD_CLIENT_LOG(WFD_LOG_ERROR,
					   "Error!!! reading socket, status = %d errno = %s\n", ret,
					   strerror(errno));
		client_info->sync_sockfd = -1;
		__wfd_reset_control();
		__WFD_CLIENT_FUNC_END__;
		return WIFI_DIRECT_ERROR_COMMUNICATION_FAILED;
	}
	else
	{
		if (rsp.cmd == WIFI_DIRECT_CMD_GET_SUPPORTED_WPS_MODE)
		{
			if (rsp.result != WIFI_DIRECT_ERROR_NONE)
			{
				WFD_CLIENT_LOG(WFD_LOG_LOW, "Error!!! Result received = %d \n",
							   rsp.result);
				WFD_CLIENT_LOG(WFD_LOG_LOW, "Error!!! [%s]\n",
							   __wfd_print_error(rsp.result));
				__WFD_CLIENT_FUNC_END__;
				return rsp.result;
			}
			else
			{
				WFD_CLIENT_LOG(WFD_LOG_LOW, "Supported wps config = [%d]\n",
							   (int) rsp.param1);
				int wps_mode;
				bool result;
				
				wps_mode = rsp.param1;

				if (wps_mode & WIFI_DIRECT_WPS_TYPE_PBC)
					result = callback(WIFI_DIRECT_WPS_TYPE_PBC, user_data);

				if ((result == true) && (wps_mode & WIFI_DIRECT_WPS_TYPE_PIN_DISPLAY))
					result = callback(WIFI_DIRECT_WPS_TYPE_PIN_DISPLAY, user_data);
					

				if ((result == true) && (wps_mode & WIFI_DIRECT_WPS_TYPE_PIN_KEYPAD))
					result = callback(WIFI_DIRECT_WPS_TYPE_PIN_KEYPAD, user_data);
			}
		}
		else
		{
			WFD_CLIENT_LOG(WFD_LOG_ERROR, "Error!!! Invalid resp cmd = %d\n",
						   rsp.cmd);
			return WIFI_DIRECT_ERROR_OPERATION_FAILED;
		}
	}

	__WFD_CLIENT_FUNC_END__;

	return WIFI_DIRECT_ERROR_NONE;

}


int wifi_direct_set_wps_type(wifi_direct_wps_type_e type)
{
	wifi_direct_client_info_s *client_info = __wfd_get_control();

	__WFD_CLIENT_FUNC_START__;

	if ((client_info->is_registered == false)
		|| (client_info->client_id == WFD_INVALID_ID))
	{
		WFD_CLIENT_LOG(WFD_LOG_ERROR, "Client is NOT registered.\n");
		__WFD_CLIENT_FUNC_END__;
		return WIFI_DIRECT_ERROR_NOT_INITIALIZED;
	}

	if (type == WIFI_DIRECT_WPS_TYPE_PBC
		|| type == WIFI_DIRECT_WPS_TYPE_PIN_DISPLAY
		|| type == WIFI_DIRECT_WPS_TYPE_PIN_KEYPAD)
	{
		WFD_CLIENT_LOG(WFD_LOG_LOW, "Param wps_mode [%d]\n", type);
	}
	else
	{
		WFD_CLIENT_LOG(WFD_LOG_ERROR, "Invalid Param [wps_mode]!\n");
		__WFD_CLIENT_FUNC_END__;
		return WIFI_DIRECT_ERROR_INVALID_PARAMETER;
	}

	wifi_direct_client_request_s req;
	wifi_direct_client_response_s rsp;

	int status = WIFI_DIRECT_ERROR_NONE;

	memset(&req, 0, sizeof(wifi_direct_client_request_s));
	memset(&rsp, 0, sizeof(wifi_direct_client_response_s));

	req.cmd = WIFI_DIRECT_CMD_SET_CURRENT_WPS_MODE;
	req.client_id = client_info->client_id;

	status =__wfd_client_send_request(client_info->sync_sockfd, &req,
								  sizeof(wifi_direct_client_request_s));
	if (status != WIFI_DIRECT_ERROR_NONE)
	{
		WFD_CLIENT_LOG(WFD_LOG_ERROR,
					   "Error!!! writing to socket, Errno = %s\n",
					   strerror(errno));
		WFD_CLIENT_LOG(WFD_LOG_ERROR, "Error!!! [%s]\n",
					   __wfd_print_error(status));
		client_info->sync_sockfd = -1;
		__wfd_reset_control();
		__WFD_CLIENT_FUNC_END__;
		return WIFI_DIRECT_ERROR_COMMUNICATION_FAILED;
	}

	WFD_CLIENT_LOG(WFD_LOG_LOW, "writing msg hdr is success!\n");

	status =
		__wfd_client_send_request(client_info->sync_sockfd, &type,
								  sizeof(wifi_direct_wps_type_e));
	if (status != WIFI_DIRECT_ERROR_NONE)
	{
		WFD_CLIENT_LOG(WFD_LOG_ERROR,
					   "Error!!! writing to socket, Errno = %s\n",
					   strerror(errno));
		WFD_CLIENT_LOG(WFD_LOG_ERROR, "Error!!! [%s]\n",
					   __wfd_print_error(status));
		client_info->sync_sockfd = -1;
		__wfd_reset_control();
		__WFD_CLIENT_FUNC_END__;
		return WIFI_DIRECT_ERROR_COMMUNICATION_FAILED;
	}

	if ((status =
		 __wfd_client_read_socket(client_info->sync_sockfd, (char *) &rsp,
								  sizeof(wifi_direct_client_response_s))) <= 0)
	{
		WFD_CLIENT_LOG(WFD_LOG_ERROR,
					   "Error!!! reading socket, status = %d errno = %s\n",
					   status, strerror(errno));
		client_info->sync_sockfd = -1;
		__wfd_reset_control();
		__WFD_CLIENT_FUNC_END__;
		return WIFI_DIRECT_ERROR_COMMUNICATION_FAILED;
	}
	else
	{
		if (rsp.cmd == WIFI_DIRECT_CMD_SET_CURRENT_WPS_MODE)
		{
			if (rsp.result != WIFI_DIRECT_ERROR_NONE)
			{
				WFD_CLIENT_LOG(WFD_LOG_LOW, "Error!!! Result received = %d \n",
							   rsp.result);
				WFD_CLIENT_LOG(WFD_LOG_LOW, "Error!!! [%s]\n",
							   __wfd_print_error(rsp.result));
				__WFD_CLIENT_FUNC_END__;
				return rsp.result;
			}
		}
		else
		{
			WFD_CLIENT_LOG(WFD_LOG_ERROR, "Error!!! Invalid resp cmd = %d\n",
						   rsp.cmd);
			return WIFI_DIRECT_ERROR_OPERATION_FAILED;
		}
	}

	__WFD_CLIENT_FUNC_END__;

	return WIFI_DIRECT_ERROR_NONE;
}

int wifi_direct_get_wps_type(wifi_direct_wps_type_e* type)
{
	wifi_direct_client_info_s *client_info = __wfd_get_control();

	__WFD_CLIENT_FUNC_START__;

	if ((client_info->is_registered == false)
		|| (client_info->client_id == WFD_INVALID_ID))
	{
		WFD_CLIENT_LOG(WFD_LOG_ERROR, "Client is NOT registered.\n");
		__WFD_CLIENT_FUNC_END__;
		return WIFI_DIRECT_ERROR_NOT_INITIALIZED;
	}

	if (type == NULL)
	{
		WFD_CLIENT_LOG(WFD_LOG_ERROR, "NULL Param [type]!\n");
		__WFD_CLIENT_FUNC_END__;
		return WIFI_DIRECT_ERROR_INVALID_PARAMETER;
	}

	wifi_direct_client_request_s req;
	wifi_direct_client_response_s rsp;
	wfd_config_data_s ls_config;

	int status = WIFI_DIRECT_ERROR_NONE;

	memset(&req, 0, sizeof(wifi_direct_client_request_s));
	memset(&rsp, 0, sizeof(wifi_direct_client_response_s));

	req.cmd = WIFI_DIRECT_CMD_GET_CONFIG;
	req.client_id = client_info->client_id;

	status =
		__wfd_client_send_request(client_info->sync_sockfd, &req,
								  sizeof(wifi_direct_client_request_s));
	if (status != WIFI_DIRECT_ERROR_NONE)
	{
		WFD_CLIENT_LOG(WFD_LOG_ERROR,
					   "Error!!! writing to socket, Errno = %s\n",
					   strerror(errno));
		WFD_CLIENT_LOG(WFD_LOG_ERROR, "Error!!! [%s]\n",
					   __wfd_print_error(status));
		client_info->sync_sockfd = -1;
		__wfd_reset_control();
		__WFD_CLIENT_FUNC_END__;
		return WIFI_DIRECT_ERROR_COMMUNICATION_FAILED;
	}

	if ((status =
		 __wfd_client_read_socket(client_info->sync_sockfd, (char *) &rsp,
								  sizeof(wifi_direct_client_response_s))) <= 0)
	{
		WFD_CLIENT_LOG(WFD_LOG_ERROR,
					   "Error!!! reading socket, status = %d errno = %s\n",
					   status, strerror(errno));
		client_info->sync_sockfd = -1;
		__wfd_reset_control();
		__WFD_CLIENT_FUNC_END__;
		return WIFI_DIRECT_ERROR_COMMUNICATION_FAILED;
	}
	else
	{
		if (rsp.cmd == WIFI_DIRECT_CMD_GET_CONFIG)
		{
			if (rsp.result != WIFI_DIRECT_ERROR_NONE)
			{
				WFD_CLIENT_LOG(WFD_LOG_ERROR,
							   "Error!!! Result received = %d \n", rsp.result);
				WFD_CLIENT_LOG(WFD_LOG_ERROR, "Error!!! [%s]\n",
							   __wfd_print_error(rsp.result));
				__WFD_CLIENT_FUNC_END__;
				return rsp.result;
			}
			else
			{
				int status = 0;

				WFD_CLIENT_LOG(WFD_LOG_LOW, "Link status = %d \n",
							   (int) rsp.param1);

				status =
					__wfd_client_read_more_data(client_info->sync_sockfd,
												&ls_config,
												sizeof(wfd_config_data_s));
				if (status != WIFI_DIRECT_ERROR_NONE)
				{
					WFD_CLIENT_LOG(WFD_LOG_ERROR, "socket read error.\n");
					return WIFI_DIRECT_ERROR_OPERATION_FAILED;
				}

				__wfd_client_print_config_data(&ls_config);

				*type = ls_config.wps_config;

				WFD_CLIENT_LOG(WFD_LOG_LOW, "wifi_direct_get_wps_type() SUCCESS\n");
			}
		}
		else
		{
			WFD_CLIENT_LOG(WFD_LOG_ERROR, "Error!!! Invalid resp cmd = %d\n",
						   rsp.cmd);
			return WIFI_DIRECT_ERROR_OPERATION_FAILED;
		}
	}

	__WFD_CLIENT_FUNC_END__;

	return WIFI_DIRECT_ERROR_NONE;
}

int wifi_direct_set_ssid(const char *ssid)
{
	wifi_direct_client_info_s *client_info = __wfd_get_control();

	__WFD_CLIENT_FUNC_START__;

	if ((client_info->is_registered == false)
		|| (client_info->client_id == WFD_INVALID_ID))
	{
		WFD_CLIENT_LOG(WFD_LOG_ERROR, "Client is NOT registered.\n");
		__WFD_CLIENT_FUNC_END__;
		return WIFI_DIRECT_ERROR_NOT_INITIALIZED;
	}

	if (NULL == ssid)
	{
		WFD_CLIENT_LOG(WFD_LOG_ERROR, "NULL Param [ssid]!\n");
		__WFD_CLIENT_FUNC_END__;
		return WIFI_DIRECT_ERROR_INVALID_PARAMETER;
	}

	WFD_CLIENT_LOG(WFD_LOG_ERROR, "ssid = [%s]\n", ssid);

	wifi_direct_client_request_s req;
	wifi_direct_client_response_s rsp;

	int status = WIFI_DIRECT_ERROR_NONE;

	memset(&req, 0, sizeof(wifi_direct_client_request_s));
	memset(&rsp, 0, sizeof(wifi_direct_client_response_s));

	req.cmd = WIFI_DIRECT_CMD_SET_SSID;
	req.client_id = client_info->client_id;

	status =
		__wfd_client_send_request(client_info->sync_sockfd, &req,
								  sizeof(wifi_direct_client_request_s));
	if (status != WIFI_DIRECT_ERROR_NONE)
	{
		WFD_CLIENT_LOG(WFD_LOG_ERROR,
					   "Error!!! writing to socket, Errno = %s\n",
					   strerror(errno));
		WFD_CLIENT_LOG(WFD_LOG_ERROR, "Error!!! [%s]\n",
					   __wfd_print_error(status));
		client_info->sync_sockfd = -1;
		__wfd_reset_control();
		__WFD_CLIENT_FUNC_END__;
		return WIFI_DIRECT_ERROR_COMMUNICATION_FAILED;
	}

	WFD_CLIENT_LOG(WFD_LOG_LOW, "writing msg hdr is success!\n");

	status =
		__wfd_client_send_request(client_info->sync_sockfd, ssid,
								  WIFI_DIRECT_MAX_SSID_LEN);
	if (status != WIFI_DIRECT_ERROR_NONE)
	{
		WFD_CLIENT_LOG(WFD_LOG_ERROR,
					   "Error!!! writing to socket, Errno = %s\n",
					   strerror(errno));
		WFD_CLIENT_LOG(WFD_LOG_ERROR, "Error!!! [%s]\n",
					   __wfd_print_error(status));
		client_info->sync_sockfd = -1;
		__wfd_reset_control();
		__WFD_CLIENT_FUNC_END__;
		return WIFI_DIRECT_ERROR_COMMUNICATION_FAILED;
	}

	if ((status =
		 __wfd_client_read_socket(client_info->sync_sockfd, (char *) &rsp,
								  sizeof(wifi_direct_client_response_s))) <= 0)
	{
		WFD_CLIENT_LOG(WFD_LOG_ERROR,
					   "Error!!! reading socket, status = %d errno = %s\n",
					   status, strerror(errno));
		client_info->sync_sockfd = -1;
		__wfd_reset_control();
		__WFD_CLIENT_FUNC_END__;
		return WIFI_DIRECT_ERROR_COMMUNICATION_FAILED;
	}
	else
	{
		if (rsp.cmd == WIFI_DIRECT_CMD_SET_SSID)
		{
			if (rsp.result != WIFI_DIRECT_ERROR_NONE)
			{
				WFD_CLIENT_LOG(WFD_LOG_ERROR,
							   "Error!!! Result received = %d \n", rsp.result);
				WFD_CLIENT_LOG(WFD_LOG_ERROR, "Error!!! [%s]\n",
							   __wfd_print_error(rsp.result));
				__WFD_CLIENT_FUNC_END__;
				return rsp.result;
			}
		}
		else
		{
			WFD_CLIENT_LOG(WFD_LOG_ERROR, "Error!!! Invalid resp cmd = %d\n",
						   rsp.cmd);
			return WIFI_DIRECT_ERROR_OPERATION_FAILED;
		}
	}

	__WFD_CLIENT_FUNC_END__;

	return WIFI_DIRECT_ERROR_NONE;
}



int wifi_direct_get_ssid(char **ssid)
{
	wifi_direct_client_info_s *client_info = __wfd_get_control();

	__WFD_CLIENT_FUNC_START__;

	if (NULL == ssid)
	{
		WFD_CLIENT_LOG(WFD_LOG_ERROR, "NULL Param [ssid]!\n");
		__WFD_CLIENT_FUNC_END__;
		return WIFI_DIRECT_ERROR_INVALID_PARAMETER;
	}

	if ((client_info->is_registered == false)
		|| (client_info->client_id == WFD_INVALID_ID))
	{
		WFD_CLIENT_LOG(WFD_LOG_ERROR, "Client is NOT registered.\n");
		__WFD_CLIENT_FUNC_END__;
		return WIFI_DIRECT_ERROR_NOT_INITIALIZED;
	}

	wifi_direct_client_request_s req;
	wifi_direct_client_response_s rsp;
	char la_ssid[WIFI_DIRECT_MAX_SSID_LEN + 1] = { 0, };

	int status = WIFI_DIRECT_ERROR_NONE;

	memset(&req, 0, sizeof(wifi_direct_client_request_s));
	memset(&rsp, 0, sizeof(wifi_direct_client_response_s));

	req.cmd = WIFI_DIRECT_CMD_GET_SSID;
	req.client_id = client_info->client_id;

	status =
		__wfd_client_send_request(client_info->sync_sockfd, &req,
								  sizeof(wifi_direct_client_request_s));
	if (status != WIFI_DIRECT_ERROR_NONE)
	{
		WFD_CLIENT_LOG(WFD_LOG_ERROR,
					   "Error!!! writing to socket, Errno = %s\n",
					   strerror(errno));
		WFD_CLIENT_LOG(WFD_LOG_ERROR, "Error!!! [%s]\n",
					   __wfd_print_error(status));
		client_info->sync_sockfd = -1;
		__wfd_reset_control();
		__WFD_CLIENT_FUNC_END__;
		return WIFI_DIRECT_ERROR_COMMUNICATION_FAILED;
	}

	if ((status =
		 __wfd_client_read_socket(client_info->sync_sockfd, (char *) &rsp,
								  sizeof(wifi_direct_client_response_s))) <= 0)
	{
		WFD_CLIENT_LOG(WFD_LOG_ERROR,
					   "Error!!! reading socket, status = %d errno = %s\n",
					   status, strerror(errno));
		client_info->sync_sockfd = -1;
		__wfd_reset_control();
		__WFD_CLIENT_FUNC_END__;
		return WIFI_DIRECT_ERROR_COMMUNICATION_FAILED;
	}
	else
	{
		if (rsp.cmd == WIFI_DIRECT_CMD_GET_SSID)
		{
			if (rsp.result != WIFI_DIRECT_ERROR_NONE)
			{
				WFD_CLIENT_LOG(WFD_LOG_LOW, "Error!!! Result received = %d \n",
							   rsp.result);
				WFD_CLIENT_LOG(WFD_LOG_LOW, "Error!!! [%s]\n",
							   __wfd_print_error(rsp.result));
				__WFD_CLIENT_FUNC_END__;
				return rsp.result;
			}
			else
			{
				WFD_CLIENT_LOG(WFD_LOG_LOW,
							   "wifi_direct_get_ssid() %s SUCCESS \n",
							   rsp.param2);
				strncpy(la_ssid, rsp.param2, WIFI_DIRECT_MAX_SSID_LEN);

				char *temp_ssid = NULL;
				temp_ssid = strdup(la_ssid);
				if (NULL == temp_ssid)
				{
					WFD_CLIENT_LOG(WFD_LOG_ERROR, "Failed to allocate memory for SSID\n");
					return WIFI_DIRECT_ERROR_OUT_OF_MEMORY;
				}

				*ssid = temp_ssid;
			}

		}
		else
		{
			WFD_CLIENT_LOG(WFD_LOG_ERROR, "Error!!! Invalid resp cmd = %d\n",
						   rsp.cmd);
			return WIFI_DIRECT_ERROR_OPERATION_FAILED;
		}
	}

	__WFD_CLIENT_FUNC_END__;

	return WIFI_DIRECT_ERROR_NONE;
}


int wifi_direct_get_network_interface_name(char** name)
{
	wifi_direct_client_info_s *client_info = __wfd_get_control();

	__WFD_CLIENT_FUNC_START__;

	if (NULL == name)
	{
		WFD_CLIENT_LOG(WFD_LOG_ERROR, "NULL Param [name]!\n");
		__WFD_CLIENT_FUNC_END__;
		return WIFI_DIRECT_ERROR_INVALID_PARAMETER;
	}

	if ((client_info->is_registered == false)
		|| (client_info->client_id == WFD_INVALID_ID))
	{
		WFD_CLIENT_LOG(WFD_LOG_ERROR, "Client is NOT registered.\n");
		__WFD_CLIENT_FUNC_END__;
		return WIFI_DIRECT_ERROR_NOT_INITIALIZED;
	}

	wifi_direct_state_e status = 0;
	int result;
	result = wifi_direct_get_state(&status);
	WFD_CLIENT_LOG(WFD_LOG_LOW, "wifi_direct_get_state() state=[%d], result=[%d]\n", status, result);

	if( status < WIFI_DIRECT_STATE_CONNECTED)
	{
		WFD_CLIENT_LOG(WFD_LOG_ERROR, "Device is not connected!\n");
		__WFD_CLIENT_FUNC_END__;
		return WIFI_DIRECT_ERROR_NOT_PERMITTED;
	}

	char* get_str = NULL;
	get_str = vconf_get_str(VCONFKEY_IFNAME);

	if (get_str == NULL)
	{
		WFD_CLIENT_LOG(WFD_LOG_LOW, "vconf (%s) value is NULL!!!\n", VCONFKEY_IFNAME);
		__WFD_CLIENT_FUNC_END__;
		return WIFI_DIRECT_ERROR_NOT_PERMITTED;
	}
	else
	{
		WFD_CLIENT_LOG(WFD_LOG_LOW, "VCONFKEY_IFNAME(%s) : %s\n", VCONFKEY_IFNAME, get_str);

		char *temp_ifname = NULL;
		temp_ifname = strdup(get_str);
		if (NULL == temp_ifname)
		{
			WFD_CLIENT_LOG(WFD_LOG_ERROR, "Failed to allocate memory for ifname.\n");
			return WIFI_DIRECT_ERROR_OUT_OF_MEMORY;
		}

		*name = temp_ifname;
	}

	__WFD_CLIENT_FUNC_END__;

	return WIFI_DIRECT_ERROR_NONE;
}



int wifi_direct_get_ip_address(char **ip_address)
{
	wifi_direct_client_info_s *client_info = __wfd_get_control();

	__WFD_CLIENT_FUNC_START__;

	if (NULL == ip_address)
	{
		WFD_CLIENT_LOG(WFD_LOG_ERROR, "NULL Param [ip_address]!\n");
		__WFD_CLIENT_FUNC_END__;
		return WIFI_DIRECT_ERROR_INVALID_PARAMETER;
	}

	if ((client_info->is_registered == false)
		|| (client_info->client_id == WFD_INVALID_ID))
	{
		WFD_CLIENT_LOG(WFD_LOG_ERROR, "Client is NOT registered.\n");
		__WFD_CLIENT_FUNC_END__;
		return WIFI_DIRECT_ERROR_NOT_INITIALIZED;
	}

	wifi_direct_state_e state = 0;
	int result;
	result = wifi_direct_get_state(&state);
	WFD_CLIENT_LOG(WFD_LOG_LOW, "wifi_direct_get_state() state=[%d], result=[%d]\n", state, result);

	if( state < WIFI_DIRECT_STATE_CONNECTED)
	{
		WFD_CLIENT_LOG(WFD_LOG_ERROR, "Device is not connected!\n");
		__WFD_CLIENT_FUNC_END__;
		return WIFI_DIRECT_ERROR_NOT_PERMITTED;
	}

	char* get_str = NULL;
	get_str = vconf_get_str(VCONFKEY_LOCAL_IP);

	if (get_str == NULL)
	{
		WFD_CLIENT_LOG(WFD_LOG_LOW, "vconf (%s) value is NULL!!!\n", VCONFKEY_LOCAL_IP);
		__WFD_CLIENT_FUNC_END__;
		return WIFI_DIRECT_ERROR_NOT_PERMITTED;
	}
	else
	{
		WFD_CLIENT_LOG(WFD_LOG_LOW, "VCONFKEY_LOCAL_IP(%s) : %s\n", VCONFKEY_LOCAL_IP, get_str);

		char *temp_ip = NULL;
		temp_ip = strdup(get_str);
		if (NULL == temp_ip)
		{
			WFD_CLIENT_LOG(WFD_LOG_ERROR, "Failed to allocate memory for local ip address.\n");
			return WIFI_DIRECT_ERROR_OUT_OF_MEMORY;
		}

		*ip_address = temp_ip;
	}


#if 0
	wifi_direct_client_request_s req;
	wifi_direct_client_response_s rsp;
	char la_ip[64] = { 0, };

	int status = WIFI_DIRECT_ERROR_NONE;

	memset(&req, 0, sizeof(wifi_direct_client_request_s));
	memset(&rsp, 0, sizeof(wifi_direct_client_response_s));

	req.cmd = WIFI_DIRECT_CMD_GET_IP_ADDR;
	req.client_id = client_info->client_id;

	status =
		__wfd_client_send_request(client_info->sync_sockfd, &req,
								  sizeof(wifi_direct_client_request_s));
	if (status != WIFI_DIRECT_ERROR_NONE)
	{
		WFD_CLIENT_LOG(WFD_LOG_ERROR,
					   "Error!!! writing to socket, Errno = %s\n",
					   strerror(errno));
		WFD_CLIENT_LOG(WFD_LOG_ERROR, "Error!!! [%s]\n",
					   __wfd_print_error(status));
		client_info->sync_sockfd = -1;
		__wfd_reset_control();
		__WFD_CLIENT_FUNC_END__;
		return WIFI_DIRECT_ERROR_COMMUNICATION_FAILED;
	}

	if ((status =
		 __wfd_client_read_socket(client_info->sync_sockfd, (char *) &rsp,
								  sizeof(wifi_direct_client_response_s))) <= 0)
	{
		WFD_CLIENT_LOG(WFD_LOG_ERROR,
					   "Error!!! reading socket, status = %d errno = %s\n",
					   status, strerror(errno));
		client_info->sync_sockfd = -1;
		__wfd_reset_control();
		__WFD_CLIENT_FUNC_END__;
		return WIFI_DIRECT_ERROR_COMMUNICATION_FAILED;
	}
	else
	{
		if (rsp.cmd == WIFI_DIRECT_CMD_GET_IP_ADDR)
		{
			if (rsp.result != WIFI_DIRECT_ERROR_NONE)
			{
				WFD_CLIENT_LOG(WFD_LOG_LOW, "Error!!! Result received = %d \n",
							   rsp.result);
				WFD_CLIENT_LOG(WFD_LOG_LOW, "Error!!! [%s]\n",
							   __wfd_print_error(rsp.result));
				__WFD_CLIENT_FUNC_END__;
				return rsp.result;
			}
			else
			{
				WFD_CLIENT_LOG(WFD_LOG_LOW,
							   "wifi_direct_get_ip_address() SUCCESS \n");
				strncpy(la_ip, rsp.param2, strlen(rsp.param2));

				char *temp_ip = NULL;
				temp_ip = strdup(la_ip);
				if (NULL == temp_ip)
				{
					WFD_CLIENT_LOG(WFD_LOG_ERROR, "Failed to allocate memory for IP address\n");
					return WIFI_DIRECT_ERROR_OUT_OF_MEMORY;
				}

				*ip_address = temp_ip;
			}
		}
		else
		{
			WFD_CLIENT_LOG(WFD_LOG_ERROR, "Error!!! Invalid resp cmd = %d\n",
						   rsp.cmd);
			return WIFI_DIRECT_ERROR_OPERATION_FAILED;
		}
	}
#endif

	__WFD_CLIENT_FUNC_END__;

	return WIFI_DIRECT_ERROR_NONE;
}


int wifi_direct_get_subnet_mask(char** subnet_mask)
{
	wifi_direct_client_info_s *client_info = __wfd_get_control();

	__WFD_CLIENT_FUNC_START__;

	if (NULL == subnet_mask)
	{
		WFD_CLIENT_LOG(WFD_LOG_ERROR, "NULL Param [subnet_mask]!\n");
		__WFD_CLIENT_FUNC_END__;
		return WIFI_DIRECT_ERROR_INVALID_PARAMETER;
	}

	if ((client_info->is_registered == false)
		|| (client_info->client_id == WFD_INVALID_ID))
	{
		WFD_CLIENT_LOG(WFD_LOG_ERROR, "Client is NOT registered.\n");
		__WFD_CLIENT_FUNC_END__;
		return WIFI_DIRECT_ERROR_NOT_INITIALIZED;
	}

	wifi_direct_state_e status = 0;
	int result;
	result = wifi_direct_get_state(&status);
	WFD_CLIENT_LOG(WFD_LOG_LOW, "wifi_direct_get_state() state=[%d], result=[%d]\n", status, result);

	if( status < WIFI_DIRECT_STATE_CONNECTED)
	{
		WFD_CLIENT_LOG(WFD_LOG_ERROR, "Device is not connected!\n");
		__WFD_CLIENT_FUNC_END__;
		return WIFI_DIRECT_ERROR_NOT_PERMITTED;
	}


	char* get_str = NULL;
	get_str = vconf_get_str(VCONFKEY_SUBNET_MASK);

	if (get_str == NULL)
	{
		WFD_CLIENT_LOG(WFD_LOG_LOW, "vconf (%s) value is NULL!!!\n", VCONFKEY_SUBNET_MASK);
		__WFD_CLIENT_FUNC_END__;
		return WIFI_DIRECT_ERROR_NOT_PERMITTED;
	}
	else
	{
		WFD_CLIENT_LOG(WFD_LOG_LOW, "VCONFKEY_SUBNET_MASK(%s) : %s\n", VCONFKEY_SUBNET_MASK, get_str);

		char *temp_subnetmask = NULL;
		temp_subnetmask = strdup(get_str);
		if (NULL == temp_subnetmask)
		{
			WFD_CLIENT_LOG(WFD_LOG_ERROR, "Failed to allocate memory for subnet mask.\n");
			return WIFI_DIRECT_ERROR_OUT_OF_MEMORY;
		}

		*subnet_mask = temp_subnetmask;
	}

	__WFD_CLIENT_FUNC_END__;

	return WIFI_DIRECT_ERROR_NONE;
}


int wifi_direct_get_gateway_address(char** gateway_address)
{
	wifi_direct_client_info_s *client_info = __wfd_get_control();

	__WFD_CLIENT_FUNC_START__;

	if (NULL == gateway_address)
	{
		WFD_CLIENT_LOG(WFD_LOG_ERROR, "NULL Param [gateway_address]!\n");
		__WFD_CLIENT_FUNC_END__;
		return WIFI_DIRECT_ERROR_INVALID_PARAMETER;
	}

	if ((client_info->is_registered == false)
		|| (client_info->client_id == WFD_INVALID_ID))
	{
		WFD_CLIENT_LOG(WFD_LOG_ERROR, "Client is NOT registered.\n");
		__WFD_CLIENT_FUNC_END__;
		return WIFI_DIRECT_ERROR_NOT_INITIALIZED;
	}

	wifi_direct_state_e status = 0;
	int result;
	result = wifi_direct_get_state(&status);
	WFD_CLIENT_LOG(WFD_LOG_LOW, "wifi_direct_get_state() state=[%d], result=[%d]\n", status, result);

	if( status < WIFI_DIRECT_STATE_CONNECTED)
	{
		WFD_CLIENT_LOG(WFD_LOG_ERROR, "Device is not connected!\n");
		__WFD_CLIENT_FUNC_END__;
		return WIFI_DIRECT_ERROR_NOT_PERMITTED;
	}

	char* get_str = NULL;
	get_str = vconf_get_str(VCONFKEY_GATEWAY);

	if (get_str == NULL)
	{
		WFD_CLIENT_LOG(WFD_LOG_LOW, "vconf (%s) value is NULL!!!\n", VCONFKEY_GATEWAY);
		__WFD_CLIENT_FUNC_END__;
		return WIFI_DIRECT_ERROR_NOT_PERMITTED;
	}
	else
	{
		WFD_CLIENT_LOG(WFD_LOG_LOW, "VCONFKEY_GATEWAY(%s) : %s\n", VCONFKEY_GATEWAY, get_str);

		char *temp_gateway = NULL;
		temp_gateway = strdup(get_str);
		if (NULL == temp_gateway)
		{
			WFD_CLIENT_LOG(WFD_LOG_ERROR, "Failed to allocate memory for gateway address.\n");
			return WIFI_DIRECT_ERROR_OUT_OF_MEMORY;
		}

		*gateway_address = temp_gateway;
	}

	__WFD_CLIENT_FUNC_END__;

	return WIFI_DIRECT_ERROR_NONE;
}


int wifi_direct_get_mac_address(char **mac_address)
{
	wifi_direct_client_info_s *client_info = __wfd_get_control();

	__WFD_CLIENT_FUNC_START__;

	if (NULL == mac_address)
	{
		WFD_CLIENT_LOG(WFD_LOG_ERROR, "NULL Param [mac_address]!\n");
		__WFD_CLIENT_FUNC_END__;
		return WIFI_DIRECT_ERROR_INVALID_PARAMETER;
	}

	if ((client_info->is_registered == false)
		|| (client_info->client_id == WFD_INVALID_ID))
	{
		WFD_CLIENT_LOG(WFD_LOG_LOW, "Client is NOT registered.\n");
		__WFD_CLIENT_FUNC_END__;
		return WIFI_DIRECT_ERROR_NOT_INITIALIZED;
	}

#if 0
	wifi_direct_client_request_s req;
	wifi_direct_client_response_s rsp;
	unsigned char la_mac_addr[6] = { 0, };

	int status = WIFI_DIRECT_ERROR_NONE;

	memset(&req, 0, sizeof(wifi_direct_client_request_s));
	memset(&rsp, 0, sizeof(wifi_direct_client_response_s));

	req.cmd = WIFI_DIRECT_CMD_GET_DEVICE_MAC;
	req.client_id = client_info->client_id;

	status =
		__wfd_client_send_request(client_info->sync_sockfd, &req,
								  sizeof(wifi_direct_client_request_s));
	if (status != WIFI_DIRECT_ERROR_NONE)
	{
		WFD_CLIENT_LOG(WFD_LOG_LOW, "Error!!! writing to socket, Errno = %s\n",
					   strerror(errno));
		WFD_CLIENT_LOG(WFD_LOG_LOW, "Error!!! [%s]\n",
					   __wfd_print_error(status));
		close(client_info->sync_sockfd);
		__WFD_CLIENT_FUNC_END__;
		return WIFI_DIRECT_ERROR_COMMUNICATION_FAILED;
	}

	if ((status =
		 __wfd_client_read_socket(client_info->sync_sockfd, (char *) &rsp,
								  sizeof(wifi_direct_client_response_s))) <= 0)
	{
		WFD_CLIENT_LOG(WFD_LOG_LOW,
					   "Error!!! reading socket, status = %d errno = %s\n",
					   status, strerror(errno));
		__WFD_CLIENT_FUNC_END__;
		return WIFI_DIRECT_ERROR_COMMUNICATION_FAILED;
	}
	else
	{
		if (rsp.cmd == WIFI_DIRECT_CMD_GET_DEVICE_MAC)
		{
			if (rsp.result != WIFI_DIRECT_ERROR_NONE)
			{
				WFD_CLIENT_LOG(WFD_LOG_LOW, "Error!!! Result received = %d \n",
							   rsp.result);
				WFD_CLIENT_LOG(WFD_LOG_LOW, "Error!!! [%s]\n",
							   __wfd_print_error(rsp.result));
				__WFD_CLIENT_FUNC_END__;
				return rsp.result;
			}
			else
			{
				WFD_CLIENT_LOG(WFD_LOG_LOW,
							   "wifi_direct_get_mac_addr() SUCCESS \n");
				strncpy((char *) la_mac_addr, (char *) rsp.param2,
						strlen(rsp.param2));

				char *temp_mac = NULL;
				temp_mac = (char *) calloc(1, 18);
				if (NULL == temp_mac)
				{
					WFD_CLIENT_LOG(WFD_LOG_ERROR, "Failed to allocate memory for MAC address\n");
					return WIFI_DIRECT_ERROR_OUT_OF_MEMORY;
				}
    
				sprintf(temp_mac, MACSTR, MAC2STR(la_mac_addr));

				*mac_address = temp_mac;

			}
		}
		else
		{
			WFD_CLIENT_LOG(WFD_LOG_ERROR, "Error!!! Invalid resp cmd = %d\n",
						   rsp.cmd);
			return WIFI_DIRECT_ERROR_OPERATION_FAILED;
		}
	}

#else
	int fd;
	int n;
	char mac_info[18];
	unsigned char la_mac_addr[6];

	memset(mac_info, 0, sizeof(mac_info));
	
	if( (fd = open(WIFI_DIRECT_MAC_ADDRESS_INFO_FILE, O_RDONLY)) == -1)
	{
		WFD_CLIENT_LOG(WFD_LOG_ERROR, "[.mac.info] file open failed.\n");
		__WFD_CLIENT_FUNC_END__;
		return WIFI_DIRECT_ERROR_OPERATION_FAILED;
	}

	n = read(fd, mac_info, 18);
	if(n < 0)
	{
		WFD_CLIENT_LOG(WFD_LOG_ERROR, "[.mac.info] file read failed.\n");
		__WFD_CLIENT_FUNC_END__;
		return WIFI_DIRECT_ERROR_OPERATION_FAILED;
	}

	WFD_CLIENT_LOG(WFD_LOG_LOW, "mac_address = [%s]\n", mac_info);

	memset(la_mac_addr, 0, sizeof(la_mac_addr));
	macaddr_atoe(mac_info, la_mac_addr);
	la_mac_addr[0] = la_mac_addr[0] | 0x02;
	la_mac_addr[1] = la_mac_addr[1];
	la_mac_addr[2] = la_mac_addr[2];
	la_mac_addr[3] = la_mac_addr[3];
	la_mac_addr[4] = la_mac_addr[4];
	la_mac_addr[5] = la_mac_addr[5];

	char *temp_mac = NULL;
	temp_mac = (char *) calloc(1, 18);
	if (NULL == temp_mac)
	{
		WFD_CLIENT_LOG(WFD_LOG_ERROR, "Failed to allocate memory for MAC address\n");
		return WIFI_DIRECT_ERROR_OUT_OF_MEMORY;
	}

	//strncpy(temp_mac, mac_info, strlen(mac_info));
	snprintf(temp_mac, 18, MACSTR, MAC2STR(la_mac_addr));

	*mac_address = temp_mac;
	
#endif

	__WFD_CLIENT_FUNC_END__;

	return WIFI_DIRECT_ERROR_NONE;
}


int wifi_direct_get_state(wifi_direct_state_e * state)
{
	wifi_direct_client_info_s *client_info = __wfd_get_control();

	__WFD_CLIENT_FUNC_START__;

	if (NULL == state)
	{
		WFD_CLIENT_LOG(WFD_LOG_ERROR, "NULL Param [state]!\n");
		__WFD_CLIENT_FUNC_END__;
		return WIFI_DIRECT_ERROR_INVALID_PARAMETER;
	}

	if ((client_info->is_registered == false)
		|| (client_info->client_id == WFD_INVALID_ID))
	{
		WFD_CLIENT_LOG(WFD_LOG_ERROR, "Client is NOT registered.\n");
		__WFD_CLIENT_FUNC_END__;
		return WIFI_DIRECT_ERROR_NOT_INITIALIZED;
	}

	wifi_direct_client_request_s req;
	wifi_direct_client_response_s rsp;

	int ret = WIFI_DIRECT_ERROR_NONE;

	memset(&req, 0, sizeof(wifi_direct_client_request_s));
	memset(&rsp, 0, sizeof(wifi_direct_client_response_s));

	req.cmd = WIFI_DIRECT_CMD_GET_LINK_STATUS;
	req.client_id = client_info->client_id;

	ret =
		__wfd_client_send_request(client_info->sync_sockfd, &req,
								  sizeof(wifi_direct_client_request_s));
	if (ret != WIFI_DIRECT_ERROR_NONE)
	{
		WFD_CLIENT_LOG(WFD_LOG_ERROR,
					   "Error!!! writing to socket, Errno = %s\n",
					   strerror(errno));
		WFD_CLIENT_LOG(WFD_LOG_ERROR, "Error!!! [%s]\n",
					   __wfd_print_error(ret));
		client_info->sync_sockfd = -1;
		__wfd_reset_control();
		__WFD_CLIENT_FUNC_END__;
		return WIFI_DIRECT_ERROR_COMMUNICATION_FAILED;
	}

	if ((ret =
		 __wfd_client_read_socket(client_info->sync_sockfd, (char *) &rsp,
								  sizeof(wifi_direct_client_response_s))) <= 0)
	{
		WFD_CLIENT_LOG(WFD_LOG_ERROR,
					   "Error!!! reading socket, status = %d errno = %s\n", ret,
					   strerror(errno));
		client_info->sync_sockfd = -1;
		__wfd_reset_control();
		__WFD_CLIENT_FUNC_END__;
		return WIFI_DIRECT_ERROR_COMMUNICATION_FAILED;
	}
	else
	{
		if (rsp.cmd == WIFI_DIRECT_CMD_GET_LINK_STATUS)
		{
			if (rsp.result != WIFI_DIRECT_ERROR_NONE)
			{
				WFD_CLIENT_LOG(WFD_LOG_LOW,
							   "Error!!! Result received = %d %s\n", rsp.result,
							   __wfd_print_error(rsp.result));
				__WFD_CLIENT_FUNC_END__;
				return rsp.result;
			}
			else
			{
				WFD_CLIENT_LOG(WFD_LOG_LOW, "Link Status = %d \n",
							   (int) rsp.param1);
				*state = (wifi_direct_state_e) rsp.param1;

				/* for CAPI : there is no WIFI_DIRECT_STATE_GROUP_OWNER type in CAPI */
				if(*state == WIFI_DIRECT_STATE_GROUP_OWNER)
					*state = WIFI_DIRECT_STATE_CONNECTED;
				
			}
		}
		else
		{
			WFD_CLIENT_LOG(WFD_LOG_ERROR, "Error!!! Invalid resp cmd = %d\n",
						   rsp.cmd);
			return WIFI_DIRECT_ERROR_OPERATION_FAILED;
		}
	}

	__WFD_CLIENT_FUNC_END__;

	return WIFI_DIRECT_ERROR_NONE;
}


int wifi_direct_is_discoverable(bool* discoverable)
{
{
	wifi_direct_client_info_s *client_info = __wfd_get_control();

	__WFD_CLIENT_FUNC_START__;

	if (discoverable == NULL)
	{
		WFD_CLIENT_LOG(WFD_LOG_ERROR, "NULL Param [discoverable]!\n");
		__WFD_CLIENT_FUNC_END__;
		return WIFI_DIRECT_ERROR_INVALID_PARAMETER;
	}

	if ((client_info->is_registered == false)
		|| (client_info->client_id == WFD_INVALID_ID))
	{
		WFD_CLIENT_LOG(WFD_LOG_ERROR, "Client is NOT registered.\n");
		__WFD_CLIENT_FUNC_END__;
		return WIFI_DIRECT_ERROR_NOT_INITIALIZED;
	}

	wifi_direct_client_request_s req;
	wifi_direct_client_response_s rsp;

	int status = WIFI_DIRECT_ERROR_NONE;

	memset(&req, 0, sizeof(wifi_direct_client_request_s));
	memset(&rsp, 0, sizeof(wifi_direct_client_response_s));

	req.cmd = WIFI_DIRECT_CMD_IS_DISCOVERABLE;
	req.client_id = client_info->client_id;

	status =
		__wfd_client_send_request(client_info->sync_sockfd, &req,
								  sizeof(wifi_direct_client_request_s));
	if (status != WIFI_DIRECT_ERROR_NONE)
	{
		WFD_CLIENT_LOG(WFD_LOG_ERROR,
					   "Error!!! writing to socket, Errno = %s\n",
					   strerror(errno));
		WFD_CLIENT_LOG(WFD_LOG_ERROR, "Error!!! [%s]\n",
					   __wfd_print_error(status));
		client_info->sync_sockfd = -1;
		__wfd_reset_control();
		__WFD_CLIENT_FUNC_END__;
		return WIFI_DIRECT_ERROR_COMMUNICATION_FAILED;
	}

	if ((status =
		 __wfd_client_read_socket(client_info->sync_sockfd, (char *) &rsp,
								  sizeof(wifi_direct_client_response_s))) <= 0)
	{
		WFD_CLIENT_LOG(WFD_LOG_ERROR,
					   "Error!!! reading socket, status = %d errno = %s\n",
					   status, strerror(errno));
		client_info->sync_sockfd = -1;
		__wfd_reset_control();
		__WFD_CLIENT_FUNC_END__;
		return WIFI_DIRECT_ERROR_COMMUNICATION_FAILED;
	}
	else
	{
		if (rsp.cmd == WIFI_DIRECT_CMD_IS_DISCOVERABLE)
		{
			if (rsp.result != WIFI_DIRECT_ERROR_NONE)
			{
				WFD_CLIENT_LOG(WFD_LOG_LOW, "Error!!! Result received = %d \n",
							   rsp.result);
				WFD_CLIENT_LOG(WFD_LOG_LOW, "Error!!! [%s]\n",
							   __wfd_print_error(rsp.result));
				__WFD_CLIENT_FUNC_END__;
				return rsp.result;
			}
			else
			{
				WFD_CLIENT_LOG(WFD_LOG_LOW,
							   "wifi_direct_is_discoverable() %s SUCCESS \n",
							   rsp.param2);
				*discoverable = (bool) rsp.param1;
			}
		}
		else
		{
			WFD_CLIENT_LOG(WFD_LOG_ERROR, "Error!!! Invalid resp cmd = %d\n",
						   rsp.cmd);
			return WIFI_DIRECT_ERROR_OPERATION_FAILED;
		}
	}

	__WFD_CLIENT_FUNC_END__;

	return WIFI_DIRECT_ERROR_NONE;

}
}


int wifi_direct_get_primary_device_type(wifi_direct_primary_device_type_e* type)
{
	wifi_direct_client_info_s *client_info = __wfd_get_control();

	__WFD_CLIENT_FUNC_START__;

	if (NULL == type)
	{
		WFD_CLIENT_LOG(WFD_LOG_ERROR, "NULL Param [type]!\n");
		__WFD_CLIENT_FUNC_END__;
		return WIFI_DIRECT_ERROR_INVALID_PARAMETER;
	}

	if ((client_info->is_registered == false)
		|| (client_info->client_id == WFD_INVALID_ID))
	{
		WFD_CLIENT_LOG(WFD_LOG_ERROR, "Client is NOT registered.\n");
		__WFD_CLIENT_FUNC_END__;
		return WIFI_DIRECT_ERROR_NOT_INITIALIZED;
	}


	int result;
	wifi_direct_config_data_s *config;
	result = wifi_direct_get_config_data(&config);
	if(result != WIFI_DIRECT_ERROR_NONE)
	{
		WFD_CLIENT_LOG(WFD_LOG_ERROR, "Failed to get wifi_direct_get_config_data() result=[%d]\n", result);
		__WFD_CLIENT_FUNC_END__;
		return WIFI_DIRECT_ERROR_OPERATION_FAILED;
	}

	WFD_CLIENT_LOG(WFD_LOG_LOW, "Current primary_dev_type [%d]\n", config->primary_dev_type);

	*type = config->primary_dev_type;

	__WFD_CLIENT_FUNC_END__;

	return WIFI_DIRECT_ERROR_NONE;
}


int wifi_direct_get_config_data(wifi_direct_config_data_s ** config)
{
	wifi_direct_client_info_s *client_info = __wfd_get_control();

	__WFD_CLIENT_FUNC_START__;

	if ((client_info->is_registered == false)
		|| (client_info->client_id == WFD_INVALID_ID))
	{
		WFD_CLIENT_LOG(WFD_LOG_ERROR, "Client is NOT registered.\n");
		__WFD_CLIENT_FUNC_END__;
		return WIFI_DIRECT_ERROR_NOT_INITIALIZED;
	}

	if (config == NULL)
	{
		WFD_CLIENT_LOG(WFD_LOG_ERROR, "NULL Param [config]!\n");
		__WFD_CLIENT_FUNC_END__;
		return WIFI_DIRECT_ERROR_INVALID_PARAMETER;
	}

	wifi_direct_client_request_s req;
	wifi_direct_client_response_s rsp;
	wfd_config_data_s ls_config;

	int status = WIFI_DIRECT_ERROR_NONE;

	memset(&req, 0, sizeof(wifi_direct_client_request_s));
	memset(&rsp, 0, sizeof(wifi_direct_client_response_s));

	req.cmd = WIFI_DIRECT_CMD_GET_CONFIG;
	req.client_id = client_info->client_id;

	status =
		__wfd_client_send_request(client_info->sync_sockfd, &req,
								  sizeof(wifi_direct_client_request_s));
	if (status != WIFI_DIRECT_ERROR_NONE)
	{
		WFD_CLIENT_LOG(WFD_LOG_ERROR,
					   "Error!!! writing to socket, Errno = %s\n",
					   strerror(errno));
		WFD_CLIENT_LOG(WFD_LOG_ERROR, "Error!!! [%s]\n",
					   __wfd_print_error(status));
		client_info->sync_sockfd = -1;
		__wfd_reset_control();
		__WFD_CLIENT_FUNC_END__;
		return WIFI_DIRECT_ERROR_COMMUNICATION_FAILED;
	}

	if ((status =
		 __wfd_client_read_socket(client_info->sync_sockfd, (char *) &rsp,
								  sizeof(wifi_direct_client_response_s))) <= 0)
	{
		WFD_CLIENT_LOG(WFD_LOG_ERROR,
					   "Error!!! reading socket, status = %d errno = %s\n",
					   status, strerror(errno));
		client_info->sync_sockfd = -1;
		__wfd_reset_control();
		__WFD_CLIENT_FUNC_END__;
		return WIFI_DIRECT_ERROR_COMMUNICATION_FAILED;
	}
	else
	{
		if (rsp.cmd == WIFI_DIRECT_CMD_GET_CONFIG)
		{
			if (rsp.result != WIFI_DIRECT_ERROR_NONE)
			{
				WFD_CLIENT_LOG(WFD_LOG_ERROR,
							   "Error!!! Result received = %d \n", rsp.result);
				WFD_CLIENT_LOG(WFD_LOG_ERROR, "Error!!! [%s]\n",
							   __wfd_print_error(rsp.result));
				__WFD_CLIENT_FUNC_END__;
				return rsp.result;
			}
			else
			{
				int status = 0;

				WFD_CLIENT_LOG(WFD_LOG_LOW, "Link status = %d \n",
							   (int) rsp.param1);

				status =
					__wfd_client_read_more_data(client_info->sync_sockfd,
												&ls_config,
												sizeof(wfd_config_data_s));
				if (status != WIFI_DIRECT_ERROR_NONE)
				{
					WFD_CLIENT_LOG(WFD_LOG_ERROR, "socket read error.\n");
					return WIFI_DIRECT_ERROR_OPERATION_FAILED;
				}

				__wfd_client_print_config_data(&ls_config);

				wifi_direct_config_data_s *temp_config;
				temp_config =
					(wifi_direct_config_data_s *) calloc(1,
														 sizeof
														 (wifi_direct_config_data_s));

				temp_config->ssid = strdup(ls_config.ssid);
				temp_config->channel = ls_config.channel;
				temp_config->wps_config = ls_config.wps_config;
				temp_config->max_clients = ls_config.max_clients;
				temp_config->hide_SSID = ls_config.hide_SSID;
				temp_config->group_owner_intent = ls_config.group_owner_intent;
				temp_config->want_persistent_group =
					ls_config.want_persistent_group;
				temp_config->auto_connection = ls_config.auto_connection;
				temp_config->primary_dev_type = ls_config.primary_dev_type;
				temp_config->secondary_dev_type = ls_config.secondary_dev_type;

				*config = temp_config;

				WFD_CLIENT_LOG(WFD_LOG_LOW,
							   "wifi_direct_get_config_data() SUCCESS\n");
			}
		}
		else
		{
			WFD_CLIENT_LOG(WFD_LOG_ERROR, "Error!!! Invalid resp cmd = %d\n",
						   rsp.cmd);
			return WIFI_DIRECT_ERROR_OPERATION_FAILED;
		}
	}

	__WFD_CLIENT_FUNC_END__;

	return WIFI_DIRECT_ERROR_NONE;
}



int wifi_direct_set_config_data(wifi_direct_config_data_s * config)
{
	wifi_direct_client_info_s *client_info = __wfd_get_control();

	__WFD_CLIENT_FUNC_START__;

	if ((client_info->is_registered == false)
		|| (client_info->client_id == WFD_INVALID_ID))
	{
		WFD_CLIENT_LOG(WFD_LOG_ERROR, "Client is NOT registered.\n");
		__WFD_CLIENT_FUNC_END__;
		return WIFI_DIRECT_ERROR_NOT_INITIALIZED;
	}

	if (config == NULL)
	{
		WFD_CLIENT_LOG(WFD_LOG_ERROR, "NULL Param [config]!\n");
		__WFD_CLIENT_FUNC_END__;
		return WIFI_DIRECT_ERROR_INVALID_PARAMETER;
	}

	wifi_direct_client_request_s req;
	wifi_direct_client_response_s rsp;
	wfd_config_data_s ls_config;

	int status = WIFI_DIRECT_ERROR_NONE;

	memset(&req, 0, sizeof(wifi_direct_client_request_s));
	memset(&rsp, 0, sizeof(wifi_direct_client_response_s));

	req.cmd = WIFI_DIRECT_CMD_SET_CONFIG;
	req.client_id = client_info->client_id;

	status =
		__wfd_client_send_request(client_info->sync_sockfd, &req,
								  sizeof(wifi_direct_client_request_s));
	if (status != WIFI_DIRECT_ERROR_NONE)
	{
		WFD_CLIENT_LOG(WFD_LOG_ERROR,
					   "Error!!! writing to socket, Errno = %s\n",
					   strerror(errno));
		WFD_CLIENT_LOG(WFD_LOG_ERROR, "Error!!! [%s]\n",
					   __wfd_print_error(status));
		client_info->sync_sockfd = -1;
		__wfd_reset_control();
		__WFD_CLIENT_FUNC_END__;
		return WIFI_DIRECT_ERROR_COMMUNICATION_FAILED;
	}

	WFD_CLIENT_LOG(WFD_LOG_LOW, "writing msg hdr is success!\n");


	strncpy(ls_config.ssid, config->ssid, strlen(config->ssid));
	ls_config.channel = config->channel;
	ls_config.wps_config = config->wps_config;
	ls_config.max_clients = config->max_clients;
	ls_config.hide_SSID = config->hide_SSID;
	ls_config.group_owner_intent = config->group_owner_intent;
	ls_config.want_persistent_group = config->want_persistent_group;
	ls_config.auto_connection = config->auto_connection;
	ls_config.primary_dev_type = config->primary_dev_type;
	ls_config.secondary_dev_type = config->secondary_dev_type;

	__wfd_client_print_config_data(&ls_config);

	status =
		__wfd_client_send_request(client_info->sync_sockfd, &ls_config,
								  sizeof(wfd_config_data_s));
	if (status != WIFI_DIRECT_ERROR_NONE)
	{
		WFD_CLIENT_LOG(WFD_LOG_ERROR,
					   "Error!!! writing to socket, Errno = %s\n",
					   strerror(errno));
		WFD_CLIENT_LOG(WFD_LOG_ERROR, "Error!!! [%s]\n",
					   __wfd_print_error(status));
		client_info->sync_sockfd = -1;
		__wfd_reset_control();
		__WFD_CLIENT_FUNC_END__;
		return WIFI_DIRECT_ERROR_COMMUNICATION_FAILED;
	}

	if ((status =
		 __wfd_client_read_socket(client_info->sync_sockfd, (char *) &rsp,
								  sizeof(wifi_direct_client_response_s))) <= 0)
	{
		WFD_CLIENT_LOG(WFD_LOG_ERROR,
					   "Error!!! reading socket, status = %d errno = %s\n",
					   status, strerror(errno));
		client_info->sync_sockfd = -1;
		__wfd_reset_control();
		__WFD_CLIENT_FUNC_END__;
		return WIFI_DIRECT_ERROR_COMMUNICATION_FAILED;
	}
	else
	{
		if (rsp.cmd == WIFI_DIRECT_CMD_SET_CONFIG)
		{
			if (rsp.result != WIFI_DIRECT_ERROR_NONE)
			{
				WFD_CLIENT_LOG(WFD_LOG_LOW, "Error!!! Result received = %d \n",
							   rsp.result);
				WFD_CLIENT_LOG(WFD_LOG_LOW, "Error!!! [%s]\n",
							   __wfd_print_error(rsp.result));
				__WFD_CLIENT_FUNC_END__;
				return rsp.result;
			}
		}
		else
		{
			WFD_CLIENT_LOG(WFD_LOG_ERROR, "Error!!! Invalid resp cmd = %d\n",
						   rsp.cmd);
			return WIFI_DIRECT_ERROR_OPERATION_FAILED;
		}
	}

	__WFD_CLIENT_FUNC_END__;

	return WIFI_DIRECT_ERROR_NONE;
}


int wifi_direct_set_autoconnection_mode(bool mode)
{
	wifi_direct_client_info_s *client_info = __wfd_get_control();

	__WFD_CLIENT_FUNC_START__;

	if ((client_info->is_registered == false)
		|| (client_info->client_id == WFD_INVALID_ID))
	{
		WFD_CLIENT_LOG(WFD_LOG_ERROR, "Client is NOT registered.\n");
		__WFD_CLIENT_FUNC_END__;
		return WIFI_DIRECT_ERROR_NOT_INITIALIZED;
	}

	wifi_direct_client_request_s req;
	wifi_direct_client_response_s rsp;

	int status = WIFI_DIRECT_ERROR_NONE;

	memset(&req, 0, sizeof(wifi_direct_client_request_s));
	memset(&rsp, 0, sizeof(wifi_direct_client_response_s));

	req.cmd = WIFI_DIRECT_CMD_SET_AUTOCONNECTION_MODE;
	req.client_id = client_info->client_id;

	status =__wfd_client_send_request(client_info->sync_sockfd, &req,
								  sizeof(wifi_direct_client_request_s));
	if (status != WIFI_DIRECT_ERROR_NONE)
	{
		WFD_CLIENT_LOG(WFD_LOG_ERROR,
					   "Error!!! writing to socket, Errno = %s\n",
					   strerror(errno));
		WFD_CLIENT_LOG(WFD_LOG_ERROR, "Error!!! [%s]\n",
					   __wfd_print_error(status));
		client_info->sync_sockfd = -1;
		__wfd_reset_control();
		__WFD_CLIENT_FUNC_END__;
		return WIFI_DIRECT_ERROR_COMMUNICATION_FAILED;
	}

	WFD_CLIENT_LOG(WFD_LOG_LOW, "writing msg hdr is success!\n");

	status =
		__wfd_client_send_request(client_info->sync_sockfd, &mode,
								  sizeof(bool));
	if (status != WIFI_DIRECT_ERROR_NONE)
	{
		WFD_CLIENT_LOG(WFD_LOG_ERROR,
					   "Error!!! writing to socket, Errno = %s\n",
					   strerror(errno));
		WFD_CLIENT_LOG(WFD_LOG_ERROR, "Error!!! [%s]\n",
					   __wfd_print_error(status));
		client_info->sync_sockfd = -1;
		__wfd_reset_control();
		__WFD_CLIENT_FUNC_END__;
		return WIFI_DIRECT_ERROR_COMMUNICATION_FAILED;
	}

	if ((status =
		 __wfd_client_read_socket(client_info->sync_sockfd, (char *) &rsp,
								  sizeof(wifi_direct_client_response_s))) <= 0)
	{
		WFD_CLIENT_LOG(WFD_LOG_ERROR,
					   "Error!!! reading socket, status = %d errno = %s\n",
					   status, strerror(errno));
		client_info->sync_sockfd = -1;
		__wfd_reset_control();
		__WFD_CLIENT_FUNC_END__;
		return WIFI_DIRECT_ERROR_COMMUNICATION_FAILED;
	}
	else
	{
		if (rsp.cmd == WIFI_DIRECT_CMD_SET_AUTOCONNECTION_MODE)
		{
			if (rsp.result != WIFI_DIRECT_ERROR_NONE)
			{
				WFD_CLIENT_LOG(WFD_LOG_LOW, "Error!!! Result received = %d \n",
							   rsp.result);
				WFD_CLIENT_LOG(WFD_LOG_LOW, "Error!!! [%s]\n",
							   __wfd_print_error(rsp.result));
				__WFD_CLIENT_FUNC_END__;
				return rsp.result;
			}
		}
		else
		{
			WFD_CLIENT_LOG(WFD_LOG_ERROR, "Error!!! Invalid resp cmd = %d\n",
						   rsp.cmd);
			return WIFI_DIRECT_ERROR_OPERATION_FAILED;
		}
	}

	__WFD_CLIENT_FUNC_END__;

	return WIFI_DIRECT_ERROR_NONE;
}



int wifi_direct_set_p2poem_loglevel(int increase_log_level)
{
	wifi_direct_client_info_s *client_info = __wfd_get_control();

	__WFD_CLIENT_FUNC_START__;

	if ((client_info->is_registered == false)
		|| (client_info->client_id == WFD_INVALID_ID))
	{
		WFD_CLIENT_LOG(WFD_LOG_ERROR, "Client is NOT registered.\n");
		__WFD_CLIENT_FUNC_END__;
		return WIFI_DIRECT_ERROR_NOT_INITIALIZED;
	}

	wifi_direct_client_request_s req;
	wifi_direct_client_response_s rsp;

	int ret = WIFI_DIRECT_ERROR_NONE;

	memset(&req, 0, sizeof(wifi_direct_client_request_s));
	memset(&rsp, 0, sizeof(wifi_direct_client_response_s));

	req.cmd = WIFI_DIRECT_CMD_SET_OEM_LOGLEVEL;
	req.client_id = client_info->client_id;
	if (increase_log_level == 0)
		req.data.listen_only = false;
	else
		req.data.listen_only = true;

	ret =
		__wfd_client_send_request(client_info->sync_sockfd, &req,
								  sizeof(wifi_direct_client_request_s));
	if (ret != WIFI_DIRECT_ERROR_NONE)
	{
		WFD_CLIENT_LOG(WFD_LOG_ERROR,
					   "Error!!! writing to socket, Errno = %s\n",
					   strerror(errno));
		WFD_CLIENT_LOG(WFD_LOG_ERROR, "Error!!! [%s]\n",
					   __wfd_print_error(ret));
		client_info->sync_sockfd = -1;
		__wfd_reset_control();
		__WFD_CLIENT_FUNC_END__;
		return WIFI_DIRECT_ERROR_COMMUNICATION_FAILED;
	}

	if ((ret =
		 __wfd_client_read_socket(client_info->sync_sockfd, (char *) &rsp,
								  sizeof(wifi_direct_client_response_s))) <= 0)
	{
		WFD_CLIENT_LOG(WFD_LOG_ERROR,
					   "Error!!! reading socket, status = %d errno = %s\n", ret,
					   strerror(errno));
		client_info->sync_sockfd = -1;
		__wfd_reset_control();
		__WFD_CLIENT_FUNC_END__;
		return WIFI_DIRECT_ERROR_COMMUNICATION_FAILED;
	}
	else
	{
		if (rsp.cmd == WIFI_DIRECT_CMD_SET_OEM_LOGLEVEL)
		{
			if (rsp.result != WIFI_DIRECT_ERROR_NONE)
			{
				WFD_CLIENT_LOG(WFD_LOG_LOW, "Error!!! Result received = %d \n",
							   rsp.result);
				WFD_CLIENT_LOG(WFD_LOG_LOW, "Error!!! [%s]\n",
							   __wfd_print_error(rsp.result));
				__WFD_CLIENT_FUNC_END__;
				return rsp.result;
			}
		}
		else
		{
			WFD_CLIENT_LOG(WFD_LOG_ERROR, "Error!!! Invalid resp cmd = %d\n",
						   rsp.cmd);
			return WIFI_DIRECT_ERROR_OPERATION_FAILED;
		}
	}

	__WFD_CLIENT_FUNC_END__;

	return WIFI_DIRECT_ERROR_NONE;
}
