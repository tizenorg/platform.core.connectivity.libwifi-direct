/*
 * libwifi-direct
 *
 * Copyright (c) 2012 Samsung Electronics Co., Ltd. All rights reserved.
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
#include <pthread.h>

/*****************************************************************************
 * 	System headers
 *****************************************************************************/
#include <vconf.h>

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
	.ip_assigned_cb = NULL,
	.user_data_for_cb_activation = NULL,
	.user_data_for_cb_discover = NULL,
	.user_data_for_cb_connection = NULL,
	.user_data_for_cb_ip_assigned = NULL,
	.mutex = PTHREAD_MUTEX_INITIALIZER
};

/*****************************************************************************
 * 	Local Functions Definition
 *****************************************************************************/

#ifdef __NR_gettid
pid_t gettid(void)
{
	return syscall(__NR_gettid);
}
#else
#error "__NR_gettid is not defined, please include linux/unistd.h"
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
	if (g_client_info.sync_sockfd > 0)
		close(g_client_info.sync_sockfd);
	g_client_info.sync_sockfd = -1;

	if (g_client_info.async_sockfd > 0)
		close(g_client_info.async_sockfd);
	g_client_info.async_sockfd = -1;

	g_client_info.is_registered = FALSE;

	// Initialize callbacks
	g_client_info.activation_cb = NULL;
	g_client_info.discover_cb = NULL;
	g_client_info.connection_cb = NULL;
	g_client_info.ip_assigned_cb = NULL;
	g_client_info.user_data_for_cb_activation = NULL;
	g_client_info.user_data_for_cb_discover = NULL;
	g_client_info.user_data_for_cb_connection = NULL;
	g_client_info.user_data_for_cb_ip_assigned = NULL;

	pthread_mutex_destroy(&g_client_info.mutex);
}

static int macaddr_atoe(const char *p, unsigned char mac[])
{
	int i = 0;

	for (;;) {
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
	case WIFI_DIRECT_CLI_EVENT_INVALID:
		return "WIFI_DIRECT_CLI_EVENT_INVALID";
		break;
	case WIFI_DIRECT_CLI_EVENT_ACTIVATION:
		return "ACTIVATION";
		break;
	case WIFI_DIRECT_CLI_EVENT_DEACTIVATION:
		return "DEACTIVATION";
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
	case WIFI_DIRECT_CLI_EVENT_CONNECTION_START:
		return "WIFI_DIRECT_CLI_EVENT_CONNECTION_START";
		break;
	case WIFI_DIRECT_CLI_EVENT_CONNECTION_REQ:
		return "WIFI_DIRECT_CLI_EVENT_CONNECTION_REQ";
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
	case WIFI_DIRECT_CLI_EVENT_DISASSOCIATION_IND:
		return "WIFI_DIRECT_CLI_EVENT_DISASSOCIATION_IND";
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
	case WIFI_DIRECT_CLI_EVENT_INVITATION_REQ:
		return "WIFI_DIRECT_CLI_EVENT_INVITATION_REQ";
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
	case WIFI_DIRECT_ERROR_NONE:
		return "WIFI_DIRECT_ERROR_NONE";
	case WIFI_DIRECT_ERROR_NOT_PERMITTED:
		return "WIFI_DIRECT_ERROR_NOT_PERMITTED";
	case WIFI_DIRECT_ERROR_OUT_OF_MEMORY:
		return "WIFI_DIRECT_ERROR_OUT_OF_MEMORY";
	case WIFI_DIRECT_ERROR_RESOURCE_BUSY:
		return "WIFI_DIRECT_ERROR_RESOURCE_BUSY";
	case WIFI_DIRECT_ERROR_INVALID_PARAMETER:
		return "WIFI_DIRECT_ERROR_INVALID_PARAMETER";
	case WIFI_DIRECT_ERROR_NOT_INITIALIZED:
		return "WIFI_DIRECT_ERROR_NOT_INITIALIZED";
	case WIFI_DIRECT_ERROR_COMMUNICATION_FAILED:
		return "WIFI_DIRECT_ERROR_COMMUNICATION_FAILED";
	case WIFI_DIRECT_ERROR_WIFI_USED:
		return "WIFI_DIRECT_ERROR_WIFI_USED";
	case WIFI_DIRECT_ERROR_MOBILE_AP_USED:
		return "WIFI_DIRECT_ERROR_MOBILE_AP_USED";
	case WIFI_DIRECT_ERROR_CONNECTION_FAILED:
		return "WIFI_DIRECT_ERROR_CONNECTION_FAILED";
	case WIFI_DIRECT_ERROR_AUTH_FAILED:
		return "WIFI_DIRECT_ERROR_AUTH_FAILED";
	case WIFI_DIRECT_ERROR_OPERATION_FAILED:
		return "WIFI_DIRECT_ERROR_OPERATION_FAILED";
	case WIFI_DIRECT_ERROR_TOO_MANY_CLIENT:
		return "WIFI_DIRECT_ERROR_TOO_MANY_CLIENT";
	case WIFI_DIRECT_ERROR_ALREADY_INITIALIZED:
		return "WIFI_DIRECT_ERROR_ALREADY_INITIALIZED";
	default:
		WDC_LOGE("Invalid error value: [%d]", error);
		return "Invalid error";
	}
}

static int __wfd_convert_client_event(wfd_client_event_e event)
{
	__WDC_LOG_FUNC_START__;

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
	case WIFI_DIRECT_CLI_EVENT_DISCOVER_FOUND_PEERS:
		return WIFI_DIRECT_DISCOVERY_FOUND;
		break;
	case WIFI_DIRECT_CLI_EVENT_DISCOVER_END:
		return WIFI_DIRECT_DISCOVERY_FINISHED;
		break;
	case WIFI_DIRECT_CLI_EVENT_CONNECTION_REQ:
		return WIFI_DIRECT_CONNECTION_REQ;
		break;
	case WIFI_DIRECT_CLI_EVENT_CONNECTION_WPS_REQ:
		return WIFI_DIRECT_CONNECTION_WPS_REQ;
		break;
	case WIFI_DIRECT_CLI_EVENT_CONNECTION_START:
		return WIFI_DIRECT_CONNECTION_IN_PROGRESS;
		break;
	case WIFI_DIRECT_CLI_EVENT_CONNECTION_RSP:
		return WIFI_DIRECT_CONNECTION_RSP;
		break;
	case WIFI_DIRECT_CLI_EVENT_DISCONNECTION_RSP:
		return WIFI_DIRECT_DISCONNECTION_RSP;
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
	case WIFI_DIRECT_CLI_EVENT_INVITATION_REQ:
		return WIFI_DIRECT_INVITATION_REQ;
		break;
	default:
		WDC_LOGE("Invalid event : [%d]", event);
		break;
	}

	__WDC_LOG_FUNC_END__;
	return -1;
}

char *__wfd_client_print_cmd(wifi_direct_cmd_e cmd)
{
	switch (cmd)
	{
	case WIFI_DIRECT_CMD_REGISTER:
		return "WIFI_DIRECT_CMD_REGISTER";
	case WIFI_DIRECT_CMD_INIT_ASYNC_SOCKET:
		return "WIFI_DIRECT_CMD_INIT_ASYNC_SOCKET";
	case WIFI_DIRECT_CMD_DEREGISTER:
		return "WIFI_DIRECT_CMD_DEREGISTER";
	case WIFI_DIRECT_CMD_ACTIVATE:
		return "WIFI_DIRECT_CMD_ACTIVATE";
	case WIFI_DIRECT_CMD_DEACTIVATE:
		return "WIFI_DIRECT_CMD_DEACTIVATE";
	case WIFI_DIRECT_CMD_START_DISCOVERY:
		return "WIFI_DIRECT_CMD_START_DISCOVERY";
	case WIFI_DIRECT_CMD_CANCEL_DISCOVERY:
		return "WIFI_DIRECT_CMD_CANCEL_DISCOVERY";
	case WIFI_DIRECT_CMD_GET_DISCOVERY_RESULT:
		return "WIFI_DIRECT_CMD_GET_DISCOVERY_RESULT";
	case WIFI_DIRECT_CMD_GET_LINK_STATUS:
		return "WIFI_DIRECT_CMD_GET_LINK_STATUS";
	case WIFI_DIRECT_CMD_CONNECT:
		return "WIFI_DIRECT_CMD_CONNECT";
	case WIFI_DIRECT_CMD_CANCEL_CONNECTION:
		return "WIFI_DIRECT_CMD_CANCEL_CONNECTION";
	case WIFI_DIRECT_CMD_REJECT_CONNECTION:
		return "WIFI_DIRECT_CMD_REJECT_CONNECTION";
	case WIFI_DIRECT_CMD_DISCONNECT_ALL:
		return "WIFI_DIRECT_CMD_DISCONNECT_ALL";
	case WIFI_DIRECT_CMD_CREATE_GROUP:
		return "WIFI_DIRECT_CMD_CREATE_GROUP";
	case WIFI_DIRECT_CMD_IS_GROUPOWNER:
		return "WIFI_DIRECT_CMD_IS_GROUPOWNER";
	case WIFI_DIRECT_CMD_GET_SSID:
		return "WIFI_DIRECT_CMD_GET_SSID";
	case WIFI_DIRECT_CMD_SET_SSID:
		return "WIFI_DIRECT_CMD_SET_SSID";
	case WIFI_DIRECT_CMD_GET_IP_ADDR:
		return "WIFI_DIRECT_CMD_GET_IP_ADDR";
	case WIFI_DIRECT_CMD_GET_CONFIG:
		return "WIFI_DIRECT_CMD_GET_CONFIG";
	case WIFI_DIRECT_CMD_SET_CONFIG:
		return "WIFI_DIRECT_CMD_SET_CONFIG";
	case WIFI_DIRECT_CMD_SEND_CONNECT_REQ:
		return "WIFI_DIRECT_CMD_SEND_CONNECT_REQ";
	case WIFI_DIRECT_CMD_ACTIVATE_PUSHBUTTON:
		return "WIFI_DIRECT_CMD_ACTIVATE_PUSHBUTTON";
	case WIFI_DIRECT_CMD_SET_WPS_PIN:
		return "WIFI_DIRECT_CMD_SET_WPS_PIN";
	case WIFI_DIRECT_CMD_GET_WPS_PIN:
		return "WIFI_DIRECT_CMD_GET_WPS_PIN";
	case WIFI_DIRECT_CMD_GENERATE_WPS_PIN:
		return "WIFI_DIRECT_CMD_GENERATE_WPS_PIN";
	case WIFI_DIRECT_CMD_SET_WPA:
		return "WIFI_DIRECT_CMD_SET_WPA";
	case WIFI_DIRECT_CMD_GET_SUPPORTED_WPS_MODE:
		return "WIFI_DIRECT_CMD_GET_SUPPORTED_WPS_MODE";
	case WIFI_DIRECT_CMD_GET_LOCAL_WPS_MODE:
		return "WIFI_DIRECT_CMD_GET_LOCAL_WPS_MODE";
	case WIFI_DIRECT_CMD_SET_REQ_WPS_MODE:
		return "WIFI_DIRECT_CMD_SET_REQ_WPS_MODE";
	case WIFI_DIRECT_CMD_GET_REQ_WPS_MODE:
		return "WIFI_DIRECT_CMD_GET_REQ_WPS_MODE";
	case WIFI_DIRECT_CMD_GET_CONNECTED_PEERS_INFO:
		return "WIFI_DIRECT_CMD_GET_CONNECTED_PEERS_INFO";
	case WIFI_DIRECT_CMD_DESTROY_GROUP:
		return "WIFI_DIRECT_CMD_DESTROY_GROUP";
	case WIFI_DIRECT_CMD_DISCONNECT:
		return "WIFI_DIRECT_CMD_DISCONNECT";
	case WIFI_DIRECT_CMD_SET_GO_INTENT:
		return "WIFI_DIRECT_CMD_SET_GO_INTENT";
	case WIFI_DIRECT_CMD_GET_GO_INTENT:
		return "WIFI_DIRECT_CMD_GET_GO_INTENT";
	case WIFI_DIRECT_CMD_GET_DEVICE_MAC:
		return "WIFI_DIRECT_CMD_GET_DEVICE_MAC";
	case WIFI_DIRECT_CMD_IS_AUTONOMOUS_GROUP:
		return "WIFI_DIRECT_CMD_IS_AUTONOMOUS_GROUP";
	case WIFI_DIRECT_CMD_SET_MAX_CLIENT:
		return "WIFI_DIRECT_CMD_SET_MAX_CLIENT";
	case WIFI_DIRECT_CMD_GET_MAX_CLIENT:
		return "WIFI_DIRECT_CMD_GET_MAX_CLIENT";
	case WIFI_DIRECT_CMD_SET_AUTOCONNECTION_MODE:
		return "WIFI_DIRECT_CMD_SET_AUTOCONNECTION_MODE";
	case WIFI_DIRECT_CMD_IS_AUTOCONNECTION_MODE:
		return "WIFI_DIRECT_CMD_IS_AUTOCONNECTION_MODE";
	case WIFI_DIRECT_CMD_IS_DISCOVERABLE:
		return "WIFI_DIRECT_CMD_IS_DISCOVERABLE";
	case WIFI_DIRECT_CMD_IS_LISTENING_ONLY:
		return "WIFI_DIRECT_CMD_IS_LISTENING_ONLY";
	case WIFI_DIRECT_CMD_GET_OPERATING_CHANNEL:
		return "WIFI_DIRECT_CMD_GET_OPERATING_CHANNEL";
	case WIFI_DIRECT_CMD_ACTIVATE_PERSISTENT_GROUP:
		return "WIFI_DIRECT_CMD_ACTIVATE_PERSISTENT_GROUP";
	case WIFI_DIRECT_CMD_DEACTIVATE_PERSISTENT_GROUP:
		return "WIFI_DIRECT_CMD_DEACTIVATE_PERSISTENT_GROUP";
	case WIFI_DIRECT_CMD_IS_PERSISTENT_GROUP:
		return "WIFI_DIRECT_CMD_IS_PERSISTENT_GROUP";
	case WIFI_DIRECT_CMD_GET_PERSISTENT_GROUP_INFO:
		return "WIFI_DIRECT_CMD_GET_PERSISTENT_GROUP_INFO";
	case WIFI_DIRECT_CMD_REMOVE_PERSISTENT_GROUP:
		return "WIFI_DIRECT_CMD_REMOVE_PERSISTENT_GROUP";
	case WIFI_DIRECT_CMD_GET_DEVICE_NAME:
		return "WIFI_DIRECT_CMD_GET_DEVICE_NAME";
	case WIFI_DIRECT_CMD_SET_DEVICE_NAME:
		return "WIFI_DIRECT_CMD_SET_DEVICE_NAME";
	case WIFI_DIRECT_CMD_SET_OEM_LOGLEVEL:
		return "WIFI_DIRECT_CMD_SET_OEM_LOGLEVEL";
	case WIFI_DIRECT_CMD_SERVICE_ADD:
		return "WIFI_DIRECT_CMD_SERVICE_ADD";
	case WIFI_DIRECT_CMD_SERVICE_DEL:
		return "WIFI_DIRECT_CMD_SERVICE_DEL";
	case WIFI_DIRECT_CMD_SERV_DISC_REQ:
		return "WIFI_DIRECT_CMD_SERV_DISC_REQ";
	case WIFI_DIRECT_CMD_SERV_DISC_CANCEL:
		return "WIFI_DIRECT_CMD_SERV_DISC_CANCEL";
	default:
		return "WIFI_DIRECT_CMD_INVALID";

	}
}

static int __wfd_client_check_socket(int sock, int timeout)
{
	struct pollfd p_fd;
	int res = 0;

	if (sock < SOCK_FD_MIN || timeout < 0) {
		WDC_LOGE("Invalid parameter");
		return -1;
	}

	p_fd.fd = sock;
	p_fd.events = POLLIN | POLLERR | POLLHUP | POLLNVAL;
	res = poll((struct pollfd *) &p_fd, 1, timeout);

	if (res < 0) {
		WDC_LOGE("Polling error from socket[%d]. [%s]", sock, strerror(errno));
		return -1;
	} else if (res == 0) {
		WDC_LOGD( "poll timeout. socket is busy");
		return 1;
	} else {
		if (p_fd.revents & POLLERR) {
			WDC_LOGE("Error! POLLERR from socket[%d]", sock);
			return -1;
		} else if (p_fd.revents & POLLHUP) {
			WDC_LOGE("Error! POLLHUP from socket[%d]", sock);
			return -1;
		} else if (p_fd.revents & POLLNVAL) {
			WDC_LOGE("Error! POLLNVAL from socket[%d]", sock);
			return -1;
		} else if (p_fd.revents & POLLIN) {
			WDC_LOGD("POLLIN from socket [%d]", sock);
			return 0;
		}
	}

	WDC_LOGD("Unknown poll event [%d]", p_fd.revents);
	return -1;
}

static int __wfd_client_write_socket(int sockfd, void *data, int data_len)
{
	__WDC_LOG_FUNC_START__;
	int wbytes = 0;

	if (sockfd < SOCK_FD_MIN || !data || data_len <= 0) {
		WDC_LOGE("Invalid parameter");
		__WDC_LOG_FUNC_END__;
		return -1;
	}

	WDC_LOGD("Write [%d] bytes to socket [%d].", data_len, sockfd);
	errno = 0;
	wbytes = write(sockfd, (char*) data, data_len);
	if (wbytes <= 0) {
		WDC_LOGE("Error!!! writing to the socket. Error = %s", strerror(errno));
		__WDC_LOG_FUNC_END__;
		return -1;
	}

	__WDC_LOG_FUNC_END__;
	return 0;
}

static int __wfd_client_read_socket(int sockfd, char *data, int data_len)
{
	__WDC_LOG_FUNC_START__;
	int rbytes = 0;
	int total_rbytes = 0;
	int res = 0;

	if (sockfd < SOCK_FD_MIN) {
		WDC_LOGE("Error!!! Invalid socket FD [%d]", sockfd);
		__WDC_LOG_FUNC_END__;
		return -1;
	}

	if (!data || data_len <= 0) {
		WDC_LOGE("Error!!! Invalid parameter");
		__WDC_LOG_FUNC_END__;
		return -1;
	}

	res = __wfd_client_check_socket(sockfd, 10000);
	if (res < 0) {
		WDC_LOGE("Socket error");
		return WIFI_DIRECT_ERROR_COMMUNICATION_FAILED;
	} else if (res > 0) {
		WDC_LOGE("Socket is busy");
		return WIFI_DIRECT_ERROR_RESOURCE_BUSY;
	}

	while(data_len) {
		errno = 0;
		rbytes = read(sockfd, data, data_len);
		if (rbytes <= 0) {
			WDC_LOGE("Failed to read socket[%d] [%s]", sockfd, strerror(errno));
			return -1;
		}
		total_rbytes += rbytes;
		data += rbytes;
		data_len -= rbytes;
	}

	__WDC_LOG_FUNC_END__;
	return total_rbytes;
}

static int __wfd_client_send_request(int sockfd, wifi_direct_client_request_s *req,
								wifi_direct_client_response_s *rsp)
{
	__WDC_LOG_FUNC_START__;
	int res = 0;

	if (!req || !rsp || sockfd < SOCK_FD_MIN) {
		WDC_LOGE("Invalid parameter");
		__WDC_LOG_FUNC_END__;
		return WIFI_DIRECT_ERROR_INVALID_PARAMETER;
	}

	pthread_mutex_lock(&g_client_info.mutex);
	res = __wfd_client_write_socket(sockfd, req, sizeof(wifi_direct_client_request_s));
	if (res != WIFI_DIRECT_ERROR_NONE) {
		WDC_LOGE("Failed to write into socket [%s]", __wfd_print_error(res));
		__wfd_reset_control();
		pthread_mutex_unlock(&g_client_info.mutex);
		__WDC_LOG_FUNC_END__;
		return WIFI_DIRECT_ERROR_COMMUNICATION_FAILED;
	}
	WDC_LOGD("Succeeded to send request [%d: %s]", req->cmd, __wfd_client_print_cmd(req->cmd));

	res = __wfd_client_read_socket(sockfd, rsp, sizeof(wifi_direct_client_response_s));
	pthread_mutex_unlock(&g_client_info.mutex);
	if (res <= 0) {
		WDC_LOGE("Failed to read socket [%d]", res);
		__wfd_reset_control();
		__WDC_LOG_FUNC_END__;
		return WIFI_DIRECT_ERROR_COMMUNICATION_FAILED;
	} else {
		if (rsp->cmd != req->cmd) {
			WDC_LOGE("Invalid resp [%d], Original request [%d]", rsp->cmd, req->cmd);
			__WDC_LOG_FUNC_END__;
			return WIFI_DIRECT_ERROR_COMMUNICATION_FAILED;
		}

		if (rsp->result != WIFI_DIRECT_ERROR_NONE) {
			WDC_LOGE("Result received [%s]", __wfd_print_error(rsp->result));
			__WDC_LOG_FUNC_END__;
			return rsp->result;
		}
	}

	__WDC_LOG_FUNC_END__;
	return WIFI_DIRECT_ERROR_NONE;
}

static gboolean __wfd_client_process_event(GIOChannel *source,
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
	int res = 0;

	memset(&client_noti, 0, sizeof(wifi_direct_client_noti_s));

	// 1.Read socket
	res = __wfd_client_read_socket(sockfd, (char*) &client_noti,
								sizeof(wifi_direct_client_noti_s));
	if (res <= 0) {
		WDC_LOGE("Error!!! Reading Async Event[%d]", sockfd);
		__wfd_reset_control();
		__WDC_LOG_FUNC_END__;
		return false;
	}
	WDC_LOGD( "Received Event is [%d,%s], error[%d]", client_noti.event,
					__wfd_print_event(client_noti.event), client_noti.error);

	event = client_noti.event;
	error = client_noti.error;
	memcpy(param1, client_noti.param1, sizeof(client_noti.param1));
	memcpy(param2, client_noti.param2, sizeof(client_noti.param2));


	// 2. dispatch event
	switch (event) {
	case WIFI_DIRECT_CLI_EVENT_ACTIVATION:
	case WIFI_DIRECT_CLI_EVENT_DEACTIVATION:
		if (!client->activation_cb) {
			WDC_LOGE("activation_cb is NULL!!");
			break;
		}
		client->activation_cb(error,
					(wifi_direct_device_state_e) __wfd_convert_client_event(event),
					client->user_data_for_cb_activation);
		break;

	case WIFI_DIRECT_CLI_EVENT_DISCOVER_START:
	case WIFI_DIRECT_CLI_EVENT_DISCOVER_START_LISTEN_ONLY:
	case WIFI_DIRECT_CLI_EVENT_DISCOVER_START_SEARCH_LISTEN:
	case WIFI_DIRECT_CLI_EVENT_DISCOVER_END:
	case WIFI_DIRECT_CLI_EVENT_DISCOVER_FOUND_PEERS:
		if (!client->discover_cb) {
			WDC_LOGE("discover_cb is NULL!!");
			break;
		}
		client->discover_cb(error,
					(wifi_direct_discovery_state_e) __wfd_convert_client_event(event),
					client->user_data_for_cb_discover);
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
	case WIFI_DIRECT_CLI_EVENT_INVITATION_REQ:
		if (!client->connection_cb) {
			WDC_LOGE("connection_cb is NULL!!");
			break;
		}
		client->connection_cb(error,
					(wifi_direct_connection_state_e) __wfd_convert_client_event(event),
					param1, client->user_data_for_cb_connection);
		break;

	// ToDo:  Handling IP lease event...
	case WIFI_DIRECT_CLI_EVENT_IP_LEASED_IND:
		if (!client->ip_assigned_cb) {
			WDC_LOGE("ip_assigned_cb is NULL!!");
			break;
		}
		char *ifname = NULL;
		ifname = vconf_get_str(VCONFKEY_IFNAME);
		if (!ifname) {
			WDC_LOGD("vconf (%s) value is NULL!!!", VCONFKEY_IFNAME);
			break;
		}
		WDC_LOGD("VCONFKEY_IFNAME(%s) : %s", VCONFKEY_IFNAME, ifname);
		client->ip_assigned_cb(param1, param2, ifname,
					client->user_data_for_cb_ip_assigned);
		free(ifname);
		break;

	default:
		break;
	}

	__WDC_LOG_FUNC_END__;

	return TRUE;
}

void __wfd_client_print_entry_list(wfd_discovery_entry_s *list, int num)
{
	int i = 0;

	WDC_LOGD("------------------------------------------");
	for (i = 0; i < num; i++)
	{
		WDC_LOGD("== Peer index : %d ==", i);
		WDC_LOGD("is Group Owner ? %s", list[i].is_group_owner ? "YES" : "NO");
		WDC_LOGD("device_name : %s", list[i].device_name);
		WDC_LOGD("MAC address : "MACSTR, MAC2STR(list[i].mac_address));
		WDC_LOGD("wps cfg method : %x", list[i].wps_cfg_methods);
	}
	WDC_LOGD("------------------------------------------");
}

void __wfd_client_print_connected_peer_info(wfd_connected_peer_info_s *list, int num)
{
	int i = 0;

	WDC_LOGD("------------------------------------------\n");
	for (i = 0; i < num; i++)
	{
		WDC_LOGD("== Peer index : %d ==\n", i);
		WDC_LOGD("device_name : %s\n", list[i].device_name);
		WDC_LOGD("Device MAC : " MACSTR "\n", MAC2STR(list[i].mac_address));
		WDC_LOGD("Interface MAC : " MACSTR "\n", MAC2STR(list[i].intf_address));
		WDC_LOGD("services : %d\n", list[i].services);
		WDC_LOGD("is_p2p : %d\n", list[i].is_p2p);
		WDC_LOGD("category : %d\n", list[i].category);
		WDC_LOGD("channel : %d\n", list[i].channel);
		WDC_LOGD("IP ["IPSTR"]\n", IP2STR(list[i].ip_address));
	}
	WDC_LOGD("------------------------------------------\n");
}

void __wfd_client_print_persistent_group_info(wfd_persistent_group_info_s *list, int num)
{
	int i = 0;

	WDC_LOGD("------------------------------------------\n");
	for (i = 0; i < num; i++)
	{
		WDC_LOGD("== Persistent Group index : %d ==\n", i);
		WDC_LOGD("ssid : %s\n", list[i].ssid);
		WDC_LOGD("GO MAC : " MACSTR "\n",
					   MAC2STR(list[i].go_mac_address));
	}
	WDC_LOGD("------------------------------------------\n");
}

static int __wfd_client_async_event_init(int clientid)
{
	__WDC_LOG_FUNC_START__;
	int sockfd = 0;
	struct sockaddr_un saddr;
	wifi_direct_client_info_s *client_info = __wfd_get_control();
	wifi_direct_client_request_s req;
	int res = 0;

	errno = 0;
	sockfd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (sockfd < 0) {
		WDC_LOGE("Failed to async socket[%s]", strerror(errno));
		__WDC_LOG_FUNC_END__;
		return WIFI_DIRECT_ERROR_COMMUNICATION_FAILED;
	}
	WDC_LOGD("Succeeded to create async socket[%d]", sockfd);

	memset(&saddr, 0, sizeof(saddr));
	saddr.sun_family = AF_UNIX;
	snprintf(saddr.sun_path, sizeof(saddr.sun_path), WFD_SOCK_FILE_PATH);

	WDC_LOGD("Connecting to server socket to register async socket [%d]", sockfd);
	errno = 0;
	res = connect(sockfd, (struct sockaddr *) &saddr, sizeof(saddr));
	if (res < 0) {
		WDC_LOGE("Error!!! connecting to server socket. Error = [%s].", strerror(errno));
		close(sockfd);
		__WDC_LOG_FUNC_END__;
		return WIFI_DIRECT_ERROR_COMMUNICATION_FAILED;
	}

	memset(&req, 0, sizeof(wifi_direct_client_request_s));

	req.cmd = WIFI_DIRECT_CMD_INIT_ASYNC_SOCKET;
	req.client_id = clientid;

	res = __wfd_client_write_socket(sockfd, &req, sizeof(wifi_direct_client_request_s));
	if (res < WIFI_DIRECT_ERROR_NONE) {
		WDC_LOGE("Failed to write to socket[%s]", strerror(errno));
		WDC_LOGE("Error!!! [%s]", __wfd_print_error(res));
		close(sockfd);
		__WDC_LOG_FUNC_END__;
		return res;
	}
	client_info->async_sockfd = sockfd;

	WDC_LOGE("Async socket is created= %d", sockfd);

	return sockfd;
}

static gboolean wfd_client_execute_file(const char *file_path,
	char *const args[], char *const envs[])
{
	pid_t pid = 0;
	int rv = 0;
	errno = 0;
	register unsigned int index = 0;

	while (args[index] != NULL) {
		WDC_LOGD("[%s]", args[index]);
		index++;
	}

	if (!(pid = fork())) {
		WDC_LOGD("pid(%d), ppid(%d)", getpid(), getppid());
		WDC_LOGD("Inside child, exec (%s) command", file_path);

		errno = 0;
		if (execve(file_path, args, envs) == -1) {
			WDC_LOGE("Fail to execute command (%s)", strerror(errno));
			exit(1);
		}
	} else if (pid > 0) {
		if (waitpid(pid, &rv, 0) == -1)
			WDC_LOGD("wait pid (%u) rv (%d)", pid, rv);
		if (WIFEXITED(rv)) {
			WDC_LOGD("exited, rv=%d", WEXITSTATUS(rv));
		} else if (WIFSIGNALED(rv)) {
			WDC_LOGD("killed by signal %d", WTERMSIG(rv));
		} else if (WIFSTOPPED(rv)) {
			WDC_LOGD("stopped by signal %d", WSTOPSIG(rv));
		} else if (WIFCONTINUED(rv)) {
			WDC_LOGD("continued");
		}

		return TRUE;
	}

	WDC_LOGE("failed to fork (%s)", strerror(errno));
	return FALSE;
}

static int __wfd_client_launch_server_dbus(void)
{
	gboolean rv = FALSE;
	const char *path = "/usr/bin/dbus-send";
	char *const args[] = { "/usr/bin/dbus-send", "--system", "--print-reply", "--dest=net.netconfig", "/net/netconfig/wifi", "net.netconfig.wifi.LaunchDirect", NULL };
	char *const envs[] = { NULL };

	rv = wfd_client_execute_file(path, args, envs);

	if (rv != TRUE) {
		WDC_LOGE("Failed to launch wfd-manager");
		return -1;
	}

	WDC_LOGD("Successfully launched wfd-manager");
	return 0;
}

int wifi_direct_initialize(void)
{
	__WDC_LOG_FUNC_START__;
	struct sockaddr_un saddr;
	wifi_direct_client_info_s *client_info = __wfd_get_control();
	wifi_direct_client_request_s req;
	wifi_direct_client_response_s resp;
	int retry_count = 3;
	int sockfd = 0;
	int res = 0;

	if (client_info->is_registered == TRUE) {
		WDC_LOGW("Warning!!! Already registered\nUpdate user data and callback!");
		__WDC_LOG_FUNC_END__;
		return WIFI_DIRECT_ERROR_ALREADY_INITIALIZED;
	}

	errno = 0;
	sockfd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (sockfd < SOCK_FD_MIN) {
		WDC_LOGE("Error!!! creating sync socket[%s]", strerror(errno));
		return WIFI_DIRECT_ERROR_COMMUNICATION_FAILED;
	}
	WDC_LOGD("Created sync socket [%d]", sockfd);

	memset(&saddr, 0, sizeof(saddr));
	saddr.sun_family = AF_UNIX;
	snprintf(saddr.sun_path, sizeof(saddr.sun_path), WFD_SOCK_FILE_PATH);

	WDC_LOGD("Connecting to server socket to register sync socket [%d]", sockfd);
	while (retry_count > 0) {
		errno = 0;
		res = connect(sockfd, (struct sockaddr*) &saddr, sizeof(saddr));
		if (!res){
			WDC_LOGD("Succeeded to connect to server socket");
			break;
		}

		WDC_LOGD("Launching wfd-server..\n");
		res = __wfd_client_launch_server_dbus();
		if (res == -1)
			WDC_LOGE("Failed to send dbus msg[%s]", strerror(errno));
		retry_count--;

		/* wait a little before retrying the next socket connection */
		usleep(100000);
	}

	if (res < 0) {
		WDC_LOGE("Failed to connect to server[%s]", strerror(errno));
		if (sockfd > SOCK_FD_MIN)
			close(sockfd);
		__WDC_LOG_FUNC_END__;
		return WIFI_DIRECT_ERROR_COMMUNICATION_FAILED;
	}

	memset(&req, 0, sizeof(wifi_direct_client_request_s));
	memset(&resp, 0, sizeof(wifi_direct_client_response_s));

	req.cmd = WIFI_DIRECT_CMD_REGISTER;
	req.client_id = gettid();
	WDC_LOGD("Client ID = %d", req.client_id);

	res = __wfd_client_send_request(sockfd, &req, &resp);
	if (res < 0) {
		__WDC_LOG_FUNC_END__;
		return res;
	} else {
		client_info->sync_sockfd = sockfd;
		client_info->client_id = resp.client_id;
		client_info->is_registered = TRUE;
	}

	int async_sockfd = -1;
	async_sockfd = __wfd_client_async_event_init(client_info->client_id);
	if (async_sockfd < 0) {
		WDC_LOGE("Failed to create async socket \n");
		if (sockfd > 0)
			close(sockfd);
		__wfd_reset_control();
		__WDC_LOG_FUNC_END__;
		return WIFI_DIRECT_ERROR_COMMUNICATION_FAILED;
	}
	client_info->async_sockfd = async_sockfd;

	GIOChannel *gio = g_io_channel_unix_new(client_info->async_sockfd);
	int g_source_id = g_io_add_watch(gio, G_IO_IN | G_IO_ERR | G_IO_HUP,
							(GIOFunc) __wfd_client_process_event, NULL);
	g_io_channel_unref(gio);

	client_info->g_source_id = g_source_id;

	// Initialize callbacks
	client_info->activation_cb = NULL;
	client_info->discover_cb = NULL;
	client_info->connection_cb = NULL;
	client_info->ip_assigned_cb = NULL;
	client_info->user_data_for_cb_activation = NULL;
	client_info->user_data_for_cb_discover = NULL;
	client_info->user_data_for_cb_connection = NULL;
	client_info->user_data_for_cb_ip_assigned = NULL;

	__WDC_LOG_FUNC_END__;
	return WIFI_DIRECT_ERROR_NONE;
}

int wifi_direct_deinitialize(void)
{
	__WDC_LOG_FUNC_START__;
	wifi_direct_client_info_s *client_info = __wfd_get_control();

	if (client_info->is_registered == false) {
		WDC_LOGE("Client is already deregistered");
		__WDC_LOG_FUNC_END__;
		return WIFI_DIRECT_ERROR_OPERATION_FAILED;
	}

	client_info->activation_cb = NULL;
	client_info->discover_cb = NULL;
	client_info->connection_cb = NULL;
	client_info->ip_assigned_cb = NULL;
	client_info->user_data_for_cb_activation = NULL;
	client_info->user_data_for_cb_discover = NULL;
	client_info->user_data_for_cb_connection = NULL;
	client_info->user_data_for_cb_ip_assigned = NULL;

	wifi_direct_client_request_s req;
	wifi_direct_client_response_s rsp;
	int res = WIFI_DIRECT_ERROR_NONE;

	memset(&req, 0, sizeof(wifi_direct_client_request_s));
	memset(&rsp, 0, sizeof(wifi_direct_client_response_s));

	req.cmd = WIFI_DIRECT_CMD_DEREGISTER;
	req.client_id = client_info->client_id;

	res = __wfd_client_send_request(client_info->sync_sockfd, &req, &rsp);
	if (res < 0)
		WDC_LOGD("Failed to deinitialize. But continue deinitialization");
	else
		WDC_LOGD("Deinit Successfull");

	__wfd_reset_control();
	__WDC_LOG_FUNC_END__;
	return WIFI_DIRECT_ERROR_NONE;
}


int wifi_direct_set_device_state_changed_cb(wifi_direct_device_state_changed_cb cb,
												void *user_data)
{
	__WDC_LOG_FUNC_START__;
	wifi_direct_client_info_s *client_info = __wfd_get_control();

	if (!cb) {
		WDC_LOGE("Invalid parameter");
		__WDC_LOG_FUNC_END__;
		return WIFI_DIRECT_ERROR_INVALID_PARAMETER;
	}

	if (client_info->is_registered == false) {
		WDC_LOGE("Client is not initialized.");
		__WDC_LOG_FUNC_END__;
		return WIFI_DIRECT_ERROR_NOT_INITIALIZED;
	}

	client_info->activation_cb = cb;
	client_info->user_data_for_cb_activation = user_data;

	__WDC_LOG_FUNC_END__;
	return WIFI_DIRECT_ERROR_NONE;
}


int wifi_direct_unset_device_state_changed_cb(void)
{
	__WDC_LOG_FUNC_START__;
	wifi_direct_client_info_s *client_info = __wfd_get_control();

	if (client_info->is_registered == false) {
		WDC_LOGE("Client is not initialized.\n");
		__WDC_LOG_FUNC_END__;
		return WIFI_DIRECT_ERROR_NOT_INITIALIZED;
	}

	client_info->activation_cb = NULL;
	client_info->user_data_for_cb_activation = NULL;

	__WDC_LOG_FUNC_END__;
	return WIFI_DIRECT_ERROR_NONE;
}


int
wifi_direct_set_discovery_state_changed_cb(wifi_direct_discovery_state_chagned_cb cb,
												void *user_data)
{
	__WDC_LOG_FUNC_START__;
	wifi_direct_client_info_s *client_info = __wfd_get_control();

	if (!cb) {
		WDC_LOGE("Callback is NULL.\n");
		__WDC_LOG_FUNC_END__;
		return WIFI_DIRECT_ERROR_INVALID_PARAMETER;
	}

	if (client_info->is_registered == false) {
		WDC_LOGE("Client is not initialized.\n");
		__WDC_LOG_FUNC_END__;
		return WIFI_DIRECT_ERROR_NOT_INITIALIZED;
	}

	client_info->discover_cb = cb;
	client_info->user_data_for_cb_discover = user_data;

	__WDC_LOG_FUNC_END__;
	return WIFI_DIRECT_ERROR_NONE;
}


int wifi_direct_unset_discovery_state_changed_cb(void)
{
	__WDC_LOG_FUNC_START__;
	wifi_direct_client_info_s *client_info = __wfd_get_control();

	if (client_info->is_registered == false) {
		WDC_LOGE("Client is not initialized.\n");
		__WDC_LOG_FUNC_END__;
		return WIFI_DIRECT_ERROR_NOT_INITIALIZED;
	}

	client_info->discover_cb = NULL;
	client_info->user_data_for_cb_discover = NULL;

	__WDC_LOG_FUNC_END__;
	return WIFI_DIRECT_ERROR_NONE;
}


int wifi_direct_set_connection_state_changed_cb(wifi_direct_connection_state_changed_cb cb,
												void *user_data)
{
	__WDC_LOG_FUNC_START__;
	wifi_direct_client_info_s *client_info = __wfd_get_control();

	if (!cb) {
		WDC_LOGE("Callback is NULL.\n");
		__WDC_LOG_FUNC_END__;
		return WIFI_DIRECT_ERROR_INVALID_PARAMETER;
	}

	if (client_info->is_registered == false) {
		WDC_LOGE("Client is not initialized.\n");
		__WDC_LOG_FUNC_END__;
		return WIFI_DIRECT_ERROR_NOT_INITIALIZED;
	}

	client_info->connection_cb = cb;
	client_info->user_data_for_cb_connection = user_data;

	__WDC_LOG_FUNC_END__;
	return WIFI_DIRECT_ERROR_NONE;
}


int wifi_direct_unset_connection_state_changed_cb(void)
{
	__WDC_LOG_FUNC_START__;
	wifi_direct_client_info_s *client_info = __wfd_get_control();

	if (client_info->is_registered == false) {
		WDC_LOGE("Client is not initialized");
		__WDC_LOG_FUNC_END__;
		return WIFI_DIRECT_ERROR_NOT_INITIALIZED;
	}

	client_info->connection_cb = NULL;
	client_info->user_data_for_cb_connection = NULL;

	__WDC_LOG_FUNC_END__;
	return WIFI_DIRECT_ERROR_NONE;
}


int wifi_direct_set_client_ip_address_assigned_cb(wifi_direct_client_ip_address_assigned_cb cb,
												void* user_data)
{
	__WDC_LOG_FUNC_START__;
	wifi_direct_client_info_s *client_info = __wfd_get_control();

	if (!cb) {
		WDC_LOGE("Callback is NULL");
		__WDC_LOG_FUNC_END__;
		return WIFI_DIRECT_ERROR_INVALID_PARAMETER;
	}

	if (client_info->is_registered == false) {
		WDC_LOGE("Client is not initialized");
		__WDC_LOG_FUNC_END__;
		return WIFI_DIRECT_ERROR_NOT_INITIALIZED;
	}

	client_info->ip_assigned_cb = cb;
	client_info->user_data_for_cb_ip_assigned = user_data;

	__WDC_LOG_FUNC_END__;
	return WIFI_DIRECT_ERROR_NONE;
}

int wifi_direct_unset_client_ip_address_assigned_cb(void)
{
	__WDC_LOG_FUNC_START__;
	wifi_direct_client_info_s *client_info = __wfd_get_control();

	if (client_info->is_registered == false) {
		WDC_LOGE("Client is not initialized");
		__WDC_LOG_FUNC_END__;
		return WIFI_DIRECT_ERROR_NOT_INITIALIZED;
	}

	client_info->ip_assigned_cb = NULL;
	client_info->user_data_for_cb_ip_assigned = NULL;

	__WDC_LOG_FUNC_END__;
	return WIFI_DIRECT_ERROR_NONE;
}


int wifi_direct_activate(void)
{
	__WDC_LOG_FUNC_START__;
	wifi_direct_client_info_s *client_info = __wfd_get_control();
	wifi_direct_client_request_s req;
	wifi_direct_client_response_s rsp;
	int res = WIFI_DIRECT_ERROR_NONE;

	if ((client_info->is_registered == false) ||
			(client_info->client_id == WFD_INVALID_ID)) {
		WDC_LOGE("Client is NOT registered");
		__WDC_LOG_FUNC_END__;
		return WIFI_DIRECT_ERROR_NOT_INITIALIZED;
	}

	memset(&req, 0, sizeof(wifi_direct_client_request_s));
	memset(&rsp, 0, sizeof(wifi_direct_client_response_s));

	req.cmd = WIFI_DIRECT_CMD_ACTIVATE;
	req.client_id = client_info->client_id;

	res = __wfd_client_send_request(client_info->sync_sockfd, &req, &rsp);
	if (res != WIFI_DIRECT_ERROR_NONE) {
		__WDC_LOG_FUNC_END__;
		return res;
	}
	WDC_LOGD("wifi_direct_activate() SUCCESS");

	__WDC_LOG_FUNC_END__;
	return WIFI_DIRECT_ERROR_NONE;
}

int wifi_direct_deactivate(void)
{
	__WDC_LOG_FUNC_START__;
	wifi_direct_client_info_s *client_info = __wfd_get_control();
	wifi_direct_client_request_s req;
	wifi_direct_client_response_s rsp;
	int res = WIFI_DIRECT_ERROR_NONE;

	if ((client_info->is_registered == false) ||
			(client_info->client_id == WFD_INVALID_ID)) {
		WDC_LOGE("Client is NOT registered");
		__WDC_LOG_FUNC_END__;
		return WIFI_DIRECT_ERROR_NOT_INITIALIZED;
	}

	memset(&req, 0, sizeof(wifi_direct_client_request_s));
	memset(&rsp, 0, sizeof(wifi_direct_client_response_s));

	req.cmd = WIFI_DIRECT_CMD_DEACTIVATE;
	req.client_id = client_info->client_id;

	res = __wfd_client_send_request(client_info->sync_sockfd, &req, &rsp);
	if (res != WIFI_DIRECT_ERROR_NONE) {
		__WDC_LOG_FUNC_END__;
		return res;
	}
	WDC_LOGD("wifi_direct_deactivate() SUCCESS");

	__WDC_LOG_FUNC_END__;
	return WIFI_DIRECT_ERROR_NONE;
}

int wifi_direct_start_discovery(bool listen_only, int timeout)
{
	__WDC_LOG_FUNC_START__;
	wifi_direct_client_info_s *client_info = __wfd_get_control();
	wifi_direct_client_request_s req;
	wifi_direct_client_response_s rsp;
	int res = WIFI_DIRECT_ERROR_NONE;

	if ((client_info->is_registered == false) ||
			(client_info->client_id == WFD_INVALID_ID)) {
		WDC_LOGE("Client is NOT registered");
		__WDC_LOG_FUNC_END__;
		return WIFI_DIRECT_ERROR_NOT_INITIALIZED;
	}

	if (timeout < 0) {
		WDC_LOGE("Nagative value. Param [timeout]!");
		__WDC_LOG_FUNC_END__;
		return WIFI_DIRECT_ERROR_INVALID_PARAMETER;
	}

	memset(&req, 0, sizeof(wifi_direct_client_request_s));
	memset(&rsp, 0, sizeof(wifi_direct_client_response_s));

	req.cmd = WIFI_DIRECT_CMD_START_DISCOVERY;
	req.client_id = client_info->client_id;
	req.data.int1 = listen_only;
	req.data.int2 = timeout;
	WDC_LOGE("listen only (%d) timeout (%d)",
				   listen_only, timeout);

	res = __wfd_client_send_request(client_info->sync_sockfd, &req, &rsp);
	if (res != WIFI_DIRECT_ERROR_NONE) {
		__WDC_LOG_FUNC_END__;
		return res;
	}
	WDC_LOGD("wifi_direct_start_discovery() SUCCESS");

	__WDC_LOG_FUNC_END__;
	return WIFI_DIRECT_ERROR_NONE;
}

int wifi_direct_cancel_discovery(void)
{
	__WDC_LOG_FUNC_START__;
	wifi_direct_client_info_s *client_info = __wfd_get_control();
	wifi_direct_client_request_s req;
	wifi_direct_client_response_s rsp;
	int res = WIFI_DIRECT_ERROR_NONE;

	if ((client_info->is_registered == false) ||
			(client_info->client_id == WFD_INVALID_ID)) {
		WDC_LOGE("Client is NOT registered");
		__WDC_LOG_FUNC_END__;
		return WIFI_DIRECT_ERROR_NOT_INITIALIZED;
	}

	memset(&req, 0, sizeof(wifi_direct_client_request_s));
	memset(&rsp, 0, sizeof(wifi_direct_client_response_s));

	req.cmd = WIFI_DIRECT_CMD_CANCEL_DISCOVERY;
	req.client_id = client_info->client_id;

	res = __wfd_client_send_request(client_info->sync_sockfd, &req, &rsp);
	if (res != WIFI_DIRECT_ERROR_NONE) {
		__WDC_LOG_FUNC_END__;
		return res;
	}
	WDC_LOGD("wifi_direct_cancel_discovery() SUCCESS");

	__WDC_LOG_FUNC_END__;
	return WIFI_DIRECT_ERROR_NONE;
}

static int get_service_list(char *services, char** result)
{
	__WDC_LOG_FUNC_START__;
	result = NULL;
	char *pos1 = services;
	char *pos2 = strdup(services);
	unsigned int cnt = 0;
	unsigned int i = 0;
	unsigned int j = 0;

	if (!services ||	(strlen(services) <= 0)) {
		WDC_LOGE("Invalid parameters.");
		__WDC_LOG_FUNC_END__;
		return 0;
	}

	pos1 = strtok (pos1,",\n");
	while (pos1) {
		cnt++;
		pos1 = strtok (NULL, ",\n");
	}
	WDC_LOGD("Total Service Count = %d", cnt);

	if (cnt > 0) {
		result = (char**) calloc(cnt, sizeof(char *));
		if (!result) {
			WDC_LOGE("Failed to allocate memory for result");
			return 0;
		}
		pos1 = pos2;
		pos2 = strtok (pos2,",\n");
		while (pos2 != NULL) {
			char *s = strchr(pos2, ' ');
			if (s) {
				*s = '\0';
				result[i++] = strdup(pos2);
				pos2 = strtok (NULL, ",\n");
			}
		}
	}

	free(pos1);
	if (cnt == i) {
		return cnt;
	} else {
		if (result) {
			for (j=0; j<i && result[j] != NULL; j++)
				free(result[j]);
			free(result);
		}
		return 0;
	}
}

int wifi_direct_foreach_discovered_peers(wifi_direct_discovered_peer_cb cb,
												void *user_data)
{
	__WDC_LOG_FUNC_START__;
	wifi_direct_client_info_s *client_info = __wfd_get_control();
	wifi_direct_client_request_s req;
	wifi_direct_client_response_s rsp;
	int res = WIFI_DIRECT_ERROR_NONE;
	int i;

	if ((client_info->is_registered == false) ||
			(client_info->client_id == WFD_INVALID_ID)) {
		WDC_LOGE("Client is NOT registered");
		__WDC_LOG_FUNC_END__;
		return WIFI_DIRECT_ERROR_NOT_INITIALIZED;
	}

	if (!cb) {
		WDC_LOGE("NULL Param [callback]!");
		__WDC_LOG_FUNC_END__;
		return WIFI_DIRECT_ERROR_INVALID_PARAMETER;
	}

	memset(&req, 0, sizeof(wifi_direct_client_request_s));
	memset(&rsp, 0, sizeof(wifi_direct_client_response_s));

	req.cmd = WIFI_DIRECT_CMD_GET_DISCOVERY_RESULT;
	req.client_id = client_info->client_id;

	pthread_mutex_lock(&g_client_info.mutex);
	res = __wfd_client_write_socket(client_info->sync_sockfd, &req, sizeof(wifi_direct_client_request_s));
	if (res != WIFI_DIRECT_ERROR_NONE) {
		WDC_LOGE("Failed to write into socket [%s]", __wfd_print_error(res));
		__wfd_reset_control();
		pthread_mutex_unlock(&g_client_info.mutex);
		__WDC_LOG_FUNC_END__;
		return WIFI_DIRECT_ERROR_COMMUNICATION_FAILED;
	}
	WDC_LOGD("Succeeded to send request [%d: %s]", req.cmd, __wfd_client_print_cmd(req.cmd));

	res = __wfd_client_read_socket(client_info->sync_sockfd, &rsp, sizeof(wifi_direct_client_response_s));
	if (res <= 0) {
		WDC_LOGE("Failed to read socket [%d]", res);
		__wfd_reset_control();
		pthread_mutex_unlock(&g_client_info.mutex);
		__WDC_LOG_FUNC_END__;
		return WIFI_DIRECT_ERROR_COMMUNICATION_FAILED;
	} else {
		if (rsp.cmd != req.cmd) {
			WDC_LOGE("Invalid resp [%d]", rsp.cmd);
			pthread_mutex_unlock(&g_client_info.mutex);
			__WDC_LOG_FUNC_END__;
			return WIFI_DIRECT_ERROR_COMMUNICATION_FAILED;
		}

		if (rsp.result != WIFI_DIRECT_ERROR_NONE) {
			WDC_LOGE("Result received [%s]", __wfd_print_error(rsp.result));
			pthread_mutex_unlock(&g_client_info.mutex);
			__WDC_LOG_FUNC_END__;
			return rsp.result;
		}
	}

	int num = rsp.param1;
	wfd_discovery_entry_s *buff = NULL;

	WDC_LOGD("Num of found peers = %d", num);

	if (num > 0) {
		buff = (wfd_discovery_entry_s*) calloc(num, sizeof (wfd_discovery_entry_s));
		if (!buff) {
			WDC_LOGE("Failed to alloc memory");
			pthread_mutex_unlock(&g_client_info.mutex);
			return WIFI_DIRECT_ERROR_OPERATION_FAILED;
		}

		res = __wfd_client_read_socket(client_info->sync_sockfd, (char*) buff,
								num * sizeof(wfd_discovery_entry_s));
		pthread_mutex_unlock(&g_client_info.mutex);
		if (res <= 0) {
			free(buff);
			WDC_LOGE("Failed to read socket");
			__wfd_reset_control();
			return WIFI_DIRECT_ERROR_OPERATION_FAILED;
		}

		__wfd_client_print_entry_list(buff, num);
		WDC_LOGD("wifi_direct_foreach_discovered_peers() SUCCESS");

		wifi_direct_discovered_peer_info_s *peer_list;

		for (i = 0; i < num; i++) {
			peer_list = (wifi_direct_discovered_peer_info_s *) calloc(1, sizeof(wifi_direct_discovered_peer_info_s));
			peer_list->device_name = strdup(buff[i].device_name);
			peer_list->mac_address = (char*) calloc(1, MACSTR_LEN);
			snprintf(peer_list->mac_address, MACSTR_LEN, MACSTR, MAC2STR(buff[i].mac_address));
			peer_list->channel = buff[i].channel;
			peer_list->is_connected = buff[i].is_connected;
			peer_list->is_group_owner = buff[i].is_group_owner;
			peer_list->is_persistent_group_owner = buff[i].is_persistent_go;
			peer_list->interface_address = (char*) calloc(1, MACSTR_LEN);
			snprintf(peer_list->interface_address, MACSTR_LEN, MACSTR, MAC2STR(buff[i].intf_address));
			peer_list->supported_wps_types= buff[i].wps_cfg_methods;
			peer_list->service_count = get_service_list(buff[i].services, peer_list->service_list);
			peer_list->primary_device_type = buff[i].category;

			if (!cb(peer_list, user_data))
				break;
		}

		if (buff)
			free(buff);
	} else {
		pthread_mutex_unlock(&g_client_info.mutex);
	}

	__WDC_LOG_FUNC_END__;
	return WIFI_DIRECT_ERROR_NONE;
}

int wifi_direct_connect(const char *mac_address)
{
	__WDC_LOG_FUNC_START__;
	wifi_direct_client_info_s *client_info = __wfd_get_control();
	unsigned char la_mac_addr[6];
	wifi_direct_client_request_s req;
	wifi_direct_client_response_s rsp;
	int res = WIFI_DIRECT_ERROR_NONE;

	if ((client_info->is_registered == false) ||
			(client_info->client_id == WFD_INVALID_ID)) {
		WDC_LOGE("Client is NOT registered");
		__WDC_LOG_FUNC_END__;
		return WIFI_DIRECT_ERROR_NOT_INITIALIZED;
	}

	if (!mac_address) {
		WDC_LOGE("mac_addr is NULL");
		__WDC_LOG_FUNC_END__;
		return WIFI_DIRECT_ERROR_INVALID_PARAMETER;
	}

	memset(&req, 0, sizeof(wifi_direct_client_request_s));
	memset(&rsp, 0, sizeof(wifi_direct_client_response_s));

	req.cmd = WIFI_DIRECT_CMD_CONNECT;
	req.client_id = client_info->client_id;
	macaddr_atoe(mac_address, la_mac_addr);
	memcpy(req.data.mac_addr, la_mac_addr, MACADDR_LEN);

	res = __wfd_client_send_request(client_info->sync_sockfd, &req, &rsp);
	if (res != WIFI_DIRECT_ERROR_NONE) {
		__WDC_LOG_FUNC_END__;
		return res;
	}
	WDC_LOGD("wifi_direct_connect() SUCCESS");

	__WDC_LOG_FUNC_END__;
	return WIFI_DIRECT_ERROR_NONE;
}

int wifi_direct_cancel_connection(const char *mac_address)
{
	__WDC_LOG_FUNC_START__;
	wifi_direct_client_info_s *client_info = __wfd_get_control();
	wifi_direct_client_request_s req;
	wifi_direct_client_response_s rsp;
	int res = WIFI_DIRECT_ERROR_NONE;

	if ((client_info->is_registered == false)
		|| (client_info->client_id == WFD_INVALID_ID))
	{
		WDC_LOGE("Client is NOT registered.");
		__WDC_LOG_FUNC_END__;
		return WIFI_DIRECT_ERROR_NOT_INITIALIZED;
	}

	memset(&req, 0, sizeof(wifi_direct_client_request_s));
	memset(&rsp, 0, sizeof(wifi_direct_client_response_s));

	req.cmd = WIFI_DIRECT_CMD_CANCEL_CONNECTION;
	req.client_id = client_info->client_id;
	macaddr_atoe(mac_address, req.data.mac_addr);

	res = __wfd_client_send_request(client_info->sync_sockfd, &req, &rsp);
	if (res != WIFI_DIRECT_ERROR_NONE) {
		__WDC_LOG_FUNC_END__;
		return res;
	}
	WDC_LOGD("wifi_direct_cancel_connect() SUCCESS");

	__WDC_LOG_FUNC_END__;
	return WIFI_DIRECT_ERROR_NONE;
}


int wifi_direct_reject_connection(const char *mac_address)
{
	__WDC_LOG_FUNC_START__;
	wifi_direct_client_info_s *client_info = __wfd_get_control();
	wifi_direct_client_request_s req;
	wifi_direct_client_response_s rsp;
	int res = WIFI_DIRECT_ERROR_NONE;

	if ((client_info->is_registered == false) ||
			(client_info->client_id == WFD_INVALID_ID)) {
		WDC_LOGE("Client is NOT registered");
		__WDC_LOG_FUNC_END__;
		return WIFI_DIRECT_ERROR_NOT_INITIALIZED;
	}

	if (!mac_address) {
		WDC_LOGE("mac_addr is NULL");
		__WDC_LOG_FUNC_END__;
		return WIFI_DIRECT_ERROR_INVALID_PARAMETER;
	}

	memset(&req, 0, sizeof(wifi_direct_client_request_s));
	memset(&rsp, 0, sizeof(wifi_direct_client_response_s));

	req.cmd = WIFI_DIRECT_CMD_REJECT_CONNECTION;
	req.client_id = client_info->client_id;
	macaddr_atoe(mac_address, req.data.mac_addr);

	res = __wfd_client_send_request(client_info->sync_sockfd, &req, &rsp);
	if (res != WIFI_DIRECT_ERROR_NONE) {
		__WDC_LOG_FUNC_END__;
		return res;
	}
	WDC_LOGE("wifi_direct_reject_connection() SUCCESS");

	__WDC_LOG_FUNC_END__;
	return WIFI_DIRECT_ERROR_NONE;
}


int wifi_direct_disconnect_all(void)
{
	__WDC_LOG_FUNC_START__;
	wifi_direct_client_info_s *client_info = __wfd_get_control();
	wifi_direct_client_request_s req;
	wifi_direct_client_response_s rsp;
	int res = WIFI_DIRECT_ERROR_NONE;

	if ((client_info->is_registered == false) ||
			(client_info->client_id == WFD_INVALID_ID)) {
		WDC_LOGE("Client is NOT registered");
		__WDC_LOG_FUNC_END__;
		return WIFI_DIRECT_ERROR_NOT_INITIALIZED;
	}

	memset(&req, 0, sizeof(wifi_direct_client_request_s));
	memset(&rsp, 0, sizeof(wifi_direct_client_response_s));

	req.cmd = WIFI_DIRECT_CMD_DISCONNECT_ALL;
	req.client_id = client_info->client_id;

	res = __wfd_client_send_request(client_info->sync_sockfd, &req, &rsp);
	if (res != WIFI_DIRECT_ERROR_NONE) {
		__WDC_LOG_FUNC_END__;
		return res;
	}
	WDC_LOGE("wifi_direct_disconnect_all() SUCCESS");

	__WDC_LOG_FUNC_END__;
	return WIFI_DIRECT_ERROR_NONE;
}


int wifi_direct_disconnect(const char *mac_address)
{
	__WDC_LOG_FUNC_START__;
	wifi_direct_client_info_s *client_info = __wfd_get_control();
	unsigned char la_mac_addr[6];
	wifi_direct_client_request_s req;
	wifi_direct_client_response_s rsp;
	int res = WIFI_DIRECT_ERROR_NONE;

	if ((client_info->is_registered == false) ||
			(client_info->client_id == WFD_INVALID_ID)) {
		WDC_LOGE("Client is NOT registered");
		__WDC_LOG_FUNC_END__;
		return WIFI_DIRECT_ERROR_NOT_INITIALIZED;
	}

	if (!mac_address) {
		WDC_LOGE("mac_address is NULL");
		__WDC_LOG_FUNC_END__;
		return WIFI_DIRECT_ERROR_INVALID_PARAMETER;
	}

	memset(&req, 0, sizeof(wifi_direct_client_request_s));
	memset(&rsp, 0, sizeof(wifi_direct_client_response_s));

	req.cmd = WIFI_DIRECT_CMD_DISCONNECT;
	req.client_id = client_info->client_id;
	macaddr_atoe(mac_address, la_mac_addr);
	memcpy(req.data.mac_addr, la_mac_addr, 6);

	res = __wfd_client_send_request(client_info->sync_sockfd, &req, &rsp);
	if (res != WIFI_DIRECT_ERROR_NONE) {
		__WDC_LOG_FUNC_END__;
		return res;
	}
	WDC_LOGE("wifi_direct_disconnect() SUCCESS");

	__WDC_LOG_FUNC_END__;
	return WIFI_DIRECT_ERROR_NONE;

}

int wifi_direct_accept_connection(char *mac_address)
{
	__WDC_LOG_FUNC_START__;
	wifi_direct_client_info_s *client_info = __wfd_get_control();
	unsigned char la_mac_addr[6];
	wifi_direct_client_request_s req;
	wifi_direct_client_response_s rsp;
	int res = WIFI_DIRECT_ERROR_NONE;

	if ((client_info->is_registered == false) ||
			(client_info->client_id == WFD_INVALID_ID)) {
		WDC_LOGE("Client is NOT registered");
		__WDC_LOG_FUNC_END__;
		return WIFI_DIRECT_ERROR_NOT_INITIALIZED;
	}

	if (!mac_address) {
		WDC_LOGE("mac_addr is NULL");
		__WDC_LOG_FUNC_END__;
		return WIFI_DIRECT_ERROR_INVALID_PARAMETER;
	}

	memset(&req, 0, sizeof(wifi_direct_client_request_s));
	memset(&rsp, 0, sizeof(wifi_direct_client_response_s));

	req.cmd = WIFI_DIRECT_CMD_SEND_CONNECT_REQ;
	req.client_id = client_info->client_id;
	macaddr_atoe(mac_address, la_mac_addr);
	memcpy(req.data.mac_addr, la_mac_addr, 6);

	res = __wfd_client_send_request(client_info->sync_sockfd, &req, &rsp);
	if (res != WIFI_DIRECT_ERROR_NONE) {
		__WDC_LOG_FUNC_END__;
		return res;
	}
	WDC_LOGE("wifi_direct_connect() SUCCESS \n");

	__WDC_LOG_FUNC_END__;
	return WIFI_DIRECT_ERROR_NONE;
}


int wifi_direct_foreach_connected_peers(wifi_direct_connected_peer_cb cb,
												void *user_data)
{
	__WDC_LOG_FUNC_START__;
	wifi_direct_client_info_s *client_info = __wfd_get_control();
	wifi_direct_client_request_s req;
	wifi_direct_client_response_s rsp;
	int res = WIFI_DIRECT_ERROR_NONE;
	int i;

	if ((client_info->is_registered == false) ||
			(client_info->client_id == WFD_INVALID_ID)) {
		WDC_LOGE("Client is NOT registered");
		__WDC_LOG_FUNC_END__;
		return WIFI_DIRECT_ERROR_NOT_INITIALIZED;
	}

	if (!cb) {
		WDC_LOGE("NULL Param [callback]!");
		__WDC_LOG_FUNC_END__;
		return WIFI_DIRECT_ERROR_INVALID_PARAMETER;
	}

	memset(&req, 0, sizeof(wifi_direct_client_request_s));
	memset(&rsp, 0, sizeof(wifi_direct_client_response_s));

	req.cmd = WIFI_DIRECT_CMD_GET_CONNECTED_PEERS_INFO;
	req.client_id = client_info->client_id;

	pthread_mutex_lock(&g_client_info.mutex);
	res = __wfd_client_write_socket(client_info->sync_sockfd, &req, sizeof(wifi_direct_client_request_s));
	if (res != WIFI_DIRECT_ERROR_NONE) {
		WDC_LOGE("Failed to write into socket [%s]", __wfd_print_error(res));
		__wfd_reset_control();
		pthread_mutex_unlock(&g_client_info.mutex);
		__WDC_LOG_FUNC_END__;
		return WIFI_DIRECT_ERROR_COMMUNICATION_FAILED;
	}
	WDC_LOGD("Succeeded to send request [%d: %s]", req.cmd, __wfd_client_print_cmd(req.cmd));

	res = __wfd_client_read_socket(client_info->sync_sockfd, &rsp, sizeof(wifi_direct_client_response_s));
	if (res <= 0) {
		WDC_LOGE("Failed to read socket [%d]", res);
		__wfd_reset_control();
		pthread_mutex_unlock(&g_client_info.mutex);
		__WDC_LOG_FUNC_END__;
		return WIFI_DIRECT_ERROR_COMMUNICATION_FAILED;
	} else {
		if (rsp.cmd != req.cmd) {
			WDC_LOGE("Invalid resp [%d]", rsp.cmd);
			pthread_mutex_unlock(&g_client_info.mutex);
			__WDC_LOG_FUNC_END__;
			return WIFI_DIRECT_ERROR_COMMUNICATION_FAILED;
		}

		if (rsp.result != WIFI_DIRECT_ERROR_NONE) {
			WDC_LOGE("Result received [%s]", __wfd_print_error(rsp.result));
			pthread_mutex_unlock(&g_client_info.mutex);
			__WDC_LOG_FUNC_END__;
			return rsp.result;
		}
	}

	int num = rsp.param1;
	wfd_connected_peer_info_s *buff = NULL;

	WDC_LOGD("Num of connected peers = %d", (int) rsp.param1);

	if (num > 0) {
		buff = (wfd_connected_peer_info_s*) calloc(num, sizeof(wfd_connected_peer_info_s));
		if (!buff) {
			WDC_LOGF("malloc() failed!!!");
			pthread_mutex_unlock(&g_client_info.mutex);
			return WIFI_DIRECT_ERROR_OPERATION_FAILED;
		}

		res= __wfd_client_read_socket(client_info->sync_sockfd, (char*) buff,
								num * sizeof(wfd_connected_peer_info_s));
		pthread_mutex_unlock(&g_client_info.mutex);
		if (res <= 0) {
			free(buff);
			WDC_LOGE("socket read error");
			__wfd_reset_control();
			return WIFI_DIRECT_ERROR_OPERATION_FAILED;
		}

		__wfd_client_print_connected_peer_info(buff, num);
		WDC_LOGD("wifi_direct_foreach_connected_peers() SUCCESS");

		wifi_direct_connected_peer_info_s *peer_list = NULL;

		for (i = 0; i < num; i++) {
			peer_list = (wifi_direct_connected_peer_info_s *) calloc(1, sizeof(wifi_direct_connected_peer_info_s));
			peer_list->device_name = strdup(buff[i].device_name);
			peer_list->ip_address= (char*) calloc(1, IPSTR_LEN);
			snprintf(peer_list->ip_address, IPSTR_LEN, IPSTR, IP2STR(buff[i].ip_address));
			peer_list->mac_address = (char*) calloc(1, MACSTR_LEN);
			snprintf(peer_list->mac_address, MACSTR_LEN, MACSTR, MAC2STR(buff[i].mac_address));
			peer_list->interface_address = (char*) calloc(1, MACSTR_LEN);
			snprintf(peer_list->interface_address, MACSTR_LEN, MACSTR, MAC2STR(buff[i].intf_address));
			peer_list->p2p_supported = buff[i].is_p2p;
			peer_list->primary_device_type = buff[i].category;
			peer_list->channel = buff[i].channel;
			peer_list->service_count = get_service_list(buff[i].services, peer_list->service_list);

			if (!cb(peer_list, user_data))
				break;
		}
		if (buff)
			free(buff);
	} else {
		pthread_mutex_unlock(&g_client_info.mutex);
	}

	__WDC_LOG_FUNC_END__;
	return WIFI_DIRECT_ERROR_NONE;
}


int wifi_direct_create_group(void)
{
	__WDC_LOG_FUNC_START__;
	wifi_direct_client_info_s *client_info = __wfd_get_control();
	wifi_direct_client_request_s req;
	wifi_direct_client_response_s rsp;
	int res = WIFI_DIRECT_ERROR_NONE;

	if ((client_info->is_registered == false) ||
			(client_info->client_id == WFD_INVALID_ID)) {
		WDC_LOGE("Client is NOT registered");
		__WDC_LOG_FUNC_END__;
		return WIFI_DIRECT_ERROR_NOT_INITIALIZED;
	}

	memset(&req, 0, sizeof(wifi_direct_client_request_s));
	memset(&rsp, 0, sizeof(wifi_direct_client_response_s));

	req.cmd = WIFI_DIRECT_CMD_CREATE_GROUP;
	req.client_id = client_info->client_id;

	res = __wfd_client_send_request(client_info->sync_sockfd, &req, &rsp);
	if (res != WIFI_DIRECT_ERROR_NONE) {
		__WDC_LOG_FUNC_END__;
		return res;
	}
	WDC_LOGE("wifi_direct_create_group() SUCCESS \n");

	__WDC_LOG_FUNC_END__;
	return WIFI_DIRECT_ERROR_NONE;
}


int wifi_direct_destroy_group(void)
{
	__WDC_LOG_FUNC_START__;
	wifi_direct_client_info_s *client_info = __wfd_get_control();
	wifi_direct_client_request_s req;
	wifi_direct_client_response_s rsp;
	int res = WIFI_DIRECT_ERROR_NONE;

	if ((client_info->is_registered == false) ||
			(client_info->client_id == WFD_INVALID_ID)) {
		WDC_LOGE("Client is NOT registered");
		__WDC_LOG_FUNC_END__;
		return WIFI_DIRECT_ERROR_NOT_INITIALIZED;
	}

	memset(&req, 0, sizeof(wifi_direct_client_request_s));
	memset(&rsp, 0, sizeof(wifi_direct_client_response_s));

	req.cmd = WIFI_DIRECT_CMD_DESTROY_GROUP;
	req.client_id = client_info->client_id;

	res = __wfd_client_send_request(client_info->sync_sockfd, &req, &rsp);
	if (res != WIFI_DIRECT_ERROR_NONE) {
		__WDC_LOG_FUNC_END__;
		return res;
	}
	WDC_LOGE("wifi_direct_destroy_group() SUCCESS");

	__WDC_LOG_FUNC_END__;
	return WIFI_DIRECT_ERROR_NONE;
}


int wifi_direct_is_group_owner(bool *owner)
{
	__WDC_LOG_FUNC_START__;
	wifi_direct_client_info_s *client_info = __wfd_get_control();
	wifi_direct_client_request_s req;
	wifi_direct_client_response_s rsp;
	int res = WIFI_DIRECT_ERROR_NONE;

	if ((client_info->is_registered == false) ||
			(client_info->client_id == WFD_INVALID_ID)) {
		WDC_LOGE("Client is NOT registered");
		__WDC_LOG_FUNC_END__;
		return WIFI_DIRECT_ERROR_NOT_INITIALIZED;
	}

	if (!owner) {
		WDC_LOGE("NULL Param [owner]!");
		__WDC_LOG_FUNC_END__;
		return WIFI_DIRECT_ERROR_INVALID_PARAMETER;
	}

	memset(&req, 0, sizeof(wifi_direct_client_request_s));
	memset(&rsp, 0, sizeof(wifi_direct_client_response_s));

	req.cmd = WIFI_DIRECT_CMD_IS_GROUPOWNER;
	req.client_id = client_info->client_id;

	res = __wfd_client_send_request(client_info->sync_sockfd, &req, &rsp);
	if (res != WIFI_DIRECT_ERROR_NONE) {
		__WDC_LOG_FUNC_END__;
		return res;
	}
	WDC_LOGD("wifi_direct_is_group_owner() SUCCESS");
	*owner = (bool) rsp.param1;

	__WDC_LOG_FUNC_END__;
	return WIFI_DIRECT_ERROR_NONE;
}

int wifi_direct_is_autonomous_group(bool *autonomous_group)
{
	__WDC_LOG_FUNC_START__;
	wifi_direct_client_info_s *client_info = __wfd_get_control();
	wifi_direct_client_request_s req;
	wifi_direct_client_response_s rsp;
	int res = WIFI_DIRECT_ERROR_NONE;

	if ((client_info->is_registered == false) ||
			(client_info->client_id == WFD_INVALID_ID)) {
		WDC_LOGE("Client is NOT registered");
		__WDC_LOG_FUNC_END__;
		return WIFI_DIRECT_ERROR_NOT_INITIALIZED;
	}

	if (!autonomous_group) {
		WDC_LOGE("NULL Param [autonomous_group]!\n");
		__WDC_LOG_FUNC_END__;
		return WIFI_DIRECT_ERROR_INVALID_PARAMETER;
	}

	memset(&req, 0, sizeof(wifi_direct_client_request_s));
	memset(&rsp, 0, sizeof(wifi_direct_client_response_s));

	req.cmd = WIFI_DIRECT_CMD_IS_AUTONOMOUS_GROUP;
	req.client_id = client_info->client_id;

	res = __wfd_client_send_request(client_info->sync_sockfd, &req, &rsp);
	if (res != WIFI_DIRECT_ERROR_NONE) {
		__WDC_LOG_FUNC_END__;
		return res;
	}
	WDC_LOGD("wifi_direct_is_autonomous_group() SUCCESS");
	*autonomous_group = (bool) rsp.param1;

	__WDC_LOG_FUNC_END__;
	return WIFI_DIRECT_ERROR_NONE;
}


int wifi_direct_set_group_owner_intent(int intent)
{
	__WDC_LOG_FUNC_START__;
	wifi_direct_client_info_s *client_info = __wfd_get_control();
	wifi_direct_client_request_s req;
	wifi_direct_client_response_s rsp;
	int res = WIFI_DIRECT_ERROR_NONE;

	if ((client_info->is_registered == false) ||
			(client_info->client_id == WFD_INVALID_ID)) {
		WDC_LOGE("Client is NOT registered");
		__WDC_LOG_FUNC_END__;
		return WIFI_DIRECT_ERROR_NOT_INITIALIZED;
	}

	if (intent < 0 || intent > 15) {
		WDC_LOGE("Invalid Param : intent[%d]", intent);
		__WDC_LOG_FUNC_END__;
		return WIFI_DIRECT_ERROR_INVALID_PARAMETER;
	}

	memset(&req, 0, sizeof(wifi_direct_client_request_s));
	memset(&rsp, 0, sizeof(wifi_direct_client_response_s));

	req.cmd = WIFI_DIRECT_CMD_SET_GO_INTENT;
	req.client_id = client_info->client_id;
	req.data.int1 = intent;

	res = __wfd_client_send_request(client_info->sync_sockfd, &req, &rsp);
	if (res != WIFI_DIRECT_ERROR_NONE) {
		__WDC_LOG_FUNC_END__;
		return res;
	}
	WDC_LOGD("wifi_direct_set_group_owner_intent() SUCCESS");

	__WDC_LOG_FUNC_END__;
	return WIFI_DIRECT_ERROR_NONE;
}

int wifi_direct_get_group_owner_intent(int *intent)
{
	__WDC_LOG_FUNC_START__;
	wifi_direct_client_info_s *client_info = __wfd_get_control();
	wifi_direct_client_request_s req;
	wifi_direct_client_response_s rsp;
	int res = WIFI_DIRECT_ERROR_NONE;

	if ((client_info->is_registered == false) ||
			(client_info->client_id == WFD_INVALID_ID)) {
		WDC_LOGE("Client is NOT registered");
		__WDC_LOG_FUNC_END__;
		return WIFI_DIRECT_ERROR_NOT_INITIALIZED;
	}

	if (!intent) {
		WDC_LOGE("Invalid Parameter");
		__WDC_LOG_FUNC_END__;
		return WIFI_DIRECT_ERROR_INVALID_PARAMETER;
	}

	memset(&req, 0, sizeof(wifi_direct_client_request_s));
	memset(&rsp, 0, sizeof(wifi_direct_client_response_s));

	req.cmd = WIFI_DIRECT_CMD_GET_GO_INTENT;
	req.client_id = client_info->client_id;

	res = __wfd_client_send_request(client_info->sync_sockfd, &req, &rsp);
	if (res != WIFI_DIRECT_ERROR_NONE) {
		__WDC_LOG_FUNC_END__;
		return res;
	}
	WDC_LOGD("int wifi_direct_get_group_owner_intent() intent[%d] SUCCESS", rsp.param1);
	*intent = rsp.param1;

	__WDC_LOG_FUNC_END__;
	return WIFI_DIRECT_ERROR_NONE;
}

int wifi_direct_set_max_clients(int max)
{
	__WDC_LOG_FUNC_START__;
	wifi_direct_client_info_s *client_info = __wfd_get_control();
	wifi_direct_client_request_s req;
	wifi_direct_client_response_s rsp;
	int res = WIFI_DIRECT_ERROR_NONE;

	if ((client_info->is_registered == false) ||
			(client_info->client_id == WFD_INVALID_ID)) {
		WDC_LOGE("Client is NOT registered");
		__WDC_LOG_FUNC_END__;
		return WIFI_DIRECT_ERROR_NOT_INITIALIZED;
	}
	WDC_LOGD("max client [%d]\n", max);

	memset(&req, 0, sizeof(wifi_direct_client_request_s));
	memset(&rsp, 0, sizeof(wifi_direct_client_response_s));

	req.cmd = WIFI_DIRECT_CMD_SET_MAX_CLIENT;
	req.client_id = client_info->client_id;
	req.data.int1 = max;

	res = __wfd_client_send_request(client_info->sync_sockfd, &req, &rsp);
	if (res != WIFI_DIRECT_ERROR_NONE) {
		__WDC_LOG_FUNC_END__;
		return res;
	}
	WDC_LOGD("int wifi_direct_set_max_clients() SUCCESS");

	__WDC_LOG_FUNC_END__;
	return WIFI_DIRECT_ERROR_NONE;
}

int wifi_direct_get_max_clients(int *max)
{
	__WDC_LOG_FUNC_START__;
	wifi_direct_client_info_s *client_info = __wfd_get_control();
	wifi_direct_client_request_s req;
	wifi_direct_client_response_s rsp;
	int res = WIFI_DIRECT_ERROR_NONE;

	if ((client_info->is_registered == false) ||
			(client_info->client_id == WFD_INVALID_ID)) {
		WDC_LOGE("Client is NOT registered");
		__WDC_LOG_FUNC_END__;
		return WIFI_DIRECT_ERROR_NOT_INITIALIZED;
	}

	if (!max) {
		WDC_LOGE("Invalid Parameter");
		__WDC_LOG_FUNC_END__;
		return WIFI_DIRECT_ERROR_INVALID_PARAMETER;
	}

	memset(&req, 0, sizeof(wifi_direct_client_request_s));
	memset(&rsp, 0, sizeof(wifi_direct_client_response_s));

	req.cmd = WIFI_DIRECT_CMD_GET_MAX_CLIENT;
	req.client_id = client_info->client_id;

	res = __wfd_client_send_request(client_info->sync_sockfd, &req, &rsp);
	if (res != WIFI_DIRECT_ERROR_NONE) {
		__WDC_LOG_FUNC_END__;
		return res;
	}
	WDC_LOGD("int wifi_direct_get_max_clients() max_client[%d] SUCCESS", rsp.param1);
	*max = rsp.param1;

	__WDC_LOG_FUNC_END__;
	return WIFI_DIRECT_ERROR_NONE;
}

int wifi_direct_get_operating_channel(int *channel)
{
	__WDC_LOG_FUNC_START__;
	wifi_direct_client_info_s *client_info = __wfd_get_control();
	wifi_direct_client_request_s req;
	wifi_direct_client_response_s rsp;
	int res = WIFI_DIRECT_ERROR_NONE;

	if ((client_info->is_registered == false) ||
			(client_info->client_id == WFD_INVALID_ID)) {
		WDC_LOGE("Client is NOT registered");
		__WDC_LOG_FUNC_END__;
		return WIFI_DIRECT_ERROR_NOT_INITIALIZED;
	}

	if (!channel) {
		WDC_LOGE("NULL Param [channel]!\n");
		__WDC_LOG_FUNC_END__;
		return WIFI_DIRECT_ERROR_INVALID_PARAMETER;
	}

	memset(&req, 0, sizeof(wifi_direct_client_request_s));
	memset(&rsp, 0, sizeof(wifi_direct_client_response_s));

	req.cmd = WIFI_DIRECT_CMD_GET_OPERATING_CHANNEL;
	req.client_id = client_info->client_id;

	res = __wfd_client_send_request(client_info->sync_sockfd, &req, &rsp);
	if (res != WIFI_DIRECT_ERROR_NONE) {
		__WDC_LOG_FUNC_END__;
		return res;
	}
	WDC_LOGD("channel = [%d]", (int) rsp.param1);
	*channel = rsp.param1;

	__WDC_LOG_FUNC_END__;

	return WIFI_DIRECT_ERROR_NONE;

}


int wifi_direct_get_passphrase(char** passphrase)
{
	__WDC_LOG_FUNC_START__;
	wifi_direct_client_info_s *client_info = __wfd_get_control();
	wifi_direct_client_request_s req;
	wifi_direct_client_response_s rsp;
	char la_passphrase[WIFI_DIRECT_WPA_LEN+1] = {0,};
	int res = WIFI_DIRECT_ERROR_NONE;

	if ((client_info->is_registered == false) ||
			(client_info->client_id == WFD_INVALID_ID)) {
		WDC_LOGE("Client is NOT registered.");
		__WDC_LOG_FUNC_END__;
		return WIFI_DIRECT_ERROR_NOT_INITIALIZED;
	}

	if(!passphrase){
		WDC_LOGE("NULL Param [passphrase]!");
		__WDC_LOG_FUNC_END__;
		return WIFI_DIRECT_ERROR_INVALID_PARAMETER;
	}

	memset(&req, 0, sizeof(wifi_direct_client_request_s));
	memset(&rsp, 0, sizeof(wifi_direct_client_response_s));

	req.cmd = WIFI_DIRECT_CMD_GET_PASSPHRASE;
	req.client_id = client_info->client_id;

	res = __wfd_client_send_request(client_info->sync_sockfd, &req, &rsp);
	if (res != WIFI_DIRECT_ERROR_NONE) {
		__WDC_LOG_FUNC_END__;
		return res;
	}

	WDC_LOGD("wifi_direct_get_wpa_passphrase() SUCCESS");
	strncpy(la_passphrase, rsp.param2, WIFI_DIRECT_WPA_LEN);
	la_passphrase[WIFI_DIRECT_WPA_LEN] = '\0';
	*passphrase = strdup(la_passphrase);

	__WDC_LOG_FUNC_END__;
	return WIFI_DIRECT_ERROR_NONE;
}

int wifi_direct_set_wpa_passphrase(char *passphrase)
{
	__WDC_LOG_FUNC_START__;
	wifi_direct_client_info_s *client_info = __wfd_get_control();
	wifi_direct_client_request_s req;
	wifi_direct_client_response_s rsp;
	int status = WIFI_DIRECT_ERROR_NONE;

	if ((client_info->is_registered == false) ||
			(client_info->client_id == WFD_INVALID_ID)) {
		WDC_LOGE("Client is NOT registered.");
		__WDC_LOG_FUNC_END__;
		return WIFI_DIRECT_ERROR_NOT_INITIALIZED;
	}

	if (!passphrase) {
		WDC_LOGE("NULL Param [passphrase]!");
		__WDC_LOG_FUNC_END__;
		return WIFI_DIRECT_ERROR_INVALID_PARAMETER;
	}
	WDC_LOGD("passphrase = [%s]", passphrase);

	memset(&req, 0, sizeof(wifi_direct_client_request_s));
	memset(&rsp, 0, sizeof(wifi_direct_client_response_s));

	req.cmd = WIFI_DIRECT_CMD_SET_WPA;
	req.client_id = client_info->client_id;
	req.cmd_data_len = 64;

	pthread_mutex_lock(&g_client_info.mutex);
	status = __wfd_client_write_socket(client_info->sync_sockfd, &req,
								  sizeof(wifi_direct_client_request_s));
	if (status != WIFI_DIRECT_ERROR_NONE) {
		WDC_LOGE("Error!!! writing to socket[%s]", __wfd_print_error(status));
		__wfd_reset_control();
		pthread_mutex_unlock(&g_client_info.mutex);
		__WDC_LOG_FUNC_END__;
		return WIFI_DIRECT_ERROR_COMMUNICATION_FAILED;
	}
	WDC_LOGD("writing msg hdr is success!");

	status = __wfd_client_write_socket(client_info->sync_sockfd, passphrase, req.cmd_data_len);
	if (status != WIFI_DIRECT_ERROR_NONE) {
		WDC_LOGE("Error!!! writing to socket[%s]", __wfd_print_error(status));
		__wfd_reset_control();
		pthread_mutex_unlock(&g_client_info.mutex);
		__WDC_LOG_FUNC_END__;
		return WIFI_DIRECT_ERROR_COMMUNICATION_FAILED;
	}

	status = __wfd_client_read_socket(client_info->sync_sockfd, (char*) &rsp,
								  sizeof(wifi_direct_client_response_s));
	pthread_mutex_unlock(&g_client_info.mutex);
	if (status <= 0) {
		WDC_LOGE("Error!!! reading socket, status = %d", status);
		__wfd_reset_control();
		__WDC_LOG_FUNC_END__;
		return WIFI_DIRECT_ERROR_COMMUNICATION_FAILED;
	} else {
		if (rsp.cmd == WIFI_DIRECT_CMD_SET_WPA) {
			if (rsp.result != WIFI_DIRECT_ERROR_NONE) {
				WDC_LOGE("Error!!! Result received = %d", rsp.result);
				WDC_LOGE("Error!!! [%s]", __wfd_print_error(rsp.result));
				__WDC_LOG_FUNC_END__;
				return rsp.result;
			}
		} else {
			WDC_LOGE("Error!!! Invalid resp cmd = %d", rsp.cmd);
			return WIFI_DIRECT_ERROR_OPERATION_FAILED;
		}
	}

	__WDC_LOG_FUNC_END__;
	return WIFI_DIRECT_ERROR_NONE;
}

int wifi_direct_activate_pushbutton(void)
{
	__WDC_LOG_FUNC_START__;
	wifi_direct_client_info_s *client_info = __wfd_get_control();
	wifi_direct_client_request_s req;
	wifi_direct_client_response_s rsp;
	int res = WIFI_DIRECT_ERROR_NONE;

	if ((client_info->is_registered == false) ||
			(client_info->client_id == WFD_INVALID_ID)) {
		WDC_LOGE("Client is NOT registered");
		__WDC_LOG_FUNC_END__;
		return WIFI_DIRECT_ERROR_NOT_INITIALIZED;
	}

	memset(&req, 0, sizeof(wifi_direct_client_request_s));
	memset(&rsp, 0, sizeof(wifi_direct_client_response_s));

	req.cmd = WIFI_DIRECT_CMD_ACTIVATE_PUSHBUTTON;
	req.client_id = client_info->client_id;

	res = __wfd_client_send_request(client_info->sync_sockfd, &req, &rsp);
	if (res != WIFI_DIRECT_ERROR_NONE) {
		__WDC_LOG_FUNC_END__;
		return res;
	}
	WDC_LOGD("wifi_direct_activate_pushbutton() SUCCESS");

	__WDC_LOG_FUNC_END__;
	return WIFI_DIRECT_ERROR_NONE;
}

int wifi_direct_set_wps_pin(char *pin)
{
	__WDC_LOG_FUNC_START__;
	wifi_direct_client_info_s *client_info = __wfd_get_control();
	wifi_direct_client_request_s req;
	wifi_direct_client_response_s rsp;
	int status = WIFI_DIRECT_ERROR_NONE;

	if ((client_info->is_registered == false) ||
			(client_info->client_id == WFD_INVALID_ID)) {
		WDC_LOGE("Client is NOT registered");
		__WDC_LOG_FUNC_END__;
		return WIFI_DIRECT_ERROR_NOT_INITIALIZED;
	}

	if (!pin) {
		WDC_LOGE("NULL Param [pin]!");
		__WDC_LOG_FUNC_END__;
		return WIFI_DIRECT_ERROR_INVALID_PARAMETER;
	}
	WDC_LOGE("pin = [%s]\n", pin);

	memset(&req, 0, sizeof(wifi_direct_client_request_s));
	memset(&rsp, 0, sizeof(wifi_direct_client_response_s));

	req.cmd = WIFI_DIRECT_CMD_SET_WPS_PIN;
	req.client_id = client_info->client_id;
	req.cmd_data_len = WIFI_DIRECT_WPS_PIN_LEN+1;

	pthread_mutex_lock(&g_client_info.mutex);
	status = __wfd_client_write_socket(client_info->sync_sockfd, &req,
								  sizeof(wifi_direct_client_request_s));
	if (status != WIFI_DIRECT_ERROR_NONE) {
		WDC_LOGE("Error!!! writing to socket[%s]", __wfd_print_error(status));
		__wfd_reset_control();
		pthread_mutex_unlock(&g_client_info.mutex);
		__WDC_LOG_FUNC_END__;
		return WIFI_DIRECT_ERROR_COMMUNICATION_FAILED;
	}
	WDC_LOGD("writing msg hdr is success!\n");

	status = __wfd_client_write_socket(client_info->sync_sockfd, pin,
								  WIFI_DIRECT_WPS_PIN_LEN);
	if (status != WIFI_DIRECT_ERROR_NONE) {
		WDC_LOGE("Error!!! writing to socket[%s]", __wfd_print_error(status));
		__wfd_reset_control();
		pthread_mutex_unlock(&g_client_info.mutex);
		__WDC_LOG_FUNC_END__;
		return WIFI_DIRECT_ERROR_COMMUNICATION_FAILED;
	}

	status = __wfd_client_read_socket(client_info->sync_sockfd, (char*) &rsp,
								  sizeof(wifi_direct_client_response_s));
	pthread_mutex_unlock(&g_client_info.mutex);
	if (status <= 0) {
		WDC_LOGE("Error!!! reading socket, status = %d", status);
		__wfd_reset_control();
		__WDC_LOG_FUNC_END__;
		return WIFI_DIRECT_ERROR_COMMUNICATION_FAILED;
	} else {
		if (rsp.cmd == WIFI_DIRECT_CMD_SET_WPS_PIN) {
			if (rsp.result != WIFI_DIRECT_ERROR_NONE) {
				WDC_LOGD("Error!!! Result received = %d", rsp.result);
				WDC_LOGD("Error!!! [%s]", __wfd_print_error(rsp.result));
				__WDC_LOG_FUNC_END__;
				return rsp.result;
			}
		} else {
			WDC_LOGE("Error!!! Invalid resp cmd = %d", rsp.cmd);
			__WDC_LOG_FUNC_END__;
			return WIFI_DIRECT_ERROR_OPERATION_FAILED;
		}
	}

	__WDC_LOG_FUNC_END__;
	return WIFI_DIRECT_ERROR_NONE;
}


int wifi_direct_get_wps_pin(char **pin)
{
	__WDC_LOG_FUNC_START__;
	wifi_direct_client_info_s *client_info = __wfd_get_control();
	wifi_direct_client_request_s req;
	wifi_direct_client_response_s rsp;
	char la_pin[WIFI_DIRECT_WPS_PIN_LEN + 1] = { 0, };
	int res = WIFI_DIRECT_ERROR_NONE;

	if ((client_info->is_registered == false) ||
			(client_info->client_id == WFD_INVALID_ID)) {
		WDC_LOGE("Client is NOT registered");
		__WDC_LOG_FUNC_END__;
		return WIFI_DIRECT_ERROR_NOT_INITIALIZED;
	}

	memset(&req, 0, sizeof(wifi_direct_client_request_s));
	memset(&rsp, 0, sizeof(wifi_direct_client_response_s));

	req.cmd = WIFI_DIRECT_CMD_GET_WPS_PIN;
	req.client_id = client_info->client_id;

	res = __wfd_client_send_request(client_info->sync_sockfd, &req, &rsp);
	if (res != WIFI_DIRECT_ERROR_NONE) {
		__WDC_LOG_FUNC_END__;
		return res;
	}
	WDC_LOGD("wifi_direct_get_wps_pin() SUCCESS");
	strncpy(la_pin, rsp.param2, WIFI_DIRECT_WPS_PIN_LEN);
	la_pin[WIFI_DIRECT_WPS_PIN_LEN] = '\0';
	*pin = strdup(la_pin);

	__WDC_LOG_FUNC_END__;
	return WIFI_DIRECT_ERROR_NONE;
}

int wifi_direct_generate_wps_pin(void)
{
	__WDC_LOG_FUNC_START__;
	wifi_direct_client_info_s *client_info = __wfd_get_control();
	wifi_direct_client_request_s req;
	wifi_direct_client_response_s rsp;
	int res = WIFI_DIRECT_ERROR_NONE;

	if ((client_info->is_registered == false) ||
			(client_info->client_id == WFD_INVALID_ID)) {
		WDC_LOGE("Client is NOT registered");
		__WDC_LOG_FUNC_END__;
		return WIFI_DIRECT_ERROR_NOT_INITIALIZED;
	}

	memset(&req, 0, sizeof(wifi_direct_client_request_s));
	memset(&rsp, 0, sizeof(wifi_direct_client_response_s));

	req.cmd = WIFI_DIRECT_CMD_GENERATE_WPS_PIN;
	req.client_id = client_info->client_id;

	res = __wfd_client_send_request(client_info->sync_sockfd, &req, &rsp);
	if (res != WIFI_DIRECT_ERROR_NONE) {
		__WDC_LOG_FUNC_END__;
		return res;
	}
	WDC_LOGD("wifi_direct_generate_wps_pin() SUCCESS");

	__WDC_LOG_FUNC_END__;
	return WIFI_DIRECT_ERROR_NONE;
}


int wifi_direct_get_supported_wps_mode(int *wps_mode)
{
	__WDC_LOG_FUNC_START__;
	wifi_direct_client_info_s *client_info = __wfd_get_control();
	wifi_direct_client_request_s req;
	wifi_direct_client_response_s rsp;
	int res = WIFI_DIRECT_ERROR_NONE;

	if ((client_info->is_registered == false) ||
			(client_info->client_id == WFD_INVALID_ID)) {
		WDC_LOGE("Client is NOT registered");
		__WDC_LOG_FUNC_END__;
		return WIFI_DIRECT_ERROR_NOT_INITIALIZED;
	}

	memset(&req, 0, sizeof(wifi_direct_client_request_s));
	memset(&rsp, 0, sizeof(wifi_direct_client_response_s));

	req.cmd = WIFI_DIRECT_CMD_GET_SUPPORTED_WPS_MODE;
	req.client_id = client_info->client_id;

	res = __wfd_client_send_request(client_info->sync_sockfd, &req, &rsp);
	if (res != WIFI_DIRECT_ERROR_NONE) {
		__WDC_LOG_FUNC_END__;
		return res;
	}
	WDC_LOGD("Supported wps config = [%d]", (int) rsp.param1);
	*wps_mode = rsp.param1;

	__WDC_LOG_FUNC_END__;
	return WIFI_DIRECT_ERROR_NONE;
}

int wifi_direct_foreach_supported_wps_types(wifi_direct_supported_wps_type_cb cb, void* user_data)
{
	__WDC_LOG_FUNC_START__;
	wifi_direct_client_info_s *client_info = __wfd_get_control();
	wifi_direct_client_request_s req;
	wifi_direct_client_response_s rsp;
	int res = WIFI_DIRECT_ERROR_NONE;

	if ((client_info->is_registered == false) ||
			(client_info->client_id == WFD_INVALID_ID)) {
		WDC_LOGE("Client is NOT registered");
		__WDC_LOG_FUNC_END__;
		return WIFI_DIRECT_ERROR_NOT_INITIALIZED;
	}

	if (!cb) {
		WDC_LOGE("NULL Param [callback]!");
		__WDC_LOG_FUNC_END__;
		return WIFI_DIRECT_ERROR_INVALID_PARAMETER;
	}

	memset(&req, 0, sizeof(wifi_direct_client_request_s));
	memset(&rsp, 0, sizeof(wifi_direct_client_response_s));

	req.cmd = WIFI_DIRECT_CMD_GET_SUPPORTED_WPS_MODE;
	req.client_id = client_info->client_id;

	res = __wfd_client_send_request(client_info->sync_sockfd, &req, &rsp);
	if (res != WIFI_DIRECT_ERROR_NONE) {
		__WDC_LOG_FUNC_END__;
		return res;
	}
	WDC_LOGD("Supported wps config = [%d]", (int) rsp.param1);

	int wps_mode;
	bool result = TRUE;

	wps_mode = rsp.param1;
	if (wps_mode & WIFI_DIRECT_WPS_TYPE_PBC)
		result = cb(WIFI_DIRECT_WPS_TYPE_PBC, user_data);
	if ((result == true) && (wps_mode & WIFI_DIRECT_WPS_TYPE_PIN_DISPLAY))
		result = cb(WIFI_DIRECT_WPS_TYPE_PIN_DISPLAY, user_data);
	if ((result == true) && (wps_mode & WIFI_DIRECT_WPS_TYPE_PIN_KEYPAD))
		result = cb(WIFI_DIRECT_WPS_TYPE_PIN_KEYPAD, user_data);

	__WDC_LOG_FUNC_END__;
	return WIFI_DIRECT_ERROR_NONE;
}

int wifi_direct_get_local_wps_type(wifi_direct_wps_type_e *type)
{
	__WDC_LOG_FUNC_START__;
	wifi_direct_client_info_s *client_info = __wfd_get_control();
	wifi_direct_client_request_s req;
	wifi_direct_client_response_s rsp;
	int res = WIFI_DIRECT_ERROR_NONE;

	if ((client_info->is_registered == false) ||
			(client_info->client_id == WFD_INVALID_ID)) {
		WDC_LOGE("Client is NOT registered");
		__WDC_LOG_FUNC_END__;
		return WIFI_DIRECT_ERROR_NOT_INITIALIZED;
	}

	if (type == NULL) {
		WDC_LOGE("NULL Param [type]!\n");
		__WDC_LOG_FUNC_END__;
		return WIFI_DIRECT_ERROR_INVALID_PARAMETER;
	}

	memset(&req, 0, sizeof(wifi_direct_client_request_s));
	memset(&rsp, 0, sizeof(wifi_direct_client_response_s));

	req.cmd = WIFI_DIRECT_CMD_GET_LOCAL_WPS_MODE;
	req.client_id = client_info->client_id;

	res = __wfd_client_send_request(client_info->sync_sockfd, &req, &rsp);
	if (res != WIFI_DIRECT_ERROR_NONE) {
		__WDC_LOG_FUNC_END__;
		return res;
	}
	WDC_LOGD("wifi_direct_get_wps_type() SUCCESS");
	*type = rsp.param1;

	__WDC_LOG_FUNC_END__;
	return WIFI_DIRECT_ERROR_NONE;
}

int wifi_direct_set_req_wps_type(wifi_direct_wps_type_e type)
{
	__WDC_LOG_FUNC_START__;
	wifi_direct_client_info_s *client_info = __wfd_get_control();
	wifi_direct_client_request_s req;
	wifi_direct_client_response_s rsp;
	int res = WIFI_DIRECT_ERROR_NONE;

	if ((client_info->is_registered == false) ||
			(client_info->client_id == WFD_INVALID_ID)) {
		WDC_LOGE("Client is NOT registered");
		__WDC_LOG_FUNC_END__;
		return WIFI_DIRECT_ERROR_NOT_INITIALIZED;
	}

	if (type == WIFI_DIRECT_WPS_TYPE_PBC ||
			type == WIFI_DIRECT_WPS_TYPE_PIN_DISPLAY ||
			type == WIFI_DIRECT_WPS_TYPE_PIN_KEYPAD) {
		WDC_LOGD("Param wps_mode [%d]", type);
	} else {
		WDC_LOGE("Invalid Param [wps_mode]!");
		__WDC_LOG_FUNC_END__;
		return WIFI_DIRECT_ERROR_INVALID_PARAMETER;
	}

	memset(&req, 0, sizeof(wifi_direct_client_request_s));
	memset(&rsp, 0, sizeof(wifi_direct_client_response_s));

	req.cmd = WIFI_DIRECT_CMD_SET_REQ_WPS_MODE;
	req.client_id = client_info->client_id;
	req.data.int1 = type;

	res = __wfd_client_send_request(client_info->sync_sockfd, &req, &rsp);
	if (res != WIFI_DIRECT_ERROR_NONE) {
		__WDC_LOG_FUNC_END__;
		return res;
	}
	WDC_LOGD("wifi_direct_set_req_wps_type() SUCCESS");

	__WDC_LOG_FUNC_END__;
	return WIFI_DIRECT_ERROR_NONE;
}

int wifi_direct_get_req_wps_type(wifi_direct_wps_type_e *type)
{
	__WDC_LOG_FUNC_START__;
	wifi_direct_client_info_s *client_info = __wfd_get_control();
	wifi_direct_client_request_s req;
	wifi_direct_client_response_s rsp;
	int res = WIFI_DIRECT_ERROR_NONE;

	if ((client_info->is_registered == false) ||
			(client_info->client_id == WFD_INVALID_ID)) {
		WDC_LOGE("Client is NOT registered");
		__WDC_LOG_FUNC_END__;
		return WIFI_DIRECT_ERROR_NOT_INITIALIZED;
	}

	if (type == NULL) {
		WDC_LOGE("NULL Param [type]!\n");
		__WDC_LOG_FUNC_END__;
		return WIFI_DIRECT_ERROR_INVALID_PARAMETER;
	}

	memset(&req, 0, sizeof(wifi_direct_client_request_s));
	memset(&rsp, 0, sizeof(wifi_direct_client_response_s));

	req.cmd = WIFI_DIRECT_CMD_GET_REQ_WPS_MODE;
	req.client_id = client_info->client_id;

	res = __wfd_client_send_request(client_info->sync_sockfd, &req, &rsp);
	if (res != WIFI_DIRECT_ERROR_NONE) {
		__WDC_LOG_FUNC_END__;
		return res;
	}
	WDC_LOGD("wifi_direct_get_req_wps_type() SUCCESS");
	*type = rsp.param1;

	__WDC_LOG_FUNC_END__;
	return WIFI_DIRECT_ERROR_NONE;
}

/* DPRECATED */
int wifi_direct_set_ssid(const char *ssid)
{
	__WDC_LOG_FUNC_START__;
	wifi_direct_client_info_s *client_info = __wfd_get_control();
	wifi_direct_client_request_s req;
	wifi_direct_client_response_s rsp;
	int res = WIFI_DIRECT_ERROR_NONE;

	if ((client_info->is_registered == false) ||
			(client_info->client_id == WFD_INVALID_ID)) {
		WDC_LOGE("Client is NOT registered");
		__WDC_LOG_FUNC_END__;
		return WIFI_DIRECT_ERROR_NOT_INITIALIZED;
	}

	if (!ssid) {
		WDC_LOGE("NULL Param [ssid]!");
		__WDC_LOG_FUNC_END__;
		return WIFI_DIRECT_ERROR_INVALID_PARAMETER;
	}
	WDC_LOGE("ssid = [%s]", ssid);

	memset(&req, 0, sizeof(wifi_direct_client_request_s));
	memset(&rsp, 0, sizeof(wifi_direct_client_response_s));

	req.cmd = WIFI_DIRECT_CMD_SET_SSID;
	req.client_id = client_info->client_id;

	pthread_mutex_lock(&g_client_info.mutex);
	res = __wfd_client_write_socket(client_info->sync_sockfd, &req,
								  sizeof(wifi_direct_client_request_s));
	if (res != WIFI_DIRECT_ERROR_NONE) {
		WDC_LOGE("Error!!! writing to socket[%s]", __wfd_print_error(res));
		__wfd_reset_control();
		pthread_mutex_unlock(&g_client_info.mutex);
		__WDC_LOG_FUNC_END__;
		return WIFI_DIRECT_ERROR_COMMUNICATION_FAILED;
	}
	WDC_LOGD("writing msg hdr is success!");

	res = __wfd_client_write_socket(client_info->sync_sockfd, (void*) ssid,
								  WIFI_DIRECT_MAX_SSID_LEN);
	if (res != WIFI_DIRECT_ERROR_NONE) {
		WDC_LOGE("Error!!! writing to socket[%s]", __wfd_print_error(res));
		__wfd_reset_control();
		pthread_mutex_unlock(&g_client_info.mutex);
		__WDC_LOG_FUNC_END__;
		return WIFI_DIRECT_ERROR_COMMUNICATION_FAILED;
	}

	res = __wfd_client_read_socket(client_info->sync_sockfd, (char*) &rsp,
								  sizeof(wifi_direct_client_response_s));
	pthread_mutex_unlock(&g_client_info.mutex);
	if (res <= 0) {
		WDC_LOGE("Error!!! reading socket, status = %d", res);
		__wfd_reset_control();
		__WDC_LOG_FUNC_END__;
		return WIFI_DIRECT_ERROR_COMMUNICATION_FAILED;
	} else {
		if (rsp.cmd == WIFI_DIRECT_CMD_SET_SSID) {
			if (rsp.result != WIFI_DIRECT_ERROR_NONE) {
				WDC_LOGE("Error!!! Result received = %d", rsp.result);
				WDC_LOGE("Error!!! [%s]", __wfd_print_error(rsp.result));
				__WDC_LOG_FUNC_END__;
				return rsp.result;
			}
		} else {
			WDC_LOGE("Error!!! Invalid resp cmd = %d\n", rsp.cmd);
			return WIFI_DIRECT_ERROR_OPERATION_FAILED;
		}
	}

	__WDC_LOG_FUNC_END__;
	return WIFI_DIRECT_ERROR_NONE;
}

int wifi_direct_get_ssid(char **ssid)
{
	__WDC_LOG_FUNC_START__;
	wifi_direct_client_info_s *client_info = __wfd_get_control();
	wifi_direct_client_request_s req;
	wifi_direct_client_response_s rsp;
	char la_ssid[WIFI_DIRECT_MAX_SSID_LEN + 1] = { 0, };
	int res = WIFI_DIRECT_ERROR_NONE;

	if ((client_info->is_registered == false) ||
			(client_info->client_id == WFD_INVALID_ID)) {
		WDC_LOGE("Client is NOT registered");
		__WDC_LOG_FUNC_END__;
		return WIFI_DIRECT_ERROR_NOT_INITIALIZED;
	}

	if (!ssid) {
		WDC_LOGE("NULL Param [ssid]!");
		__WDC_LOG_FUNC_END__;
		return WIFI_DIRECT_ERROR_INVALID_PARAMETER;
	}

	memset(&req, 0, sizeof(wifi_direct_client_request_s));
	memset(&rsp, 0, sizeof(wifi_direct_client_response_s));

	req.cmd = WIFI_DIRECT_CMD_GET_SSID;
	req.client_id = client_info->client_id;

	res = __wfd_client_send_request(client_info->sync_sockfd, &req, &rsp);
	if (res != WIFI_DIRECT_ERROR_NONE) {
		__WDC_LOG_FUNC_END__;
		return res;
	}
	WDC_LOGD("wifi_direct_get_ssid() %s SUCCESS", rsp.param2);
	strncpy(la_ssid, rsp.param2, WIFI_DIRECT_MAX_SSID_LEN);
	la_ssid[WIFI_DIRECT_MAX_SSID_LEN] = '\0';
	*ssid = strdup(la_ssid);

	__WDC_LOG_FUNC_END__;
	return WIFI_DIRECT_ERROR_NONE;
}

int wifi_direct_get_device_name(char **device_name)
{
	__WDC_LOG_FUNC_START__;
	wifi_direct_client_info_s *client_info = __wfd_get_control();
	wifi_direct_client_request_s req;
	wifi_direct_client_response_s rsp;
	char la_device_name[WIFI_DIRECT_MAX_DEVICE_NAME_LEN + 1] = { 0, };
	int res = WIFI_DIRECT_ERROR_NONE;

	if ((client_info->is_registered == false) ||
			(client_info->client_id == WFD_INVALID_ID)) {
		WDC_LOGE("Client is NOT registered");
		__WDC_LOG_FUNC_END__;
		return WIFI_DIRECT_ERROR_NOT_INITIALIZED;
	}

	if (!device_name) {
		WDC_LOGE("NULL Param [device_name]!");
		__WDC_LOG_FUNC_END__;
		return WIFI_DIRECT_ERROR_INVALID_PARAMETER;
	}

	memset(&req, 0, sizeof(wifi_direct_client_request_s));
	memset(&rsp, 0, sizeof(wifi_direct_client_response_s));

	req.cmd = WIFI_DIRECT_CMD_GET_DEVICE_NAME;
	req.client_id = client_info->client_id;

	res = __wfd_client_send_request(client_info->sync_sockfd, &req, &rsp);
	if (res != WIFI_DIRECT_ERROR_NONE) {
		__WDC_LOG_FUNC_END__;
		return res;
	}
	WDC_LOGD("wifi_direct_get_device_name() %s SUCCESS \n", rsp.param2);
	strncpy(la_device_name, rsp.param2, WIFI_DIRECT_MAX_DEVICE_NAME_LEN);
	la_device_name[WIFI_DIRECT_MAX_DEVICE_NAME_LEN] = '\0';
	*device_name = strdup(la_device_name);

	__WDC_LOG_FUNC_END__;
	return WIFI_DIRECT_ERROR_NONE;
}

int wifi_direct_set_device_name(const char *device_name)
{
	__WDC_LOG_FUNC_START__;
	wifi_direct_client_info_s *client_info = __wfd_get_control();
	wifi_direct_client_request_s req;
	wifi_direct_client_response_s rsp;
	int status = WIFI_DIRECT_ERROR_NONE;

	if ((client_info->is_registered == false) ||
			(client_info->client_id == WFD_INVALID_ID)) {
		WDC_LOGE("Client is NOT registered");
		__WDC_LOG_FUNC_END__;
		return WIFI_DIRECT_ERROR_NOT_INITIALIZED;
	}

	if (!device_name) {
		WDC_LOGE("NULL Param [device_name]!");
		__WDC_LOG_FUNC_END__;
		return WIFI_DIRECT_ERROR_INVALID_PARAMETER;
	}
	WDC_LOGE("device_name = [%s]", device_name);

	memset(&req, 0, sizeof(wifi_direct_client_request_s));
	memset(&rsp, 0, sizeof(wifi_direct_client_response_s));

	req.cmd = WIFI_DIRECT_CMD_SET_DEVICE_NAME;
	req.client_id = client_info->client_id;

	pthread_mutex_lock(&g_client_info.mutex);
	status = __wfd_client_write_socket(client_info->sync_sockfd, &req,
								  sizeof(wifi_direct_client_request_s));
	if (status != WIFI_DIRECT_ERROR_NONE) {
		WDC_LOGE("Error!!! writing to socket[%s]", __wfd_print_error(status));
		__wfd_reset_control();
		pthread_mutex_unlock(&g_client_info.mutex);
		__WDC_LOG_FUNC_END__;
		return WIFI_DIRECT_ERROR_COMMUNICATION_FAILED;
	}
	WDC_LOGD( "writing msg hdr is success!\n");

	status = __wfd_client_write_socket(client_info->sync_sockfd, (void*) device_name,
								  WIFI_DIRECT_MAX_DEVICE_NAME_LEN);
	if (status != WIFI_DIRECT_ERROR_NONE) {
		WDC_LOGE("Error!!! writing to socket[%s]", __wfd_print_error(status));
		__wfd_reset_control();
		pthread_mutex_unlock(&g_client_info.mutex);
		__WDC_LOG_FUNC_END__;
		return WIFI_DIRECT_ERROR_COMMUNICATION_FAILED;
	}

	status = __wfd_client_read_socket(client_info->sync_sockfd, (char*) &rsp,
								  sizeof(wifi_direct_client_response_s));
	pthread_mutex_unlock(&g_client_info.mutex);
	if (status <= 0) {
		WDC_LOGE("Error!!! reading socket, status = %d", status);
		__wfd_reset_control();
		__WDC_LOG_FUNC_END__;
		return WIFI_DIRECT_ERROR_COMMUNICATION_FAILED;
	} else {
		if (rsp.cmd == WIFI_DIRECT_CMD_SET_DEVICE_NAME) {
			if (rsp.result != WIFI_DIRECT_ERROR_NONE) {
				WDC_LOGE("Error!!! Result received = %d", rsp.result);
				WDC_LOGE("Error!!! [%s]", __wfd_print_error(rsp.result));
				__WDC_LOG_FUNC_END__;
				return rsp.result;
			}
		} else {
			WDC_LOGE("Error!!! Invalid resp cmd = %d", rsp.cmd);
			return WIFI_DIRECT_ERROR_OPERATION_FAILED;
		}
	}

	__WDC_LOG_FUNC_END__;
	return WIFI_DIRECT_ERROR_NONE;
}

int wifi_direct_get_network_interface_name(char **name)
{
	__WDC_LOG_FUNC_START__;
	wifi_direct_client_info_s *client_info = __wfd_get_control();
	wifi_direct_state_e status = 0;
	char *get_str = NULL;
	int result;

	if ((client_info->is_registered == false) ||
			(client_info->client_id == WFD_INVALID_ID)) {
		WDC_LOGE("Client is NOT registered");
		__WDC_LOG_FUNC_END__;
		return WIFI_DIRECT_ERROR_NOT_INITIALIZED;
	}

	if (!name) {
		WDC_LOGE("NULL Param [name]!\n");
		__WDC_LOG_FUNC_END__;
		return WIFI_DIRECT_ERROR_INVALID_PARAMETER;
	}

	result = wifi_direct_get_state(&status);
	WDC_LOGD("wifi_direct_get_state() state=[%d], result=[%d]\n", status, result);

	if (status < WIFI_DIRECT_STATE_CONNECTED) {
		WDC_LOGE("Device is not connected!\n");
		__WDC_LOG_FUNC_END__;
		return WIFI_DIRECT_ERROR_NOT_PERMITTED;
	}

	get_str = vconf_get_str(VCONFKEY_IFNAME);
	if (!get_str) {
		WDC_LOGD( "vconf (%s) value is NULL!!!\n", VCONFKEY_IFNAME);
		__WDC_LOG_FUNC_END__;
		return WIFI_DIRECT_ERROR_NOT_PERMITTED;
	}
	WDC_LOGD( "VCONFKEY_IFNAME(%s) : %s\n", VCONFKEY_IFNAME, get_str);
	*name = strdup(get_str);
	free(get_str);

	__WDC_LOG_FUNC_END__;
	return WIFI_DIRECT_ERROR_NONE;
}

int wifi_direct_get_ip_address(char **ip_address)
{
	__WDC_LOG_FUNC_START__;
	wifi_direct_client_info_s *client_info = __wfd_get_control();
	wifi_direct_state_e state = 0;
	char *get_str = NULL;
	int result;

	if ((client_info->is_registered == false) ||
			(client_info->client_id == WFD_INVALID_ID)) {
		WDC_LOGE("Client is NOT registered");
		__WDC_LOG_FUNC_END__;
		return WIFI_DIRECT_ERROR_NOT_INITIALIZED;
	}

	if (!ip_address) {
		WDC_LOGE("NULL Param [ip_address]!\n");
		__WDC_LOG_FUNC_END__;
		return WIFI_DIRECT_ERROR_INVALID_PARAMETER;
	}

	result = wifi_direct_get_state(&state);
	WDC_LOGD( "wifi_direct_get_state() state=[%d], result=[%d]", state, result);
	if( state < WIFI_DIRECT_STATE_CONNECTED) {
		WDC_LOGE("Device is not connected!");
		__WDC_LOG_FUNC_END__;
		return WIFI_DIRECT_ERROR_NOT_PERMITTED;
	}

	get_str = vconf_get_str(VCONFKEY_LOCAL_IP);
	if (!get_str)
	{
		WDC_LOGD("vconf (%s) value is NULL!!!", VCONFKEY_LOCAL_IP);
		__WDC_LOG_FUNC_END__;
		return WIFI_DIRECT_ERROR_NOT_PERMITTED;
	}
	WDC_LOGD("VCONFKEY_LOCAL_IP(%s) : %s", VCONFKEY_LOCAL_IP, get_str);
	*ip_address = strdup(get_str);
	free(get_str);

	__WDC_LOG_FUNC_END__;
	return WIFI_DIRECT_ERROR_NONE;
}

int wifi_direct_get_subnet_mask(char **subnet_mask)
{
	__WDC_LOG_FUNC_START__;
	wifi_direct_client_info_s *client_info = __wfd_get_control();
	wifi_direct_state_e status = 0;
	char *get_str = NULL;
	int result;

	if ((client_info->is_registered == false) ||
			(client_info->client_id == WFD_INVALID_ID)) {
		WDC_LOGE("Client is NOT registered");
		__WDC_LOG_FUNC_END__;
		return WIFI_DIRECT_ERROR_NOT_INITIALIZED;
	}

	if (!subnet_mask) {
		WDC_LOGE("NULL Param [subnet_mask]!");
		__WDC_LOG_FUNC_END__;
		return WIFI_DIRECT_ERROR_INVALID_PARAMETER;
	}

	result = wifi_direct_get_state(&status);
	WDC_LOGD("wifi_direct_get_state() state=[%d], result=[%d]", status, result);
	if( status < WIFI_DIRECT_STATE_CONNECTED) {
		WDC_LOGE("Device is not connected!");
		__WDC_LOG_FUNC_END__;
		return WIFI_DIRECT_ERROR_NOT_PERMITTED;
	}

	get_str = vconf_get_str(VCONFKEY_SUBNET_MASK);
	if (!get_str) {
		WDC_LOGD("vconf (%s) value is NULL!!!", VCONFKEY_SUBNET_MASK);
		__WDC_LOG_FUNC_END__;
		return WIFI_DIRECT_ERROR_NOT_PERMITTED;
	}
	WDC_LOGD("VCONFKEY_SUBNET_MASK(%s) : %s", VCONFKEY_SUBNET_MASK, get_str);
	*subnet_mask = strdup(get_str);
	free(get_str);

	__WDC_LOG_FUNC_END__;
	return WIFI_DIRECT_ERROR_NONE;
}

int wifi_direct_get_gateway_address(char **gateway_address)
{
	__WDC_LOG_FUNC_START__;
	wifi_direct_client_info_s *client_info = __wfd_get_control();
	wifi_direct_state_e status = 0;
	char *get_str = NULL;
	int result;

	if ((client_info->is_registered == false) ||
			(client_info->client_id == WFD_INVALID_ID)) {
		WDC_LOGE("Client is NOT registered");
		__WDC_LOG_FUNC_END__;
		return WIFI_DIRECT_ERROR_NOT_INITIALIZED;
	}

	if (!gateway_address) {
		WDC_LOGE("NULL Param [gateway_address]!");
		__WDC_LOG_FUNC_END__;
		return WIFI_DIRECT_ERROR_INVALID_PARAMETER;
	}

	result = wifi_direct_get_state(&status);
	WDC_LOGD("wifi_direct_get_state() state=[%d], result=[%d]", status, result);
	if(status < WIFI_DIRECT_STATE_CONNECTED) {
		WDC_LOGE("Device is not connected!");
		__WDC_LOG_FUNC_END__;
		return WIFI_DIRECT_ERROR_NOT_PERMITTED;
	}

	get_str = vconf_get_str(VCONFKEY_GATEWAY);
	if (!get_str) {
		WDC_LOGD("vconf (%s) value is NULL!!!", VCONFKEY_GATEWAY);
		__WDC_LOG_FUNC_END__;
		return WIFI_DIRECT_ERROR_NOT_PERMITTED;
	}
	WDC_LOGD("VCONFKEY_GATEWAY(%s) : %s", VCONFKEY_GATEWAY, get_str);
	*gateway_address = strdup(get_str);
	free(get_str);

	__WDC_LOG_FUNC_END__;
	return WIFI_DIRECT_ERROR_NONE;
}

int wifi_direct_get_mac_address(char **mac_address)
{
	__WDC_LOG_FUNC_START__;
	wifi_direct_client_info_s *client_info = __wfd_get_control();
	int fd;
	int n;
	char mac_info[MACSTR_LEN];
	unsigned char la_mac_addr[6];

	if ((client_info->is_registered == false) ||
			(client_info->client_id == WFD_INVALID_ID)) {
		WDC_LOGE("Client is NOT registered");
		__WDC_LOG_FUNC_END__;
		return WIFI_DIRECT_ERROR_NOT_INITIALIZED;
	}

	if (!mac_address) {
		WDC_LOGE("NULL Param [mac_address]!");
		__WDC_LOG_FUNC_END__;
		return WIFI_DIRECT_ERROR_INVALID_PARAMETER;
	}

	memset(mac_info, 0, sizeof(mac_info));

	fd = open(WIFI_DIRECT_MAC_ADDRESS_INFO_FILE, O_RDONLY);
	if (fd == -1) {
		WDC_LOGE("[.mac.info] file open failed.");
		__WDC_LOG_FUNC_END__;
		return WIFI_DIRECT_ERROR_OPERATION_FAILED;
	}

	n = read(fd, mac_info, MACSTR_LEN);
	if(n < 0) {
		WDC_LOGE("[.mac.info] file read failed.");
		if (fd > 0)
			close(fd);
		__WDC_LOG_FUNC_END__;
		return WIFI_DIRECT_ERROR_OPERATION_FAILED;
	}
	mac_info[17] = '\0';
	WDC_LOGD("mac_address = [%s]", mac_info);

	memset(la_mac_addr, 0, sizeof(la_mac_addr));
	macaddr_atoe(mac_info, la_mac_addr);
	la_mac_addr[0] |= 0x02;

	*mac_address = (char*) calloc(1, MACSTR_LEN);
	snprintf(*mac_address, MACSTR_LEN, MACSTR, MAC2STR(la_mac_addr));

	if (fd > 0)
		close(fd);

	__WDC_LOG_FUNC_END__;
	return WIFI_DIRECT_ERROR_NONE;
}


int wifi_direct_get_state(wifi_direct_state_e *state)
{
	__WDC_LOG_FUNC_START__;
	wifi_direct_client_info_s *client_info = __wfd_get_control();
	wifi_direct_client_request_s req;
	wifi_direct_client_response_s rsp;
	int res = WIFI_DIRECT_ERROR_NONE;

	if (!state) {
		WDC_LOGE("NULL Param [state]!");
		__WDC_LOG_FUNC_END__;
		return WIFI_DIRECT_ERROR_INVALID_PARAMETER;
	}

	if ((client_info->is_registered == false) ||
			(client_info->client_id == WFD_INVALID_ID)) {
		WDC_LOGE("Client is NOT registered");
		__WDC_LOG_FUNC_END__;
		return WIFI_DIRECT_ERROR_NOT_INITIALIZED;
	}

	memset(&req, 0, sizeof(wifi_direct_client_request_s));
	memset(&rsp, 0, sizeof(wifi_direct_client_response_s));

	req.cmd = WIFI_DIRECT_CMD_GET_LINK_STATUS;
	req.client_id = client_info->client_id;

	res = __wfd_client_send_request(client_info->sync_sockfd, &req, &rsp);
	if (res != WIFI_DIRECT_ERROR_NONE) {
		__WDC_LOG_FUNC_END__;
		return res;
	}
	WDC_LOGD("Link Status = %d", (int) rsp.param1);
	*state = (wifi_direct_state_e) rsp.param1;

	/* for CAPI : there is no WIFI_DIRECT_STATE_GROUP_OWNER type in CAPI */
	if(*state == WIFI_DIRECT_STATE_GROUP_OWNER)
		*state = WIFI_DIRECT_STATE_CONNECTED;

	__WDC_LOG_FUNC_END__;
	return WIFI_DIRECT_ERROR_NONE;
}


int wifi_direct_is_discoverable(bool* discoverable)
{
	__WDC_LOG_FUNC_START__;
	wifi_direct_client_info_s *client_info = __wfd_get_control();
	wifi_direct_client_request_s req;
	wifi_direct_client_response_s rsp;
	int res = WIFI_DIRECT_ERROR_NONE;

	if ((client_info->is_registered == false) ||
			(client_info->client_id == WFD_INVALID_ID)) {
		WDC_LOGE("Client is NOT registered");
		__WDC_LOG_FUNC_END__;
		return WIFI_DIRECT_ERROR_NOT_INITIALIZED;
	}

	if (!discoverable) {
		WDC_LOGE("NULL Param [discoverable]!");
		__WDC_LOG_FUNC_END__;
		return WIFI_DIRECT_ERROR_INVALID_PARAMETER;
	}

	memset(&req, 0, sizeof(wifi_direct_client_request_s));
	memset(&rsp, 0, sizeof(wifi_direct_client_response_s));

	req.cmd = WIFI_DIRECT_CMD_IS_DISCOVERABLE;
	req.client_id = client_info->client_id;

	res = __wfd_client_send_request(client_info->sync_sockfd, &req, &rsp);
	if (res != WIFI_DIRECT_ERROR_NONE) {
		__WDC_LOG_FUNC_END__;
		return res;
	}
	WDC_LOGD("wifi_direct_is_discoverable() SUCCESS");
	*discoverable = (bool) rsp.param1;

	__WDC_LOG_FUNC_END__;
	return WIFI_DIRECT_ERROR_NONE;
}

int wifi_direct_is_listening_only(bool* listen_only)
{
	__WDC_LOG_FUNC_START__;
	wifi_direct_client_info_s *client_info = __wfd_get_control();
	wifi_direct_client_request_s req;
	wifi_direct_client_response_s rsp;
	int res = WIFI_DIRECT_ERROR_NONE;

	if ((client_info->is_registered == false) ||
			(client_info->client_id == WFD_INVALID_ID)) {
		WDC_LOGE("Client is NOT registered");
		__WDC_LOG_FUNC_END__;
		return WIFI_DIRECT_ERROR_NOT_INITIALIZED;
	}

	if (!listen_only) {
		WDC_LOGE("NULL Param [listen_only]!");
		__WDC_LOG_FUNC_END__;
		return WIFI_DIRECT_ERROR_INVALID_PARAMETER;
	}

	memset(&req, 0, sizeof(wifi_direct_client_request_s));
	memset(&rsp, 0, sizeof(wifi_direct_client_response_s));

	req.cmd = WIFI_DIRECT_CMD_IS_LISTENING_ONLY;
	req.client_id = client_info->client_id;

	res = __wfd_client_send_request(client_info->sync_sockfd, &req, &rsp);
	if (res != WIFI_DIRECT_ERROR_NONE) {
		__WDC_LOG_FUNC_END__;
		return res;
	}
	WDC_LOGD("wifi_direct_is_listening_only() SUCCESS");
	*listen_only = (bool) rsp.param1;

	__WDC_LOG_FUNC_END__;
	return WIFI_DIRECT_ERROR_NONE;
}


int wifi_direct_get_primary_device_type(wifi_direct_primary_device_type_e* type)
{
	__WDC_LOG_FUNC_START__;
	wifi_direct_client_info_s *client_info = __wfd_get_control();

	if (!type) {
		WDC_LOGE("NULL Param [type]!");
		__WDC_LOG_FUNC_END__;
		return WIFI_DIRECT_ERROR_INVALID_PARAMETER;
	}

	if ((client_info->is_registered == false) ||
			(client_info->client_id == WFD_INVALID_ID)) {
		WDC_LOGE("Client is NOT registered");
		__WDC_LOG_FUNC_END__;
		return WIFI_DIRECT_ERROR_NOT_INITIALIZED;
	}

	WDC_LOGD("Current primary_dev_type [%d]", WIFI_DIRECT_PRIMARY_DEVICE_TYPE_TELEPHONE);
	*type = WIFI_DIRECT_PRIMARY_DEVICE_TYPE_TELEPHONE;

	__WDC_LOG_FUNC_END__;
	return WIFI_DIRECT_ERROR_NONE;
}

int wifi_direct_get_secondary_device_type(wifi_direct_secondary_device_type_e* type)
{
	__WDC_LOG_FUNC_START__;
	wifi_direct_client_info_s *client_info = __wfd_get_control();

	if ((client_info->is_registered == false) ||
			(client_info->client_id == WFD_INVALID_ID)) {
		WDC_LOGE("Client is NOT registered");
		__WDC_LOG_FUNC_END__;
		return WIFI_DIRECT_ERROR_NOT_INITIALIZED;
	}

	if (NULL == type) {
		WDC_LOGE("NULL Param [type]!");
		__WDC_LOG_FUNC_END__;
		return WIFI_DIRECT_ERROR_INVALID_PARAMETER;
	}

	WDC_LOGD("Current second_dev_type [%d]", WIFI_DIRECT_SECONDARY_DEVICE_TYPE_PHONE_SM_DUAL);
	*type = WIFI_DIRECT_SECONDARY_DEVICE_TYPE_PHONE_SM_DUAL;	// smart phone dual mode (wifi and cellular)

	__WDC_LOG_FUNC_END__;
	return WIFI_DIRECT_ERROR_NONE;
}

int wifi_direct_set_autoconnection_mode(bool mode)
{
	__WDC_LOG_FUNC_START__;
	wifi_direct_client_info_s *client_info = __wfd_get_control();
	wifi_direct_client_request_s req;
	wifi_direct_client_response_s rsp;
	int res = WIFI_DIRECT_ERROR_NONE;

	if ((client_info->is_registered == false) ||
			(client_info->client_id == WFD_INVALID_ID)) {
		WDC_LOGE("Client is NOT registered");
		__WDC_LOG_FUNC_END__;
		return WIFI_DIRECT_ERROR_NOT_INITIALIZED;
	}

	memset(&req, 0, sizeof(wifi_direct_client_request_s));
	memset(&rsp, 0, sizeof(wifi_direct_client_response_s));

	req.cmd = WIFI_DIRECT_CMD_SET_AUTOCONNECTION_MODE;
	req.client_id = client_info->client_id;
	req.data.int1 = mode;

	res = __wfd_client_send_request(client_info->sync_sockfd, &req, &rsp);
	if (res != WIFI_DIRECT_ERROR_NONE) {
		__WDC_LOG_FUNC_END__;
		return res;
	}

	__WDC_LOG_FUNC_END__;
	return WIFI_DIRECT_ERROR_NONE;
}

int wifi_direct_is_autoconnection_mode(bool *mode)
{
	__WDC_LOG_FUNC_START__;
	wifi_direct_client_info_s *client_info = __wfd_get_control();
	wifi_direct_client_request_s req;
	wifi_direct_client_response_s rsp;
	int res = WIFI_DIRECT_ERROR_NONE;

	if ((client_info->is_registered == false) ||
			(client_info->client_id == WFD_INVALID_ID)) {
		WDC_LOGE("Client is NOT registered");
		__WDC_LOG_FUNC_END__;
		return WIFI_DIRECT_ERROR_NOT_INITIALIZED;
	}

	if (!mode) {
		WDC_LOGE("NULL Param [mode]!");
		__WDC_LOG_FUNC_END__;
		return WIFI_DIRECT_ERROR_INVALID_PARAMETER;
	}

	memset(&req, 0, sizeof(wifi_direct_client_request_s));
	memset(&rsp, 0, sizeof(wifi_direct_client_response_s));

	req.cmd = WIFI_DIRECT_CMD_IS_AUTOCONNECTION_MODE;
	req.client_id = client_info->client_id;

	res = __wfd_client_send_request(client_info->sync_sockfd, &req, &rsp);
	if (res != WIFI_DIRECT_ERROR_NONE) {
		__WDC_LOG_FUNC_END__;
		return res;
	}
	WDC_LOGD("wifi_direct_is_autoconnection_mode() SUCCESS");
	*mode = (bool) rsp.param1;

	__WDC_LOG_FUNC_END__;
	return WIFI_DIRECT_ERROR_NONE;

}


int wifi_direct_set_persistent_group_enabled(bool enabled)
{
	__WDC_LOG_FUNC_START__;
	wifi_direct_client_info_s *client_info = __wfd_get_control();
	wifi_direct_client_request_s req;
	wifi_direct_client_response_s rsp;
	int res = WIFI_DIRECT_ERROR_NONE;

	if ((client_info->is_registered == false) ||
			(client_info->client_id == WFD_INVALID_ID)) {
		WDC_LOGE("Client is NOT registered");
		__WDC_LOG_FUNC_END__;
		return WIFI_DIRECT_ERROR_NOT_INITIALIZED;
	}

	memset(&req, 0, sizeof(wifi_direct_client_request_s));
	memset(&rsp, 0, sizeof(wifi_direct_client_response_s));

	if (enabled == true)
		req.cmd = WIFI_DIRECT_CMD_ACTIVATE_PERSISTENT_GROUP;
	else
		req.cmd = WIFI_DIRECT_CMD_DEACTIVATE_PERSISTENT_GROUP;
	req.client_id = client_info->client_id;

	res = __wfd_client_send_request(client_info->sync_sockfd, &req, &rsp);
	if (res != WIFI_DIRECT_ERROR_NONE) {
		__WDC_LOG_FUNC_END__;
		return res;
	}
	WDC_LOGD("wifi_direct_set_persistent_group_enabled() SUCCESS");

	__WDC_LOG_FUNC_END__;
	return WIFI_DIRECT_ERROR_NONE;
}


int wifi_direct_is_persistent_group_enabled(bool *enabled)
{
	__WDC_LOG_FUNC_START__;
	wifi_direct_client_info_s *client_info = __wfd_get_control();
	wifi_direct_client_request_s req;
	wifi_direct_client_response_s rsp;
	int res = WIFI_DIRECT_ERROR_NONE;

	if ((client_info->is_registered == false) ||
			(client_info->client_id == WFD_INVALID_ID)) {
		WDC_LOGE("Client is NOT registered");
		__WDC_LOG_FUNC_END__;
		return WIFI_DIRECT_ERROR_NOT_INITIALIZED;
	}

	if (!enabled) {
		WDC_LOGE("NULL Param [enabled]!");
		__WDC_LOG_FUNC_END__;
		return WIFI_DIRECT_ERROR_INVALID_PARAMETER;
	}

	memset(&req, 0, sizeof(wifi_direct_client_request_s));
	memset(&rsp, 0, sizeof(wifi_direct_client_response_s));

	req.cmd = WIFI_DIRECT_CMD_IS_PERSISTENT_GROUP;
	req.client_id = client_info->client_id;

	res = __wfd_client_send_request(client_info->sync_sockfd, &req, &rsp);
	if (res != WIFI_DIRECT_ERROR_NONE) {
		__WDC_LOG_FUNC_END__;
		return res;
	}
	WDC_LOGD("wifi_direct_is_persistent_group_enabled() SUCCESS");
	*enabled = (bool) rsp.param1;

	__WDC_LOG_FUNC_END__;
	return WIFI_DIRECT_ERROR_NONE;
}

int wifi_direct_foreach_persistent_groups(wifi_direct_persistent_group_cb cb,
												void* user_data)
{
	__WDC_LOG_FUNC_START__;
	wifi_direct_client_info_s *client_info = __wfd_get_control();
	wifi_direct_client_request_s req;
	wifi_direct_client_response_s rsp;
	int res = WIFI_DIRECT_ERROR_NONE;
	int i;

	if ((client_info->is_registered == false) ||
			(client_info->client_id == WFD_INVALID_ID)) {
		WDC_LOGE("Client is NOT registered");
		__WDC_LOG_FUNC_END__;
		return WIFI_DIRECT_ERROR_NOT_INITIALIZED;
	}

	if (!cb) {
		WDC_LOGE("NULL Param [callback]!");
		__WDC_LOG_FUNC_END__;
		return WIFI_DIRECT_ERROR_INVALID_PARAMETER;
	}

	memset(&req, 0, sizeof(wifi_direct_client_request_s));
	memset(&rsp, 0, sizeof(wifi_direct_client_response_s));

	req.cmd = WIFI_DIRECT_CMD_GET_PERSISTENT_GROUP_INFO;
	req.client_id = client_info->client_id;

	pthread_mutex_lock(&g_client_info.mutex);
	res = __wfd_client_write_socket(client_info->sync_sockfd, &req, sizeof(wifi_direct_client_request_s));
	if (res != WIFI_DIRECT_ERROR_NONE) {
		WDC_LOGE("Failed to write into socket [%s]", __wfd_print_error(res));
		__wfd_reset_control();
		pthread_mutex_unlock(&g_client_info.mutex);
		__WDC_LOG_FUNC_END__;
		return WIFI_DIRECT_ERROR_COMMUNICATION_FAILED;
	}
	WDC_LOGD("Succeeded to send request [%d: %s]", req.cmd, __wfd_client_print_cmd(req.cmd));

	res = __wfd_client_read_socket(client_info->sync_sockfd, &rsp, sizeof(wifi_direct_client_response_s));
	if (res <= 0) {
		WDC_LOGE("Failed to read socket [%d]", res);
		__wfd_reset_control();
		pthread_mutex_unlock(&g_client_info.mutex);
		__WDC_LOG_FUNC_END__;
		return WIFI_DIRECT_ERROR_COMMUNICATION_FAILED;
	} else {
		if (rsp.cmd != req.cmd) {
			WDC_LOGE("Invalid resp [%d]", rsp.cmd);
			pthread_mutex_unlock(&g_client_info.mutex);
			__WDC_LOG_FUNC_END__;
			return WIFI_DIRECT_ERROR_COMMUNICATION_FAILED;
		}

		if (rsp.result != WIFI_DIRECT_ERROR_NONE) {
			WDC_LOGE("Result received [%s]", __wfd_print_error(rsp.result));
			pthread_mutex_unlock(&g_client_info.mutex);
			__WDC_LOG_FUNC_END__;
			return rsp.result;
		}
	}

	int num = rsp.param1;
	wfd_persistent_group_info_s *buff = NULL;

	WDC_LOGD("Num of persistent groups = %d", (int) rsp.param1);

	if (num > 0) {
		buff = (wfd_persistent_group_info_s *) malloc(num * sizeof(wfd_persistent_group_info_s));
		if (!buff) {
			WDC_LOGE("malloc() failed!!!.");
			pthread_mutex_unlock(&g_client_info.mutex);
			return WIFI_DIRECT_ERROR_OPERATION_FAILED;
		}

		res = __wfd_client_read_socket(client_info->sync_sockfd, (char*) buff,
										num * sizeof(wfd_persistent_group_info_s));
		pthread_mutex_unlock(&g_client_info.mutex);
		if (res <= 0){
			free(buff);
			WDC_LOGE("socket read error.");
			__wfd_reset_control();
			return WIFI_DIRECT_ERROR_OPERATION_FAILED;
		}

		__wfd_client_print_persistent_group_info(buff, num);
		WDC_LOGD("wifi_direct_foreach_persistent_groups() SUCCESS");

		char *ssid;
		char *go_mac_address;

		for (i = 0; i < num; i++) {
			ssid = strdup(buff[i].ssid);
			if (!ssid) {
				WDC_LOGD("Failed to copy ssid");
				break;
			}
			go_mac_address = (char*) calloc(1, MACSTR_LEN);
			if (!go_mac_address) {
				WDC_LOGD("Failed to allocate memory for GO MAC address");
				free(ssid);
				free(buff);
				return WIFI_DIRECT_ERROR_OUT_OF_MEMORY;
			}
			snprintf(go_mac_address, MACSTR_LEN, MACSTR, MAC2STR(buff[i].go_mac_address));

			res = cb(go_mac_address, ssid, user_data);
			free(ssid);
			ssid = NULL;
			free(go_mac_address);
			go_mac_address = NULL;
			if (!res)
				break;
		}

		if (buff)
			free(buff);

	} else {
		pthread_mutex_unlock(&g_client_info.mutex);
	}

	__WDC_LOG_FUNC_END__;
	return WIFI_DIRECT_ERROR_NONE;
}

int wifi_direct_remove_persistent_group(const char *mac_address, const char *ssid)
{
	__WDC_LOG_FUNC_START__;
	wifi_direct_client_info_s *client_info = __wfd_get_control();
	wifi_direct_client_request_s req;
	wifi_direct_client_response_s rsp;
	wfd_persistent_group_info_s persistent_group_info;
	int status = WIFI_DIRECT_ERROR_NONE;

	if ((client_info->is_registered == false) ||
			(client_info->client_id == WFD_INVALID_ID)) {
		WDC_LOGE("Client is NOT registered");
		__WDC_LOG_FUNC_END__;
		return WIFI_DIRECT_ERROR_NOT_INITIALIZED;
	}

	if (!mac_address || !ssid) {
		WDC_LOGE("NULL Param");
		__WDC_LOG_FUNC_END__;
		return WIFI_DIRECT_ERROR_INVALID_PARAMETER;
	}

	memset(&req, 0, sizeof(wifi_direct_client_request_s));
	memset(&rsp, 0, sizeof(wifi_direct_client_response_s));

	req.cmd = WIFI_DIRECT_CMD_REMOVE_PERSISTENT_GROUP;
	req.client_id = client_info->client_id;

	pthread_mutex_lock(&g_client_info.mutex);
	status = __wfd_client_write_socket(client_info->sync_sockfd, &req,
								  sizeof(wifi_direct_client_request_s));
	if (status != WIFI_DIRECT_ERROR_NONE) {
		WDC_LOGE("Error!!! writing to socket[%s]", __wfd_print_error(status));
		__wfd_reset_control();
		pthread_mutex_unlock(&g_client_info.mutex);
		__WDC_LOG_FUNC_END__;
		return WIFI_DIRECT_ERROR_COMMUNICATION_FAILED;
	}
	WDC_LOGD("writing msg hdr is success!");

	strncpy(persistent_group_info.ssid, ssid, WIFI_DIRECT_MAX_SSID_LEN);
	persistent_group_info.ssid[WIFI_DIRECT_MAX_SSID_LEN] ='\0';
	macaddr_atoe(mac_address, persistent_group_info.go_mac_address);

	status = __wfd_client_write_socket(client_info->sync_sockfd, &persistent_group_info,
								  sizeof(wfd_persistent_group_info_s));
	if (status != WIFI_DIRECT_ERROR_NONE) {
		WDC_LOGE("Error!!! writing to socket[%s]", __wfd_print_error(status));
		__wfd_reset_control();
		pthread_mutex_unlock(&g_client_info.mutex);
		__WDC_LOG_FUNC_END__;
		return WIFI_DIRECT_ERROR_COMMUNICATION_FAILED;
	}

	status = __wfd_client_read_socket(client_info->sync_sockfd, (char*) &rsp,
								  sizeof(wifi_direct_client_response_s));
	pthread_mutex_unlock(&g_client_info.mutex);
	if (status <= 0) {
		WDC_LOGE("Error!!! reading socket, status = %d", status);
		__wfd_reset_control();
		__WDC_LOG_FUNC_END__;
		return WIFI_DIRECT_ERROR_COMMUNICATION_FAILED;
	} else {
		if (rsp.cmd == WIFI_DIRECT_CMD_REMOVE_PERSISTENT_GROUP) {
			if (rsp.result != WIFI_DIRECT_ERROR_NONE) {
				WDC_LOGD("Error!!! Result received = %d", rsp.result);
				WDC_LOGD("Error!!! [%s]", __wfd_print_error(rsp.result));
				__WDC_LOG_FUNC_END__;
				return rsp.result;
			}
		} else {
			WDC_LOGE("Error!!! Invalid resp cmd = %d", rsp.cmd);
			return WIFI_DIRECT_ERROR_OPERATION_FAILED;
		}
	}

	__WDC_LOG_FUNC_END__;
	return WIFI_DIRECT_ERROR_NONE;
}

int wifi_direct_set_p2poem_loglevel(int increase_log_level)
{
	__WDC_LOG_FUNC_START__;
	wifi_direct_client_info_s *client_info = __wfd_get_control();
	wifi_direct_client_request_s req;
	wifi_direct_client_response_s rsp;
	int res = WIFI_DIRECT_ERROR_NONE;

	if ((client_info->is_registered == false) ||
			(client_info->client_id == WFD_INVALID_ID)) {
		WDC_LOGE("Client is NOT registered");
		__WDC_LOG_FUNC_END__;
		return WIFI_DIRECT_ERROR_NOT_INITIALIZED;
	}

	memset(&req, 0, sizeof(wifi_direct_client_request_s));
	memset(&rsp, 0, sizeof(wifi_direct_client_response_s));

	req.cmd = WIFI_DIRECT_CMD_SET_OEM_LOGLEVEL;
	req.client_id = client_info->client_id;
	if (increase_log_level == 0)
		req.data.int1 = false;
	else
		req.data.int1 = true;

	res = __wfd_client_send_request(client_info->sync_sockfd, &req, &rsp);
	if (res != WIFI_DIRECT_ERROR_NONE) {
		__WDC_LOG_FUNC_END__;
		return res;
	}

	__WDC_LOG_FUNC_END__;
	return WIFI_DIRECT_ERROR_NONE;
}

int wifi_direct_service_add(wifi_direct_service_type_e type, char *data1, char *data2)
{
	__WDC_LOG_FUNC_START__;
	wifi_direct_client_info_s *client_info = __wfd_get_control();
	wifi_direct_client_request_s req;
	wifi_direct_client_response_s rsp;
	char *buf = NULL;
	char *ptr = NULL;
	int status = WIFI_DIRECT_ERROR_NONE;
	int len = 0;
	int data_len=0;

	if (!data1 && !strlen(data1)) {
		WDC_LOGE("NULL Param [data1]!");
		__WDC_LOG_FUNC_END__;
		return WIFI_DIRECT_ERROR_INVALID_PARAMETER;
	}

	if ((client_info->is_registered == false) ||
			(client_info->client_id == WFD_INVALID_ID)) {
		WDC_LOGE("Client is NOT registered.");
		__WDC_LOG_FUNC_END__;
		return WIFI_DIRECT_ERROR_NOT_INITIALIZED;
	}

	if (type >= WIFI_DIRECT_SERVICE_BONJOUR &&
			type <= WIFI_DIRECT_SERVICE_VENDORSPEC) {
		WDC_LOGD("Param service_type [%d]", type);
	} else {
		WDC_LOGE("Invalid Param [type]!");
		__WDC_LOG_FUNC_END__;
		return WIFI_DIRECT_ERROR_INVALID_PARAMETER;
	}

	memset(&req, 0, sizeof(wifi_direct_client_request_s));
	memset(&rsp, 0, sizeof(wifi_direct_client_response_s));

//TODO: modify the method to handle the NULL or zero length data

	if (data2 && (data_len=strlen(data2)))
		len =data_len +strlen(data1)+2;
	else
		len = strlen(data1)+1;

	WDC_LOGD("data1 [%s], data2 [%s], len [%d]", data1, data2, len);
	buf= calloc(sizeof(wifi_direct_client_request_s)+len, sizeof(char));
	if (NULL == buf) {
		WDC_LOGE("Memory can't be allocated for Buf\n");
		return WIFI_DIRECT_ERROR_OUT_OF_MEMORY;
	}

	req.cmd = WIFI_DIRECT_CMD_SERVICE_ADD;
	req.client_id = client_info->client_id;
	req.data.int1 = type;
	req.data.int2 = data_len;
	req.cmd_data_len = len;

	memcpy(buf, &req, sizeof(wifi_direct_client_request_s));
	ptr = buf;
	ptr += sizeof(wifi_direct_client_request_s);
	if(data_len)
		snprintf(ptr, len, "%s %s", data2, data1);
	else
		snprintf(ptr, len, "%s", data1);

	pthread_mutex_lock(&g_client_info.mutex);
	status = __wfd_client_write_socket(client_info->sync_sockfd, buf,
									sizeof(wifi_direct_client_request_s) + len);
	free(buf);
	if (status != WIFI_DIRECT_ERROR_NONE) {
		WDC_LOGE("Error!!! writing to socket, Errno = %s", strerror(errno));
		__wfd_reset_control();
		pthread_mutex_unlock(&g_client_info.mutex);
		__WDC_LOG_FUNC_END__;
		return WIFI_DIRECT_ERROR_COMMUNICATION_FAILED;
	}
	WDC_LOGD("Success writing data to the socket!");

	status = __wfd_client_read_socket(client_info->sync_sockfd, (char*) &rsp,
												sizeof(wifi_direct_client_response_s));
	pthread_mutex_unlock(&g_client_info.mutex);
	if (status <= 0) {
		WDC_LOGE("Error!!! reading socket, status = %d", status);
		__wfd_reset_control();
		__WDC_LOG_FUNC_END__;
		return WIFI_DIRECT_ERROR_COMMUNICATION_FAILED;
	} else {
		if (rsp.cmd == WIFI_DIRECT_CMD_SERVICE_ADD) {
			if (rsp.result != WIFI_DIRECT_ERROR_NONE) {
				WDC_LOGD("Error!!! Result received = %d", rsp.result);
				WDC_LOGD("Error!!! [%spin]", __wfd_print_error(rsp.result));
				__WDC_LOG_FUNC_END__;
				return rsp.result;
			}
		} else {
			WDC_LOGE("Error!!! Invalid resp cmd = %d", rsp.cmd);
			__WDC_LOG_FUNC_END__;
			return WIFI_DIRECT_ERROR_OPERATION_FAILED;
		}
	}

	__WDC_LOG_FUNC_END__;
	return WIFI_DIRECT_ERROR_NONE;
}

int wifi_direct_service_del(wifi_direct_service_type_e type, char *data1, char *data2)
{
	__WDC_LOG_FUNC_START__;
	wifi_direct_client_info_s *client_info = __wfd_get_control();
	wifi_direct_client_request_s req;
	wifi_direct_client_response_s rsp;
	char *buf = NULL;
	char *ptr = NULL;
	int status = WIFI_DIRECT_ERROR_NONE;
	int len = 0;
	int data_len=0;

	if (!data1 && !strlen(data1)) {
		WDC_LOGE("NULL Param [data1]!");
		__WDC_LOG_FUNC_END__;
		return WIFI_DIRECT_ERROR_INVALID_PARAMETER;
	}

	if ((client_info->is_registered == false) ||
			(client_info->client_id == WFD_INVALID_ID)) {
		WDC_LOGE("Client is NOT registered.");
		__WDC_LOG_FUNC_END__;
		return WIFI_DIRECT_ERROR_NOT_INITIALIZED;
	}

	if (type >= WIFI_DIRECT_SERVICE_BONJOUR &&
			type <= WIFI_DIRECT_SERVICE_VENDORSPEC) {
		WDC_LOGD("Param service_type [%d]", type);
	} else {
		WDC_LOGE("Invalid Param [type]!");
		__WDC_LOG_FUNC_END__;
		return WIFI_DIRECT_ERROR_INVALID_PARAMETER;
	}

	memset(&req, 0, sizeof(wifi_direct_client_request_s));
	memset(&rsp, 0, sizeof(wifi_direct_client_response_s));

//TODO: modify the method to handle the NULL or zero length data

	if (data2 && (data_len=strlen(data2)))
		len =data_len +strlen(data1)+2;
	else
		len = strlen(data1)+1;

	WDC_LOGD("data1 [%s], data2 [%s], len [%d]", data1, data2, len);
	buf= calloc(sizeof(wifi_direct_client_request_s) + len, sizeof(char));
	if (NULL == buf) {
		WDC_LOGE("Memory can't be allocated for Buf\n");
		return WIFI_DIRECT_ERROR_OUT_OF_MEMORY;
	}

	req.cmd = WIFI_DIRECT_CMD_SERVICE_DEL;
	req.client_id = client_info->client_id;
	req.data.int1 = type;
	req.data.int2 = data_len;
	req.cmd_data_len = len;

	memcpy(buf, &req, sizeof(wifi_direct_client_request_s));
	ptr = buf;
	ptr += sizeof(wifi_direct_client_request_s);
	if(data_len)
		snprintf(ptr, len, "%s %s", data2, data1);
	else
		snprintf(ptr, len, "%s", data1);

	pthread_mutex_lock(&g_client_info.mutex);
	status = __wfd_client_write_socket(client_info->sync_sockfd, buf,
									sizeof(wifi_direct_client_request_s) + len);
	free(buf);
	if (status != WIFI_DIRECT_ERROR_NONE) {
		WDC_LOGE("Error!!! writing to socket, Errno = %s", strerror(errno));
		__wfd_reset_control();
		pthread_mutex_unlock(&g_client_info.mutex);
		__WDC_LOG_FUNC_END__;
		return WIFI_DIRECT_ERROR_COMMUNICATION_FAILED;
	}
	WDC_LOGD("Success writing data to the socket!");

	status = __wfd_client_read_socket(client_info->sync_sockfd, (char*) &rsp,
												sizeof(wifi_direct_client_response_s));
	pthread_mutex_unlock(&g_client_info.mutex);
	if (status <= 0) {
		WDC_LOGE("Error!!! reading socket, status = %d", status);
		__wfd_reset_control();
		__WDC_LOG_FUNC_END__;
		return WIFI_DIRECT_ERROR_COMMUNICATION_FAILED;
	} else {
		if (rsp.cmd == WIFI_DIRECT_CMD_SERVICE_DEL) {
			if (rsp.result != WIFI_DIRECT_ERROR_NONE) {
				WDC_LOGD("Error!!! Result received = %d", rsp.result);
				WDC_LOGD("Error!!! [%spin]", __wfd_print_error(rsp.result));
				__WDC_LOG_FUNC_END__;
				return rsp.result;
			}
		} else {
			WDC_LOGE("Error!!! Invalid resp cmd = %d", rsp.cmd);
			__WDC_LOG_FUNC_END__;
			return WIFI_DIRECT_ERROR_OPERATION_FAILED;
		}
	}

	__WDC_LOG_FUNC_END__;
	return WIFI_DIRECT_ERROR_NONE;
}


int wifi_direct_serv_disc_req(char* mac_address, wifi_direct_service_type_e type, char *data1, char *data2)
{
	__WDC_LOG_FUNC_START__;
	wifi_direct_client_info_s *client_info = __wfd_get_control();
	wifi_direct_client_request_s req;
	wifi_direct_client_response_s rsp;
	unsigned char la_mac_addr[6];
	char *buf = NULL;
	char *ptr = NULL;
	int status = WIFI_DIRECT_ERROR_NONE;
	int query_len = 0;
	int data_len = 0;


	if ((client_info->is_registered == false) ||
			(client_info->client_id == WFD_INVALID_ID)) {
		WDC_LOGE("Client is NOT registered.");
		__WDC_LOG_FUNC_END__;
		return WIFI_DIRECT_ERROR_NOT_INITIALIZED;
	}

	if (type >= WIFI_DIRECT_SERVICE_BONJOUR &&
			type <= WIFI_DIRECT_SERVICE_VENDORSPEC) {
		WDC_LOGD("Param service_type [%d]", type);
	} else {
		WDC_LOGE("Invalid Param [type]!");
		__WDC_LOG_FUNC_END__;
		return WIFI_DIRECT_ERROR_INVALID_PARAMETER;
	}

	memset(&req, 0, sizeof(wifi_direct_client_request_s));
	memset(&rsp, 0, sizeof(wifi_direct_client_response_s));

	if(data2 && (data_len = strlen(data2)))
		data_len++;
	if(data1 && (query_len = strlen(data1)))
		query_len++;

	WDC_LOGD("data [%s], query [%s]", data2, data1);
	buf= calloc(sizeof(wifi_direct_client_request_s)+data_len+query_len, sizeof(char));
	if (NULL == buf) {
		WDC_LOGE("Memory can't be allocated for Buf\n");
		return WIFI_DIRECT_ERROR_OUT_OF_MEMORY;
	}

	req.cmd = WIFI_DIRECT_CMD_SERV_DISC_REQ;
	req.client_id = client_info->client_id;
	req.data.int1 = type;
	req.data.int2 = data_len;
	req.cmd_data_len = data_len+ query_len;
	macaddr_atoe(mac_address, la_mac_addr);
	memcpy(req.data.mac_addr, la_mac_addr, MACADDR_LEN);

	memcpy(buf, &req, sizeof(wifi_direct_client_request_s));
	ptr = buf;
	ptr += sizeof(wifi_direct_client_request_s);

	if(data_len)
		snprintf(ptr, data_len+query_len, "%s %s", data2, data1);
	else if(query_len)
		snprintf(ptr, query_len, "%s", data1);

	pthread_mutex_lock(&g_client_info.mutex);
	status = __wfd_client_write_socket(client_info->sync_sockfd, buf,
									sizeof(wifi_direct_client_request_s) + req.cmd_data_len);
	free(buf);
	if (status != WIFI_DIRECT_ERROR_NONE) {
		WDC_LOGE("Error!!! writing to socket, Errno = %s", strerror(errno));
		__wfd_reset_control();
		pthread_mutex_unlock(&g_client_info.mutex);
		__WDC_LOG_FUNC_END__;
		return WIFI_DIRECT_ERROR_COMMUNICATION_FAILED;
	}
	WDC_LOGD("Success writing data to the socket!");

	status = __wfd_client_read_socket(client_info->sync_sockfd, (char*) &rsp,
												sizeof(wifi_direct_client_response_s));
	pthread_mutex_unlock(&g_client_info.mutex);
	if (status <= 0) {
		WDC_LOGE("Error!!! reading socket, status = %d", status);
		__wfd_reset_control();
		__WDC_LOG_FUNC_END__;
		return WIFI_DIRECT_ERROR_COMMUNICATION_FAILED;
	} else {
		if (rsp.cmd == WIFI_DIRECT_CMD_SERV_DISC_REQ) {
			if (rsp.result != WIFI_DIRECT_ERROR_NONE) {
				WDC_LOGD("Error!!! Result received = %d", rsp.result);
				WDC_LOGD("Error!!! [%spin]", __wfd_print_error(rsp.result));
				__WDC_LOG_FUNC_END__;
				return rsp.result;
			}
		} else {
			WDC_LOGE("Error!!! Invalid resp cmd = %d", rsp.cmd);
			return WIFI_DIRECT_ERROR_OPERATION_FAILED;
		}
	}
	WDC_LOGD("handle = [%d]\n", (int) rsp.param1);
	__WDC_LOG_FUNC_END__;
	return rsp.param1;
}

int wifi_direct_serv_disc_cancel(int handle)
{
	__WDC_LOG_FUNC_START__;
	wifi_direct_client_info_s *client_info = __wfd_get_control();
	wifi_direct_client_request_s req;
	wifi_direct_client_response_s rsp;
	int res = WIFI_DIRECT_ERROR_NONE;

	if ((client_info->is_registered == false) ||
			(client_info->client_id == WFD_INVALID_ID)) {
		WDC_LOGE("Client is NOT registered");
		__WDC_LOG_FUNC_END__;
		return WIFI_DIRECT_ERROR_NOT_INITIALIZED;
	}

	memset(&req, 0, sizeof(wifi_direct_client_request_s));
	memset(&rsp, 0, sizeof(wifi_direct_client_response_s));

	req.cmd = WIFI_DIRECT_CMD_SERV_DISC_CANCEL;
	req.client_id = client_info->client_id;
	req.data.int1 = handle;

	res = __wfd_client_send_request(client_info->sync_sockfd, &req, &rsp);
	if (res != WIFI_DIRECT_ERROR_NONE) {
		__WDC_LOG_FUNC_END__;
		return res;
	}

	__WDC_LOG_FUNC_END__;
	return WIFI_DIRECT_ERROR_NONE;
}
