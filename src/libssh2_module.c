/* VDE PN Manager -- VDE Private Network Manager
 * Copyright (C) 2011 - Massimo Gengarelli <gengarel@cs.unibo.it>
 *                    - Vincenzo Ferrari   <ferrari@cs.unibo.it>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 */

#include <stdio.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>

#include <libssh2.h>
#define LIBSSH2_INIT_NO_CRYPTO 0x0001

#include <glib.h>
#include <gio/gio.h>

/* Using a SSH connection to registering vdepn public key on remote host */
gboolean vdepn_libssh_wrapper_set_ssh_pass (const gchar *user, const gchar *host, const gchar *pass, const gchar *cmd_pubkey) {
  struct addrinfo hints;
  struct addrinfo *result;
  int res;
  int connecting_socket;
  char buffer[400];
  LIBSSH2_SESSION *session;
  LIBSSH2_CHANNEL *channel;
  char *userauthlist;

  /* Initialize libssh2 functions */
  if ((libssh2_init (0)) < 0) {
  	fprintf (stderr, "Error! Could not initialize libssh2\n");
  	return -1;
  }

  /* Needed to get host by name */
  hints.ai_family = AF_INET;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_protocol = 0;
  hints.ai_addrlen = 0;
  hints.ai_next = NULL;
  hints.ai_canonname = NULL;
  hints.ai_addr = NULL;
  hints.ai_flags = AI_NUMERICSERV;

  /* This is the new replacement for gethostby* */
  if ((getaddrinfo (host, "22", &hints, &result)) > 0) {
  	fprintf (stderr, "%s\n", gai_strerror (res));
	return -1;
  }

  /* Communication descriptor */
  if ((connecting_socket = socket (hints.ai_family, hints.ai_socktype, 0)) == -1) {
  	perror ("socket()");
  	return -1;
  }

  /* Connection */
  if ((connect (connecting_socket, result->ai_addr, result->ai_addrlen)) == -1) {
  	perror ("connect()");
	return -1;
  }

  /* Init libssh2 session */
  if ((session = libssh2_session_init ()) == NULL) {
  	fprintf (stderr, "Error! Could not initialize SSH session\n");
  	return -1;
  }

  /* Init transport layer (ssh session) */
  if ((libssh2_session_startup (session, connecting_socket)) < 0) {
	fprintf (stderr, "Error! Could not start SSH session\n");
	return -1;
  }

  /* List of authentication methods supported by server */
  if ((userauthlist = libssh2_userauth_list (session, user, strlen(user))) == NULL) {
  	fprintf (stderr, "Error! Could not list the authentication methods supported by server\n");
  	return -1;
  }

  /* Finding the authentication password method */
  if ((strstr (userauthlist, "password")) == NULL) {
	fprintf (stderr, "Error! Could not found a password authentication method on %s\n", host);
	return -1;
  }

  /* Authenticate via password */
  /* session : ssh session */
  if ((libssh2_userauth_password (session, user, pass)) < 0) {
	fprintf (stderr, "Error! Could not authenticate via password\n");
	return -1;
  }

  /* Checking authentication status */
  if ((libssh2_userauth_authenticated(session)) == 0) {
  	fprintf (stderr, "Error! Could not authenticate\n");
  	return -1;
  }

  /* Get a new session channel */
  if ((channel = libssh2_channel_open_session (session)) == NULL) {
  	fprintf (stderr, "Error! Could not receive session\n");
  	return -1;
  }
  
  /* Exec cmd_pubkey into the remote host */
  if ((libssh2_channel_exec (channel, cmd_pubkey)) < 0) {
  	fprintf (stderr, "Error! Could not copy the pubkey into the remote host\n");
  	return -1;
  }

  libssh2_exit ();
  
  return TRUE;
}
