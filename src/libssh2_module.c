#include <stdio.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>

#include <libssh2.h>
#define LIBSSH2_INIT_NO_CRYPTO 0x0001

#include <glib.h>
#include <gio/gio.h>

/* cmd_pubkey = mkdir .ssh; echo 'pubkey' >> .ssh/authorized_keys */
gboolean vdepn_libssh_wrapper_set_ssh_pass (const gchar *user, const gchar *host, const gchar *pass, const gchar *cmd_pubkey) {
  struct addrinfo hints;
  struct addrinfo *result;
  int res;
  int connecting_socket;
  char buffer[400];
  LIBSSH2_SESSION *session;
  LIBSSH2_CHANNEL *channel;

  /* Initialize libssh2 functions */
  libssh2_init (0);

  /* Needed to get host by name */
  hints.ai_family = AF_INET;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_protocol = 0;
  hints.ai_addrlen = 0;
  hints.ai_next = NULL;
  hints.ai_canonname = NULL;
  hints.ai_addr = NULL;
  hints.ai_flags = AI_NUMERICSERV;
  
  printf ("Username : %s\n", user);
  printf ("Host : %s\n", host);
  printf ("Password : %s\n", pass);
  printf ("Pubkey : %s\n", cmd_pubkey);

  /* This is the new replacement for gethostby* */
  /* argv[2] : host, 22 it's a service (ssh) */
  res = getaddrinfo (host, "22", &hints, &result);

  if (res > 0) {
	fprintf (stderr, "%s\n", gai_strerror (res));
	return -1;
  }

  /* Communication descriptor */
  connecting_socket = socket (hints.ai_family, hints.ai_socktype, 0);
  /* Connection */
  res = connect (connecting_socket, result->ai_addr, result->ai_addrlen);

  if (res != 0) {
	perror ("connect()");
	return -1;
  }

  /* Init libssh2 session */
  session = libssh2_session_init ();

  /* Init transport layer (ssh session) */
  if (libssh2_session_startup (session, connecting_socket)) {
	fprintf (stderr, "Could not initialize SSH session\n");
	return -1;
  }

  /* List of authentication methods supported by server */
  char *userauthlist = libssh2_userauth_list (session, user, strlen(user));

  /* Finding the authentication password method */
  if (strstr (userauthlist, "password") != NULL)
	printf ("Ok, found password authentication method on %s\n", host);

  /* Authenticate via password */
  /* session : ssh session */
  /* argv[1] : username */
  /* argv[3] : password */
  if (libssh2_userauth_password (session, user, pass)) {
	fprintf (stderr, "Password authentication failed\n");
	fprintf (stderr, "Maybe wrong user or password.\n");
	return -1;
  }
  else
	printf ("Password authentication succeeded\n");

  /* Checking authentication status */
  if (libssh2_userauth_authenticated(session))
  	printf ("Hell yeah! Authenticated successful!\n");
  else {
  	fprintf (stderr, "Not authenticated yet\n");
  	return -1;
  }

  /* Get a new session channel */
  if (!(channel = libssh2_channel_open_session (session))) {
  	fprintf (stderr, "Session not received\n");
  	return -1;
  }
  else
	printf ("Session received\n");
  
  /*printf ("Vai col comando in remoto!");*/
  /* argv[4] = "mkdir .ssh 2>/dev/null; echo 'pubkey' >> .ssh/authorized_keys" */
  if ((libssh2_channel_exec (channel, cmd_pubkey)) < 0) {
  	fprintf (stderr, "An error occured with libssh2_channel_exec ()");
  	return -1;
  }
  
  
  /* send command (argv[4]) */
  /*libssh2_channel_exec (channel, argv[4]);*/

  /* read result */
/*  libssh2_channel_read (channel, buffer, sizeof (buffer));

  printf("read: %s\n", buffer);*/

  libssh2_exit ();
  
  return TRUE;
}
