/* VDE PN Manager -- VDE Private Network Manager
 * Copyright (C) 2011 - Massimo Gengarelli <gengarel@cs.unibo.it>
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

using GLib.Environment;
using Xml;

namespace VDEPN {
	public class Application : GLib.Object {
		private static Doc default_configuration() {
			Doc def_conf = new Doc();

			// Defines the elements of the DOM
			Xml.Node *root_elem = def_conf.new_node(null, "vdemanager");
			Xml.Node *conn_root_elem = def_conf.new_node(null, "connection");
			Xml.Node *conn_sock_path = def_conf.new_node(null, "sockpath");
			Xml.Node *remote_sock_path = def_conf.new_node (null, "remotesocket");
			Xml.Node *conn_ip_address = def_conf.new_node(null, "ipaddress");
			Xml.Node *conn_user = def_conf.new_node(null, "user");
			Xml.Node *conn_machine = def_conf.new_node(null, "machine");
			Xml.Node *conn_password = def_conf.new_node(null, "password");

			// Creates the DOM
			def_conf.set_root_element (root_elem);

			root_elem->add_child (conn_root_elem);
			conn_root_elem->set_prop ("id", "test-connection");

			conn_root_elem->add_child (conn_sock_path);
			conn_sock_path->set_content ("/tmp/test-connection");

			conn_root_elem->add_child (remote_sock_path);
			remote_sock_path->set_content ("/tmp/vde.ctl");

			conn_root_elem->add_child (conn_ip_address);
			conn_ip_address->set_prop ("dhcp", "false");
			conn_ip_address->set_content ("10.0.0.1");

			conn_root_elem->add_child (conn_user);
			conn_user->set_content ("vde0");

			conn_root_elem->add_child (conn_machine);
			conn_machine->set_content ("vde2.v2.cs.unibo.it");
			conn_machine->set_prop ("checkhost", "true");
			conn_machine->set_prop ("port", "22");

			conn_root_elem->add_child (conn_password);
			conn_password->set_prop ("required", "false");
			conn_password->set_prop ("usekeys", "false");

			return def_conf;
		}


		public static void main (string[] args) {
			File prog_dir = File.new_for_path (Environment.get_user_config_dir () + Helper.PROG_DATA_DIR);
			File prog_xml = File.new_for_path (Environment.get_user_config_dir () + Helper.XML_FILE);

			// Configuration dir exists..
			if (prog_dir.query_exists (null)) {
				if (!(prog_xml.query_exists (null))) {
					Doc conf = default_configuration ();
					conf.save_file (get_user_config_dir () + Helper.XML_FILE);
				}
			}

			// Configuration dir doesn't exist
			else {
				DirUtils.create (get_user_config_dir () + Helper.PROG_DATA_DIR, 0775);
				Doc conf = default_configuration ();
				conf.save_file (get_user_config_dir () + Helper.XML_FILE);
			}

			set_application_name ("VDE PN Manager");
			set_prgname ("VDE PN Manager");

			/* Internationalization support */
			Intl.bindtextdomain (Config.GETTEXT_PACKAGE, Config.LOCALEDIR);
			Intl.bind_textdomain_codeset (Config.GETTEXT_PACKAGE, "UTF-8");
			Intl.textdomain (Config.GETTEXT_PACKAGE);

			Gtk.init (ref args);
			Gdk.threads_init ();

			Notify.init ("VDE PN Manager");
			ConfigurationsList mainWindow = new ConfigurationsList ("VDE PN Manager");
			TrayIcon tray = new TrayIcon (mainWindow);
			tray.show ();

			Gdk.threads_enter ();
			Gtk.main ();
			Gdk.threads_leave ();
			Notify.uninit ();
		}
	}
}
