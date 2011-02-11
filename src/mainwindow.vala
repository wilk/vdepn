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

using Gtk;
using GLib.Environment;

namespace VDEPN
{
	public class ConfigurationsList : Gtk.Window
	{
		private VBox main_vbox;
		private Notebook conf_pages;
		private VDEParser conf_holder;
		private List<VDEConfiguration> conf_list;
		private MenuBar main_menu;
		private string prg_files = get_user_config_dir() + "/vdepn";
		private Manager.VDEConnector connections_manager;

		public ConfigurationsList(string caption)
		{
			connections_manager = new Manager.VDEConnector();
			build_menubar();
			try {
				set_icon_from_file(Config.PKGDATADIR + "/share/v2.png");
			}

			catch (Error e) {
				Helper.debug(Helper.TAG_ERROR, "Can't find v2.png image in " + Config.PKGDATADIR + "/share/");
			}

			main_vbox = new VBox(false, 2);
			conf_pages = new Notebook();
			conf_pages.scrollable = true;
			title = caption;
			resize(500,200);
			this.delete_event.connect(
				(a) => {
					Gtk.main_quit();
					return true;
				});

			try {
				conf_holder = new VDEParser(prg_files + "/connections.xml");
			}
			catch (Error e)
			{
				Helper.debug(Helper.TAG_ERROR, "Error while parsing XML file");
			}

			conf_list = conf_holder.get_configurations();
			build_notebook();
			main_vbox.pack_start(main_menu, false, true, 0);
			main_vbox.pack_end(conf_pages, true, true, 0);
			add(main_vbox);
			show_all();
		}

		private void add_notebook_page(VDEConfiguration v) {
			// build a notebook page for each configuration
			int index = conf_list.index(v);
			bool button_status = false;
			Table conf_table = new Table(8, 2, true);
			string conn_name = v.connection_name;
			string conn_machine = v.machine;
			string conn_user = v.user;
			string conn_socket = v.socket_path;
			string conn_ipaddr = v.ip_address;

			Label conn_name_label = new Label("Connection name: ");
			Entry conn_name_entry = new Entry();

			Label machine_label = new Label("VDE Machine: ");
			Entry machine_entry = new Entry();

			Label user_label = new Label("VDE User: ");
			Entry user_entry = new Entry();

			Label socket_label = new Label("Socket path: ");
			Entry socket_entry = new Entry();

			Label ipaddr_label = new Label("TUN Interface IPv4: ");
			Entry ipaddr_entry = new Entry();

			CheckButton button_ssh = new CheckButton.with_label("Use SSH keys");
			CheckButton button_root = new CheckButton.with_label("Needs root");

			button_ssh.active = v.use_keys;
			button_root.active = v.root_required;

			Button activate_connection = get_button(v, out button_status);
			Button save_configuration = new Button.with_label("Save");

			machine_entry.editable = true;
			machine_entry.set_text(conn_machine);

			conn_name_entry.editable = false;
			conn_name_entry.set_text(conn_name);

			user_entry.editable = true;
			user_entry.set_text(conn_user);

			socket_entry.editable = true;
			socket_entry.set_text(conn_socket);

			ipaddr_entry.editable = true;
			ipaddr_entry.set_text(conn_ipaddr);
			conf_table.attach_defaults(conn_name_label, 0, 1, 0, 1);
			conf_table.attach_defaults(conn_name_entry, 1, 2, 0, 1);

			conf_table.attach_defaults(machine_label, 0, 1, 1, 2);
			conf_table.attach_defaults(machine_entry, 1, 2, 1, 2);

			conf_table.attach_defaults(user_label, 0, 1, 2, 3);
			conf_table.attach_defaults(user_entry, 1, 2, 2, 3);

			conf_table.attach_defaults(socket_label, 0, 1, 3, 4);
			conf_table.attach_defaults(socket_entry, 1, 2, 3, 4);

			conf_table.attach_defaults(ipaddr_label, 0, 1, 4, 5);
			conf_table.attach_defaults(ipaddr_entry, 1, 2, 4, 5);

			conf_table.attach_defaults(button_ssh, 0, 1, 5, 6);
			conf_table.attach_defaults(button_root, 1, 2, 5, 6);

			conf_table.attach_defaults(save_configuration, 0, 1, 7, 8);
			conf_table.attach_defaults(activate_connection, 1, 2, 7, 8);

			conf_pages.append_page(conf_table, new Label(conn_name));

			save_configuration.clicked.connect(
				(ev) => {
					VDEConfiguration tmp = conf_list.nth_data(index);
					tmp.update_configuration(socket_entry.text, machine_entry.text,
											 user_entry.text, ipaddr_entry.text,
											 button_root.active, button_ssh.active);
					tmp.store_configuration(conf_holder);
				});

			activate_connection.clicked.connect(
				(ev) => {
					if (button_status == false) {
						// Activate Connection
						try {
							VDEConfiguration tmp = conf_list.nth_data(index);
							Helper.debug(Helper.TAG_DEBUG, "Activated Connection " +
										 tmp.connection_name);
							tmp.update_configuration(socket_entry.get_text(), machine_entry.get_text(),
													 user_entry.get_text(), ipaddr_entry.get_text(),
													 button_root.active, button_ssh.active);
							connections_manager.new_connection(tmp);
							button_status = true;
							activate_connection.label = "Deactivate";
						}
						catch (Manager.ConnectorError e) {
							Dialog error_dialog = new Dialog.with_buttons("Error", this, DialogFlags.MODAL);
							error_dialog.vbox.add(new Label("ERROR WHILE ACTIVATING CONNECTION"));
							error_dialog.vbox.add(new Label(e.message));
							error_dialog.add_button("Close", 0);
							error_dialog.vbox.show_all();
							error_dialog.close.connect(
								(ev) => {
									error_dialog.destroy();
								});
							error_dialog.response.connect(
								(ev, resp) => {
									error_dialog.destroy();
								});
							Helper.debug(Helper.TAG_ERROR, e.message);
							error_dialog.run();
						}
					}
					else {
						// Deactivate Connection
						activate_connection.label = "Activate";
						Helper.debug(Helper.TAG_DEBUG, "Deactivated Connection " + conn_name);
						connections_manager.rm_connection(conn_name);
						button_status = false;
					}
				});
			conf_pages.show_all();
		}

		private void build_notebook() {
			Helper.debug(Helper.TAG_DEBUG, "Creating " + conf_list.length().to_string() + " pages");
			foreach (VDEConfiguration v in conf_list)
				add_notebook_page(v);

			conf_pages.show_all();
			main_vbox.pack_end(conf_pages, true, true, 0);
		}

		private void build_menubar()
		{
			main_menu = new MenuBar();

			// file
			Menu file_menu = new Menu();
			MenuItem file_item = new MenuItem.with_label("File");
			MenuItem new_conn_item = new MenuItem.with_label("New connection");
			MenuItem rm_conn_item = new MenuItem.with_label("Remove connection");
			MenuItem exit_item = new MenuItem.with_label("Exit");
			file_menu.append(new_conn_item);
			file_menu.append(rm_conn_item);
			file_menu.append(new SeparatorMenuItem());
			file_menu.append(exit_item);

			rm_conn_item.activate.connect(
				(ev) => {
					int conn_id = conf_pages.get_current_page();
					if (conn_id < 0) {
						Helper.debug(Helper.TAG_ERROR, "No active page");
						return;
					}
					else {
						Dialog confirm = new Dialog.with_buttons("Connection removal", this, DialogFlags.MODAL);
						confirm.vbox.add(new Label("This cannot be undone!"));
						confirm.add_button("Yes, I'm sure", 0);
						confirm.add_button("Abort", 1);
						confirm.vbox.show_all();
						confirm.close.connect((ev) => { confirm.destroy(); });
						confirm.response.connect(
							(ev, resp) => {
								if (resp == 1)
									confirm.destroy();
								else {
									VDEConfiguration rem = conf_list.nth_data(conn_id);
									Helper.debug(Helper.TAG_DEBUG, "Remove connection " + rem.connection_name);
									conf_holder.update_file(null, rem, true);
									conf_list.remove(rem);
									conf_pages.next_page();
									conf_pages.remove_page(conn_id);
									confirm.destroy();
								}
							});
						confirm.run();
					}
				});


			new_conn_item.activate.connect(
				(ev) => {
					Dialog new_conf_dialog = new Dialog.with_buttons("New Configuration", this, DialogFlags.MODAL);
					Entry new_conf_entry = new Entry();
					new_conf_entry.text = "change";
					new_conf_dialog.vbox.add(new Label("New configuration ID"));
					new_conf_dialog.vbox.add(new_conf_entry);
					new_conf_dialog.add_button("Create", 0);
					new_conf_dialog.add_button("Abort", 1);
					new_conf_dialog.vbox.show_all();
					new_conf_dialog.close.connect(
						(ev) => {
							new_conf_dialog.destroy();
						});
					new_conf_dialog.response.connect(
						(ev, resp) => {
							if (resp == 0) {
								VDEConfiguration new_conf = new VDEConfiguration.with_defaults(new_conf_entry.text);
								Helper.debug(Helper.TAG_DEBUG, "New connection");
								conf_list.append(new_conf);
								add_notebook_page(new_conf);
								new_conf_dialog.destroy();
							}
							else
								new_conf_dialog.destroy();
						});
					new_conf_dialog.run();
				});

			exit_item.activate.connect(
				(ev) => {
					Gtk.main_quit();
				});

			file_item.submenu = file_menu;

			// help
			Menu help_menu = new Menu();
			MenuItem help_item = new MenuItem.with_label("Help");
			MenuItem about_item = new MenuItem.with_label("About");
			help_menu.append(about_item);

			about_item.activate.connect(
				(ev) => {
					AboutDialog about = new AboutDialog();
					about.authors = {"Massimo Gengarelli"};
					about.copyright = "(C) 2011 Massimo Gengarelli";
					about.license = "GPL v3";
					about.program_name = Config.PACKAGE_NAME;
					about.version = Config.PACKAGE_VERSION;
					about.website = "http://git.casafamelica.info/vdepn.git";
					try {
						about.logo = new Gdk.Pixbuf.from_file(Config.PKGDATADIR + "/share/v2_big.png");
					}
					catch (Error e) {
						Helper.debug(Helper.TAG_ERROR, "Error while retrieving logo image");
					}
					about.close.connect(
						(ev) => {
							Helper.debug(Helper.TAG_DEBUG, "Close dialog");
							about.destroy();
						});
					about.response.connect(
						(ev) => {
							Helper.debug(Helper.TAG_DEBUG, "Response (close)");
							about.destroy();
						});
					about.run();
				});

			help_item.submenu = help_menu;

			main_menu.append(file_item);
			main_menu.append(help_item);
		}

		private Button get_button(VDEConfiguration c, out bool status)
		{
			File pidfile = File.new_for_path("/tmp/vdepn-" + c.connection_name + ".pid");
			if (pidfile.query_exists(null)) {
				connections_manager.new_connection_from_pid(c);
				status = true;
				return new Button.with_label("Deactivate");
			}
			else {
				status = false;
				return new Button.with_label("Activate");
			}
		}
	}
}
