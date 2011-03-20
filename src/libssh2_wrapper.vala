namespace VDEPN.Libssh
{
	public class Wrapper
	{
		public static extern bool set_ssh_pass (string user, string host, string pass, string cmd_pubkey);
	}
}
