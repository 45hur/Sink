using System;
using System.Diagnostics;
using System.IO;
using System.Reflection;
using System.Xml;

namespace Kres.Man
{
    public class Program
    {
        private static readonly log4net.ILog log = log4net.LogManager.GetLogger(MethodBase.GetCurrentMethod().DeclaringType);

        private static void LoadLogConfig()
        {
            var log4netConfig = new XmlDocument();
            log4netConfig.Load(File.OpenRead("log4net.config"));

            var repo = log4net.LogManager.CreateRepository(
                Assembly.GetEntryAssembly(), typeof(log4net.Repository.Hierarchy.Hierarchy));

            log4net.GlobalContext.Properties["pid"] = Process.GetCurrentProcess().Id;

            log4net.Config.XmlConfigurator.Configure(repo, log4netConfig["log4net"]);
        }

        public static void Main(string[] args)
        {
            LoadLogConfig();
            log.Info("Main");

            log.Info("Init cache");
            CacheLiveStorage.CoreCache = new Models.Cache();
            CacheLiveStorage.UdpCache = new System.Collections.Concurrent.ConcurrentDictionary<string, Models.CacheIPRange>();

            log.Info("Run shell script");
            RunScriptIfExists();

            log.Info("Starting UDP Server");
            UdpServer.Listen();

            log.Info("Starting CoreClient Updater");
            CoreClient.Start();

            log.Info("Starting HTTP Listener");
            var listener = new Listener();
            var kresUpdater = new KresUpdater();

            log.Info("Starting Knot-Resolver Updater");
            kresUpdater.Start(listener);

            listener.Listen();


        }

        private static void RunScriptIfExists()
        {
            if (!File.Exists("gencert.sh"))
            {
                log.Info($"Sheel script gencert.sh does not exist.");
                return;
            }

            var psi = new ProcessStartInfo();
            psi.FileName = "sh";
            psi.Arguments = "gencert.sh";
            psi.UseShellExecute = false;
            psi.RedirectStandardOutput = true;
            psi.RedirectStandardError = true;

            Process proc = new Process
            {
                StartInfo = psi
            };

            proc.Start();

            string error = proc.StandardError.ReadToEnd();
            if (!string.IsNullOrEmpty(error))
            {
                log.Error($"Sheel script failed with {error}");
            }

            var output = proc.StandardOutput.ReadToEnd();
            log.Info($"Sheel script output = {output}");
            proc.WaitForExit();
        }
    }
}