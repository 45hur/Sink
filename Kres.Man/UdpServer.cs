using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading;

namespace Kres.Man
{
    internal class UdpServer
    {
        private static readonly log4net.ILog log = log4net.LogManager.GetLogger(typeof(UdpServer));
        private const int listenPort = 11000;
        public static Thread tUdpLoop;

        private static void ThreadProc()
        {
            log.Info("Starting UDP Server thread.");

            UdpClient listener = new UdpClient(Configuration.GetUdpPort());
            IPEndPoint groupEP = new IPEndPoint(IPAddress.Any, listenPort);
            try
            {
                while (true)
                {
                    log.Info("Waiting for broadcast");
                    byte[] bytes = listener.Receive(ref groupEP);
                    var len = Encoding.ASCII.GetString(bytes, 0, bytes.Length);
                    log.Info($"Received broadcast from {groupEP.ToString()} :\n length={len}\n");
                }
            }
            catch (Exception ex)
            {
                log.Fatal(ex);
            }
            finally
            {
                listener.Close();
                tUdpLoop = null;
            }
        }

        public static void Listen()
        {
            tUdpLoop = new Thread(ThreadProc);
            tUdpLoop.Start();
        }
    }
}
