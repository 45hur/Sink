using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading;

namespace Kres.Man
{
    class UdpServer
    {
        private static readonly log4net.ILog log = log4net.LogManager.GetLogger(typeof(UdpServer));
        private const int listenPort = 11000;
        private static Thread tUdpLoop;

        private static void ThreadProc()
        {
            bool done = false;

            UdpClient listener = new UdpClient(Configuration.GetUdpPort());
            IPEndPoint groupEP = new IPEndPoint(IPAddress.Any, listenPort);
            try
            {
                while (!done)
                {
                    log.Info("Waiting for broadcast");
                    byte[] bytes = listener.Receive(ref groupEP);
                    var len = Encoding.ASCII.GetString(bytes, 0, bytes.Length);
                    log.Info($"Received broadcast from {groupEP.ToString()} :\n length={len}\n");
                }
            }
            catch (Exception ex)
            {
                log.Error(ex);
            }
            finally
            {
                listener.Close();
                tUdpLoop = null;
                done = true;
            }
        }

        public static int Listen()
        {
            tUdpLoop = new Thread(ThreadProc);
            tUdpLoop.Start();

            while (tUdpLoop != null)
            {
                Thread.Sleep(1000);
            }

            return 0;
        }
    }
}
