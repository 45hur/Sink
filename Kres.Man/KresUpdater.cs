using System;
using System.Collections.Generic;
using System.Text;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Threading;

namespace Kres.Man
{
    class KresUpdater
    {
        private static readonly log4net.ILog log = log4net.LogManager.GetLogger(typeof(KresUpdater));
        public static Thread tKresLoop;

        public static object Push(string server, string postData)
        {
            log.Info($"Push");
            var list = postData.Split(';');
            log.Info($"Split list = {list.Length}");
            var orderedList = new List<ulong>();
            foreach (var item in list)
            {
                if (item.Length == 0)
                    continue;

                var domain = Encoding.ASCII.GetBytes(item);
                orderedList.Add(Crc64.Compute(0, domain));
            }
            log.Info($"Sorting list");
            orderedList.Sort();

            log.Info($"List sorted, length = {orderedList.Count}");

            var message = new byte[orderedList.Count * 8];
            for (var i = 0; i < orderedList.Count; i++)
            {
                Array.Copy(BitConverter.GetBytes(orderedList[i]), 0, message, i * 8, 8);
            }

            TcpClient client = new TcpClient();
            client.Client.Connect(IPAddress.Parse(server), 8888);

            var messageType = (ulong)0;
            var messageSize = (ulong)message.Length;
            var messageCrc = Crc64.Compute(0, message);

            var header = BitConverter.GetBytes(messageType).Concat(BitConverter.GetBytes(messageSize).Concat(BitConverter.GetBytes(messageCrc)));
            var headerCrc = Crc64.Compute(0, header.ToArray());
            header = header.Concat(BitConverter.GetBytes(headerCrc));

            log.Info($"Get stream");
            using (var stream = client.GetStream())
            {
                var headerBytes = header.ToArray();
                stream.Write(headerBytes, 0, headerBytes.Length);

                log.Info($"Written header");

                var response = new byte[1];
                var bytesRead = stream.Read(response, 0, 1);

                log.Info($"Read header response");
                if (bytesRead == 1 && response[0] == '1')
                {
                    log.Info($"Header understood");

                    stream.Write(message, 0, message.Length);
                    log.Info($"Written message");

                    bytesRead = stream.Read(response, 0, 1);

                    log.Info($"Read message response");
                    if (bytesRead == 1 && response[0] == '1')
                    {

                        log.Info($"Buffer succesfully exchanged and freed.");
                    }
                }

                log.Info($"Closing stream.");
                stream.Flush();
                stream.Close();
            }

            log.Info($"Return.");
            return null;
        }

        private static void ThreadProc()
        {
            log.Info("Starting KresUpdater thread.");

            try
            {
                while (true)
                {
                    Thread.Sleep(60000);
                }
            }
            catch (Exception ex)
            {
                tKresLoop = null;
                log.Fatal($"{ex}");
            }
        }
        public static void Start()
        {
            tKresLoop = new Thread(ThreadProc);
            tKresLoop.Start();
        }
    }
}
