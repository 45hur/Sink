using System;
using System.Collections.Generic;
using System.Collections.Concurrent;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using System.Text;


using Newtonsoft.Json;

namespace Kres.Man
{
    internal class Listener
    {
        private ConcurrentQueue<string> queue = new ConcurrentQueue<string>();
        private static readonly log4net.ILog log = log4net.LogManager.GetLogger(typeof(Listener));
        private Thread tLoop;

        [Mapping("health")]
        public object getHealthHandler(string postData)
        {
            if ((tLoop == null) || (tLoop != null && !tLoop.IsAlive))
            {
                log.Info($"Health check failed.");

                return new HttpException("Kres.Man is unhealthy.", HttpStatusCode.InternalServerError);
            }

            log.Info($"Health check passed.");

            return null;
        }

        [Mapping("push")]
        public object getPushHandler(string postData, string server)
        {
            log.Info($"Push");
            var list = postData.Split(';');
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
            for(var i = 0; i < orderedList.Count; i++)
            {
                Array.Copy(BitConverter.GetBytes(orderedList[i]), 0, message, i * 8, 8);
            }

            TcpClient client = new TcpClient();
            client.Client.Connect(IPAddress.Parse(server/*Configuration.GetServer()*/), 8888);

            var messageType = (ulong)0;
            var messageSize = (ulong)message.Length;
            var messageCrc = Crc64.Compute(0, message);

            var header = BitConverter.GetBytes(messageType).Concat(BitConverter.GetBytes(messageSize).Concat(BitConverter.GetBytes(messageCrc)));
            var headerCrc = Crc64.Compute(0, header.ToArray());
            header = header.Concat(BitConverter.GetBytes(headerCrc));

            log.Info($"Get stream");
            var stream = client.GetStream();
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
                    stream.Write(message, 0, message.Length);
                }
            }

            return null;
        }

        private static string Base64Decode(string base64EncodedData)
        {
            var base64EncodedBytes = Convert.FromBase64String(base64EncodedData);
            return Encoding.UTF8.GetString(base64EncodedBytes);
        }

        private void ThreadProc()
        {
            log.Info("Starting thread.");

            while (true)
            {
                //log.Info($"Starting loop.");

                Thread.Sleep(Configuration.GetRedeliveryInterval());
            }
        }

        public void Listen()
        {
            try
            {
                tLoop = new Thread(ThreadProc);
                tLoop.Start();

                log.Info($"Starting listener.");
                HttpListener listener = new HttpListener();
                
                listener.Prefixes.Add(Configuration.GetListener());
                listener.Start();
                while (true)
                {
                    log.Info($"Waiting for listener context.");
                    HttpListenerContext ctx = listener.GetContext();

                    ThreadPool.QueueUserWorkItem((_) =>
                    {
                        try
                        {
                            string methodName = ctx.Request.Url.Segments[1].Replace("/", "");
                            string[] strParams = ctx.Request.Url
                                                    .Segments
                                                    .Skip(2)
                                                    .Select(s => s.Replace("/", ""))
                                                    .ToArray();

                            var method = this.GetType()
                                                .GetMethods()
                                                .Where(mi => mi.GetCustomAttributes(true).Any(attr => attr is Mapping && ((Mapping)attr).Map == methodName))
                                                .First();

                            var args = method.GetParameters().Skip(1).Select((p, i) => Convert.ChangeType(strParams[i], p.ParameterType));
                            var @params = new object[args.Count() + 1];

                            var inLength = ctx.Request.ContentLength64;
                            var inBuffer = new byte[inLength];
                            if (ctx.Request.InputStream.Read(inBuffer, 0, inBuffer.Length) != inLength)
                                throw new Exception("Unable to read input stream.");

                            var content = Encoding.UTF8.GetString(inBuffer);
                            @params[0] = content;
                            Array.Copy(args.ToArray(), 0, @params, 1, args.Count());

                            log.Info($"Invoking {method.Name}");
                            try
                            {
                                var ret = method.Invoke(this, @params);
                                var retstr = JsonConvert.SerializeObject(ret);

                                var outBuffer = Encoding.UTF8.GetBytes(retstr);
                                ctx.Response.ContentLength64 = outBuffer.LongLength;
                                ctx.Response.OutputStream.Write(outBuffer, 0, outBuffer.Length);
                                ctx.Response.OutputStream.Close();
                            }
                            catch (HttpException ex)
                            {
                                log.Warn($"{ex}");

                                ctx.Response.StatusCode = (int)ex.Status;
                                ctx.Response.ContentType = "text/plain";

                                var outBuffer = Encoding.UTF8.GetBytes(ex.Message);
                                ctx.Response.ContentLength64 = outBuffer.LongLength;
                                ctx.Response.OutputStream.Write(outBuffer, 0, outBuffer.Length);
                                ctx.Response.OutputStream.Close();
                            }
                        }
                        catch (Exception ex)
                        {
                            log.Error($"{ex}");
                        }
                    });
                }
            }
            catch (Exception ex)
            {
                tLoop = null;

                log.Fatal($"{ex}");
            }
        }
    }
}
