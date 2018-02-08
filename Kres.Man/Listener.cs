using System;
using System.Linq;
using System.Collections.Generic;
using System.Net;
using System.Threading;
using System.Text;
using Newtonsoft.Json;

namespace Kres.Man
{
    internal class Listener
    {
        private static readonly log4net.ILog log = log4net.LogManager.GetLogger(typeof(Listener));
        private Thread tLoop;

        [Mapping("health")]
        public object getHealthHandler(string postData)
        {
            if (
                (tLoop == null) || (tLoop != null && !tLoop.IsAlive) ||
                (UdpServer.tUdpLoop == null) || (UdpServer.tUdpLoop != null && !UdpServer.tUdpLoop.IsAlive) ||
                (CoreClient.tCoreLoop == null) || (CoreClient.tCoreLoop != null && !CoreClient.tCoreLoop.IsAlive) ||
                (KresUpdater.tKresLoop == null) || (KresUpdater.tKresLoop != null && !KresUpdater.tKresLoop.IsAlive)
                )
            {
                log.Info($"Health check failed.");
                log.Info($"tLoop = {tLoop}, UdpServer.tUdpLoop = {UdpServer.tUdpLoop}, CoreClient.tCoreLoop = {CoreClient.tCoreLoop}, KresUpdater.tKresLoop = {KresUpdater.tKresLoop}");

                return new HttpException("Kres.Man is unhealthy.", HttpStatusCode.InternalServerError);
            }

            log.Info($"Health check passed.");

            return null;
        }


        [Mapping("pushswapcaches")]
        public object pushSwapCaches(List<byte[]> buffer)
        {
            return KresUpdater.Push(bufferType.swapcache, buffer);
        }

        [Mapping("pushfreecaches")]
        public object pushFreeCaches(List<byte[]> buffer)
        {
            return KresUpdater.Push(bufferType.swapfreebuffers, buffer);
        }

        [Mapping("pushdomaincrcbuffer")]
        public object pushDomainCrcBuffer(List<byte[]> buffer)
        {
            return KresUpdater.Push(bufferType.domainCrcBuffer, buffer); 
        }

        [Mapping("pushdomainaccuracybuffer")]
        public object pushDomainAccuracyBuffer(List<byte[]> buffer)
        {
            return KresUpdater.Push(bufferType.domainAccuracyBuffer, buffer); 
        }

        [Mapping("pushdomainflagsbuffer")]
        public object pushDomainFlagsBuffer(List<byte[]> buffer)
        {
            return KresUpdater.Push(bufferType.domainFlagsBuffer, buffer); 
        }

        [Mapping("pushiprangefrombuffer")]
        public object pushIPRangeFromBuffer(List<byte[]> buffer)
        {
            return KresUpdater.Push(bufferType.iprangeipfrom, buffer);
        }

        [Mapping("pushiprangetobuffer")]
        public object pushIPRangeToBuffer(List<byte[]> buffer)
        {
            return KresUpdater.Push(bufferType.iprangeipto, buffer);
        }

        [Mapping("pushiprangeidentitybuffer")]
        public object pushIPRangeIdentityBuffer(List<byte[]> buffer)
        {
            return KresUpdater.Push(bufferType.iprangeidentity, buffer);
        }

        [Mapping("pushiprangepolicybuffer")]
        public object pushIPRangePolicyBuffer(List<byte[]> buffer)
        {
            return KresUpdater.Push(bufferType.iprangepolicyid, buffer);
        }

        private static string Base64Decode(string base64EncodedData)
        {
            var base64EncodedBytes = Convert.FromBase64String(base64EncodedData);
            return Encoding.UTF8.GetString(base64EncodedBytes);
        }

        private void ThreadProc()
        {
            log.Info("Starting Listener thread.");

            try
            {
                while (true)
                {
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
                                log.Info($"Content len = {inLength}.");
                                var inBuffer = new byte[4096];
                                var buffer = new byte[inLength];
                                int totalBytesRead = 0;
                                int bytesRead = 0;
                                while (true)
                                {
                                    bytesRead = ctx.Request.InputStream.Read(inBuffer, 0, inBuffer.Length);
                                    if (bytesRead == 0 || bytesRead == -1)
                                    {
                                        log.Info($"Nothing to read len = {totalBytesRead}.");
                                        break;
                                    }

                                    Array.Copy(inBuffer, 0, buffer, totalBytesRead, bytesRead);
                                    totalBytesRead += bytesRead;

                                    if (totalBytesRead == inLength)
                                    {
                                        log.Info($"Read finished to read len = {totalBytesRead}.");
                                        break;
                                    }
                                }

                                var content = Encoding.UTF8.GetString(buffer);
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
            }
            catch (Exception ex)
            {
                tLoop = null;

                log.Fatal($"{ex}");
            }
        }
        

        public void Listen()
        {
            tLoop = new Thread(ThreadProc);
            tLoop.Start();

                
        }
    }
}
