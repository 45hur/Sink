using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Reflection;
using System.Threading;
using System.Text;

using Newtonsoft.Json;

namespace Kres.Man
{
    internal class Listener
    {
        private static readonly log4net.ILog log = log4net.LogManager.GetLogger(MethodBase.GetCurrentMethod().DeclaringType);
        private Thread tLoop;
        private static string filename = "";

        //[Mapping("filename")] Disabled for security reasons
        public object setFileHandler(HttpListenerContext ctx, string path)
        {
            filename = path;

            return null;
        }

        [Mapping("health")]
        public object getHealthHandler(HttpListenerContext ctx, string postData)
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
        public object pushSwapCaches(HttpListenerContext ctx, List<byte[]> buffer)
        {
            return KresUpdater.PushHdd(bufferType.swapcache, buffer, filename);
        }

        [Mapping("pushfreecaches")]
        public object pushFreeCaches(HttpListenerContext ctx, List<byte[]> buffer)
        {
            return KresUpdater.PushHdd(bufferType.swapfreebuffers, buffer, filename);
        }

        [Mapping("pushdomaincrcbuffer")]
        public object pushDomainCrcBuffer(HttpListenerContext ctx, List<byte[]> buffer)
        {
            return KresUpdater.PushHdd(bufferType.domainCrcBuffer, buffer, filename); 
        }

        [Mapping("pushdomainaccuracybuffer")]
        public object pushDomainAccuracyBuffer(HttpListenerContext ctx, List<byte[]> buffer)
        {
            return KresUpdater.PushHdd(bufferType.domainAccuracyBuffer, buffer, filename); 
        }

        [Mapping("pushdomainflagsbuffer")]
        public object pushDomainFlagsBuffer(HttpListenerContext ctx, List<byte[]> buffer)
        {
            return KresUpdater.PushHdd(bufferType.domainFlagsBuffer, buffer, filename); 
        }

        [Mapping("pushiprangefrombuffer")]
        public object pushIPRangeFromBuffer(HttpListenerContext ctx, List<byte[]> buffer)
        {
            return KresUpdater.PushHdd(bufferType.iprangeipfrom, buffer, filename);
        }

        [Mapping("pushiprangetobuffer")]
        public object pushIPRangeToBuffer(HttpListenerContext ctx, List<byte[]> buffer)
        {
            return KresUpdater.PushHdd(bufferType.iprangeipto, buffer, filename);
        }

        [Mapping("pushiprangeidentitybuffer")]
        public object pushIPRangeIdentityBuffer(HttpListenerContext ctx, List<byte[]> buffer)
        {
            return KresUpdater.PushHdd(bufferType.iprangeidentity, buffer, filename);
        }

        [Mapping("pushiprangepolicybuffer")]
        public object pushIPRangePolicyBuffer(HttpListenerContext ctx, List<byte[]> buffer)
        {
            return KresUpdater.PushHdd(bufferType.iprangepolicyid, buffer, filename);
        }

        [Mapping("pushpolicyidbuffer")]
        public object pushPolicyIDBuffer(HttpListenerContext ctx, List<byte[]> buffer)
        {
            return KresUpdater.PushHdd(bufferType.policyid, buffer, filename);
        }

        [Mapping("pushpolicystrategybuffer")]
        public object pushPolicyStrategyBuffer(HttpListenerContext ctx, List<byte[]> buffer)
        {
            return KresUpdater.PushHdd(bufferType.policystrategy, buffer, filename);
        }

        [Mapping("pushpolicyauditbuffer")]
        public object pushPolicyAuditBuffer(HttpListenerContext ctx, List<byte[]> buffer)
        {
            return KresUpdater.PushHdd(bufferType.policyaudit, buffer, filename);
        }

        [Mapping("pushpolicyblockbuffer")]
        public object pushPolicyBlockBuffer(HttpListenerContext ctx, List<byte[]> buffer)
        {
            return KresUpdater.PushHdd(bufferType.policyblock, buffer, filename);
        }

        [Mapping("pushcustomlistidentitkbuffer")]
        public object pushCustomListIdentityBuffer(HttpListenerContext ctx, List<byte[]> buffer)
        {
            return KresUpdater.PushHdd(bufferType.identitybuffer, buffer, filename);
        }

        [Mapping("pushcustomlistwhitelistbuffer")]
        public object pushCustomListWhitelistBuffer(HttpListenerContext ctx, List<byte[]> buffer)
        {
            return KresUpdater.PushHdd(bufferType.identitybufferwhitelist, buffer, filename);
        }

        [Mapping("pushcustomlistblacklistbuffer")]
        public object pushCustomListBlacklistBuffer(HttpListenerContext ctx, List<byte[]> buffer)
        {
            return KresUpdater.PushHdd(bufferType.identitybufferblacklist, buffer, filename);
        }

        [Mapping("pushcustomlistblacklistbuffer")]
        public object pushCustomListPolicyIdBuffer(HttpListenerContext ctx, List<byte[]> buffer)
        {
            return KresUpdater.PushHdd(bufferType.identitybufferpolicyid, buffer, filename);
        }

        [Mapping("updatenow")]
        public object UpdateNow(HttpListenerContext ctx, string postdata)
        {
            KresUpdater.UpdateNow();
            return 0;
        }

        [Mapping("pushloadfile")]
        public object pushLoadFileFromBuffer(HttpListenerContext ctx, List<byte[]> buffer)
        {
            return KresUpdater.PushTcp(bufferType.loadfile, buffer);
        }

        private void ThreadProc()
        {
            log.Info("Starting Listener thread.");

            if (string.IsNullOrEmpty(Configuration.GetListener()))
            {
                log.Info("listener (configuration) not set, Listener thread exiting.");
                return;
            }

            try
            {
                while (true)
                {
                    var prefix = Configuration.GetListener();
                    log.Info($"Starting listener {prefix}");
                    HttpListener listener = new HttpListener();
                    
                    listener.Prefixes.Add(prefix);
                    listener.Start();
                    while (true)
                    {
                        //log.Info($"Waiting for listener context.");
                        HttpListenerContext ctx = listener.GetContext();

                        ThreadPool.QueueUserWorkItem((_) =>
                        {
                            try
                            {
                                log.Info($"RemoteEndPoint = {ctx.Request.RemoteEndPoint.ToString()}");

                                string methodName = ctx.Request.Url.Segments[1].Replace("/", "");
                                string[] strParams = ctx.Request.Url
                                                        .Segments
                                                        .Skip(2)
                                                        .Select(s => s.Replace("/", ""))
                                                        .ToArray();

                                MethodInfo method = null;

                                try
                                {
                                    method = this.GetType()
                                                        .GetMethods()
                                                        .Where(mi => mi.GetCustomAttributes(true).Any(attr => attr is Mapping && ((Mapping)attr).Map == methodName))
                                                        .First();
                                }
                                catch (Exception ex)
                                {
                                    ctx.Response.OutputStream.Close();

                                    return;
                                }

                                var args = method.GetParameters().Skip(2).Select((p, i) => Convert.ChangeType(strParams[i], p.ParameterType));
                                var @params = new object[args.Count() + 2];

                                var inLength = ctx.Request.ContentLength64;
                                //log.Info($"Content len = {inLength}.");
                                
                                var inBuffer = new byte[4096];
                                var buffer = new byte[inLength];
                                int totalBytesRead = 0;
                                int bytesRead = 0;
                                while (true)
                                {
                                    bytesRead = ctx.Request.InputStream.Read(inBuffer, 0, inBuffer.Length);
                                    if (bytesRead == 0 || bytesRead == -1)
                                    {
                                        //log.Info($"Nothing to read len = {totalBytesRead}.");
                                        break;
                                    }

                                    Array.Copy(inBuffer, 0, buffer, totalBytesRead, bytesRead);
                                    totalBytesRead += bytesRead;

                                    if (totalBytesRead == inLength)
                                    {
                                        //log.Info($"Read finished to read len = {totalBytesRead}.");
                                        break;
                                    }
                                }

                                @params[0] = ctx;
                                @params[1] = Encoding.UTF8.GetString(buffer);
                                Array.Copy(args.ToArray(), 0, @params, 2, args.Count());

                                log.Info($"Invoking {method.Name}");
                                try
                                {
                                    var ret = method.Invoke(this, @params) as string;

                                    var outBuffer = Encoding.UTF8.GetBytes(ret);
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
                                log.Error($"Unable to process request {ctx.Request.Url}, ex: {ex.Message}");
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
