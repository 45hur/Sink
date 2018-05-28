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
    internal class PublicListener
    {
        private static readonly log4net.ILog log = log4net.LogManager.GetLogger(MethodBase.GetCurrentMethod().DeclaringType);
        private Thread tLoop;

        [PublicMapping("passthrough")]
        public object PassThrough(HttpListenerContext ctx, string postdata)
        {
            using (var file = File.OpenRead(@"Web/sinkit.en.html"))
            {
                using (var reader = new StreamReader(file))
                {
                    var url = ctx.Request.Url;
                    var encodedUrl = Base64Encode(url.ToString());
                    var ipaddress = ctx.Request.RemoteEndPoint.Address.ToString();
                    var content = reader.ReadToEnd();

                    content = content.Replace("{$targetUrl}", $"{url.Host} from {ipaddress}");
                    content = content.Replace("{$url}", $"{url.ToString()}");
                    content = content.Replace("{$authToken}", $"BFLMPSVZ");
                    content = content.Replace("{$ipToBypass}", ipaddress);
                    content = content.Replace("{$domainToWhitelist}", url.Host);
                    content = content.Replace("{$redirectUrl}", encodedUrl);

                    return content;
                }
            }
        }

        [PublicMapping("bypass")]
        public object Bypass(HttpListenerContext ctx, string postdata, string clientIpAddress, string domainToWhitelist, string authToken, string base64encodedUrlToRedirectTo)
        {
            string identity = clientIpAddress.GetHashCode().ToString("X");

            IPAddress ip;
            if (!IPAddress.TryParse(clientIpAddress, out ip))
            {
                return new Exception($"unable to parse ip address {clientIpAddress}.");
            }

            var bytes = ip.GetAddressBytes();
            BigMath.Int128 intip;
            if (bytes.Length == 4)
            {
                intip = new BigMath.Int128(0, BitConverter.ToUInt32(bytes, 0));
            }
            else if (bytes.Length == 16)
            {
                intip = new BigMath.Int128(BitConverter.ToUInt64(bytes, 0), BitConverter.ToUInt64(bytes, 8));
            }
            else
            {
                return new Exception($"unable to parse ip address {clientIpAddress}.");
            }

            List<Models.CacheIPRange> ipranges;
            List<Models.CacheCustomList> customlists;
            if (CacheLiveStorage.CoreCache.IPRanges != null)
            {
                ipranges = CacheLiveStorage.CoreCache.IPRanges.ToList();
            }
            else
            {
                ipranges = new List<Models.CacheIPRange>();
            }

            if (CacheLiveStorage.CoreCache.IPRanges != null)
            {
                customlists = CacheLiveStorage.CoreCache.CustomLists.ToList();
            }
            else
            {
                customlists = new List<Models.CacheCustomList>();
            }

           
            ipranges.Add(new Models.CacheIPRange()
            {
                Identity = identity,
                Proto_IpFrom = Encoding.ASCII.GetBytes(intip.ToString()),
                Proto_IpTo = Encoding.ASCII.GetBytes(intip.ToString()),
                PolicyId = 0
            });
            var item = customlists.FirstOrDefault(t => string.Compare(t.Identity, identity, StringComparison.OrdinalIgnoreCase) == 0);
            if (item == null)
            {
                item = new Models.CacheCustomList()
                {
                    Identity = identity,
                    WhiteList = new List<string>() { domainToWhitelist },
                    BlackList = new List<string>(),
                    PolicyId = 0
                };
            }
            else
            {
                if (item.WhiteList.Contains(domainToWhitelist))
                {
                    log.Info($"Identity {identity} has {domainToWhitelist} already whitelisted.");

                    var redirectTo = Base64Decode(base64encodedUrlToRedirectTo);
                    log.Debug($"Redirecting to {redirectTo}");
                    ctx.Response.RedirectLocation = redirectTo;
                    ctx.Response.StatusCode = 302;

                    return null;
                }

                var list = item.WhiteList.ToList();
                list.Add(domainToWhitelist);
                item.WhiteList = list;
            }
            customlists.RemoveAll(t => string.Compare(t.Identity, identity, StringComparison.OrdinalIgnoreCase) == 0);
            customlists.Add(item);

            log.Info($"Identity {identity} now has {domainToWhitelist} whitelisted.");

            CacheLiveStorage.CoreCache.IPRanges = ipranges;
            CacheLiveStorage.CoreCache.CustomLists = customlists;

            log.Info($"Updating kres modules.");
            KresUpdater.UpdateNow();
            log.Info($"Kres modules have been updated.");

            var redirectUrl = Base64Decode(base64encodedUrlToRedirectTo);
            log.Debug($"Redirecting to {redirectUrl}");
            ctx.Response.RedirectLocation = redirectUrl;
            ctx.Response.StatusCode = 302;

            return null;
        }

        private static string Base64Decode(string base64EncodedData)
        {
            var base64EncodedBytes = Convert.FromBase64String(base64EncodedData);
            return Encoding.UTF8.GetString(base64EncodedBytes);
        }

        private static string Base64Encode(string data)
        {
            var bytes = Encoding.UTF8.GetBytes(data);
            return Convert.ToBase64String(bytes);
        }


        private void ThreadProc()
        {
            log.Info("Starting PublicListener thread.");

            using (var sr = new StreamReader("publiclistenerconfig.json"))
            {
                var views = JsonConvert.DeserializeObject<Models.PublicListenerConfig>(sr.ReadToEnd());
            }

            try
            {
                while (true)
                {
                    var prefix = Configuration.GetPublicListener();
                    var prefixs = Configuration.GetPublicListenerS();
                    log.Info($"Starting PublicListener listener {prefix}.");
                    var listener = new HttpListener();

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

                                method = this.GetType()
                                                    .GetMethods()
                                                    .Where(mi => mi.GetCustomAttributes(true).Any(attr => attr is PublicMapping && ((PublicMapping)attr).Map == methodName))
                                                    .First();

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

                                    if (ret != null)
                                    {
                                        var outBuffer = Encoding.UTF8.GetBytes(ret);
                                        ctx.Response.ContentLength64 = outBuffer.LongLength;
                                        ctx.Response.OutputStream.Write(outBuffer, 0, outBuffer.Length);
                                    }

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
                                // log.Error($"{ex}");

                                try
                                {
                                    var ret = PassThrough(ctx, null) as string;

                                    var outBuffer = Encoding.UTF8.GetBytes(ret);
                                    ctx.Response.ContentLength64 = outBuffer.LongLength;
                                    ctx.Response.OutputStream.Write(outBuffer, 0, outBuffer.Length);
                                    ctx.Response.OutputStream.Close();
                                }
                                catch (Exception ex2)
                                {
                                    log.Error($"{ex2}");
                                }
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
