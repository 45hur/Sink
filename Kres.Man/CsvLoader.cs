using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Linq;
using System.Reflection;
using System.Text;

namespace Kres.Man
{

    internal class CsvLoader
    {
        private static readonly log4net.ILog log = log4net.LogManager.GetLogger(MethodBase.GetCurrentMethod().DeclaringType);

        public static Models.Cache LoadCacheFromCsv()
        {
            var result = new Models.Cache()
            {
                CustomLists = LoadCustomLists(),
                Domains = LoadDomains(),
                IPRanges = LoadIPRanges(),
                Policies = LoadPolicies(),
            };

            return result;
        }

        public static Models.Cache InitCache()
        {
            var result = new Models.Cache();
            return result;
        }

        private static List<Models.CacheCustomList> LoadCustomLists()
        {
            var result = new List<Models.CacheCustomList>();
            var csv = new CsvHelper.CsvReader(File.OpenText("custom.csv"));

            while (csv.Read())
            {
                var item = new Models.CacheCustomList
                {
                    Identity = csv.GetField(0),
                    WhiteList = csv.GetField(1).Split(';'),
                    BlackList = csv.GetField(2).Split(';'),
                    PolicyId = Convert.ToInt32(csv.GetField(3))
                };

                result.Add(item);
            }

            return result;
        }

        private static List<Models.CacheDomain> LoadDomains()
        {
            var result = new List<Models.CacheDomain>();
            var csv = new CsvHelper.CsvReader(File.OpenText("domains.csv"));
            
            while (csv.Read())
            {
                var b0 = Convert.ToInt32(csv.GetField(2));
                var b1 = Convert.ToInt32(csv.GetField(3));
                var b2 = Convert.ToInt32(csv.GetField(4));
                var b3 = Convert.ToInt32(csv.GetField(5));
                var b4 = Convert.ToInt32(csv.GetField(6));
                var b5 = Convert.ToInt32(csv.GetField(7));
                var b6 = Convert.ToInt32(csv.GetField(8));
                var b7 = Convert.ToInt32(csv.GetField(9));
                var b8 = Convert.ToInt32(csv.GetField(10));
                var b9 = Convert.ToInt32(csv.GetField(11));
                var b10 = Convert.ToInt32(csv.GetField(12));
                var b11 = Convert.ToInt32(csv.GetField(13));
                var b12 = Convert.ToInt32(csv.GetField(14));
                var b13 = Convert.ToInt32(csv.GetField(15));
                var b14 = Convert.ToInt32(csv.GetField(16));
                var b15 = Convert.ToInt32(csv.GetField(17));

                var item = new Models.CacheDomain
                {
                    Crc64 = Crc64.Compute(0, ASCIIEncoding.ASCII.GetBytes(csv.GetField(0))),
                    Accuracy = Convert.ToInt32(csv.GetField(1)),
                    Flags =  new [] { b0, b1, b2, b3, b4, b5, b6, b7, b8, b9, b10, b11, b12, b13, b14 }
                };
                result.Add(item);
            }

            return result;
        }

        private static List<Models.CacheIPRange> LoadIPRanges()
        {
            var result = new List<Models.CacheIPRange>();
            var csv = new CsvHelper.CsvReader(File.OpenText("ranges.csv"));

            while (csv.Read())
            {
                var ipfrom = csv.GetField(0);
                IPAddress ipaddrfrom;
                if (!IPAddress.TryParse(ipfrom, out ipaddrfrom))
                {
                    break;
                }

                var ipto = csv.GetField(1);
                IPAddress ipaddrto;
                if (!IPAddress.TryParse(ipfrom, out ipaddrto))
                {
                    break;
                }

                var fromlist = ipaddrfrom.GetAddressBytes().ToList();
                var tolist = ipaddrto.GetAddressBytes().ToList();
                BigMath.Int128 outFrom;
                BigMath.Int128 outTo;
                if (fromlist.Count == 4)
                {
                     outFrom = new BigMath.Int128(BitConverter.ToUInt32(fromlist.Take(4).ToArray(), 0));
                     outTo = new BigMath.Int128(BitConverter.ToUInt32(tolist.Take(4).ToArray(), 0));
                }
                else
                {
                    outFrom = new BigMath.Int128(BitConverter.ToUInt64(tolist.Take(8).ToArray(), 0), BitConverter.ToUInt64(fromlist.Skip(8).Take(8).ToArray(), 0));
                    outTo = new BigMath.Int128(BitConverter.ToUInt64(tolist.Take(8).ToArray(), 0), BitConverter.ToUInt64(tolist.Take(8).ToArray(), 0));
                }


                var item = new Models.CacheIPRange
                {
                    IpFrom = Kres.Man.Models.Int128.Convert(outFrom),
                    IpTo = Kres.Man.Models.Int128.Convert(outTo),
                    Identity = csv.GetField(2),
                    PolicyId = Convert.ToInt32(csv.GetField(3))
                };
                result.Add(item);
            }

            return result;
        }

        private static List<Models.CachePolicy> LoadPolicies()
        {
            var result = new List<Models.CachePolicy>();
            var csv = new CsvHelper.CsvReader(File.OpenText("policy.csv"));

            while (csv.Read())
            {
                var item = new Models.CachePolicy
                {
                    Policy_id = Convert.ToInt32(csv.GetField(0)),
                    Strategy = Convert.ToInt32(csv.GetField(1)),
                    Audit = Convert.ToInt32(csv.GetField(2)),
                    Block = Convert.ToInt32(csv.GetField(3)),
                };
                result.Add(item);
            }

            return result;
        }
    }
}
