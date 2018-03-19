using System;
using System.Collections.Generic;
using System.Net;
using System.Linq;
using System.IO;
using System.Text;



namespace Kres.Man
{

    internal class CsvLoader
    {
        private static readonly log4net.ILog log = log4net.LogManager.GetLogger(typeof(CsvLoader));

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
                var item = new Models.CacheDomain
                {
                    Crc64 = Crc64.Compute(0, ASCIIEncoding.ASCII.GetBytes(csv.GetField(0))),
                    Accuracy = Convert.ToInt32(csv.GetField(1)),
                    Flags = BitConverter.GetBytes(Convert.ToUInt64(csv.GetField(2)))
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
