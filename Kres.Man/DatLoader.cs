using System;
using System.Collections.Generic;
using System.Linq;
using System.IO;
using System.Reflection;

using Kres.Man.Models;

namespace Kres.Man
{
    struct DatHeader
    {
        public bufferType message;
        public Int32 count;
        public Int64 crc64;
    }

    public class DatLoader
    {
        private static readonly log4net.ILog log = log4net.LogManager.GetLogger(MethodBase.GetCurrentMethod().DeclaringType);

        protected static List<CacheDomain> domains;

        public static bool Load(string filename)
        {
            try
            {
                domains = new List<CacheDomain>();

                using (var stream = new FileStream(filename, FileMode.Open, FileAccess.Read, FileShare.None))
                {
                    do
                    {
                        var header = ReadHeader(stream);
                        if (header.message == bufferType.swapcache)
                            break;

                        var set = new List<byte[]>();
                        for (var i = 0; i < header.count; i++)
                        {
                            set.Add(ReadMessage(stream));
                        }

                        CreateCache(header, set);
                    } while (true);
                }
            }
            catch (Exception ex)
            {
                log.Error(ex);
                return false;
            }

            return true;
        }

        private static DatHeader ReadHeader(FileStream stream)
        {
            byte[] buffer = new byte[16];
            if (stream.Read(buffer, 0, buffer.Length) != buffer.Length)
                throw new Exception("Unable to read prime header");

            var result = new DatHeader()
            {
                message = (bufferType)BitConverter.ToInt64(buffer, 0),
                count = BitConverter.ToInt32(buffer, 4),
                crc64 = BitConverter.ToInt64(buffer, 8)
            };

            return result;
        }

        private static byte[] ReadMessage(FileStream stream)
        {
            byte[] buffer = new byte[16];
            if (stream.Read(buffer, 0, buffer.Length) != buffer.Length)
                throw new Exception("Unable to read messageheader");

            var length = BitConverter.ToInt64(buffer, 0);
            var crc64 = BitConverter.ToInt64(buffer, 8);
            buffer = new byte[length];
            if (stream.Read(buffer, 0, (int)length) != length)
                throw new Exception("Unable to read message");

            var computedCrc = Crc64.Compute(0, buffer); 

            return buffer;
        }

        private static void CreateCache(DatHeader header, List<byte[]> set)
        {
            switch (header.message)
            {
                case bufferType.domainCrcBuffer:
                    {
                        for (int i = 0; i < set[0].Length; i = i + 8)
                        {
                            domains.Add(new CacheDomain()
                            {
                                Crc64 = BitConverter.ToUInt64(set[0], i)
                            });
                        }
                        break;
                    }
                case bufferType.domainAccuracyBuffer:
                    {
                        for (int i = 0; i < set[0].Length; i = i + 2)
                        {
                            domains[i / 2].Accuracy = BitConverter.ToInt16(set[0], i);
                        }
                        break;
                    }
                case bufferType.domainFlagsBuffer:
                    {
                        for (int i = 0; i < set[0].Length; i = i + 8)
                        {
                            var flags = new List<int>();
                            flags[0] = BitConverter.ToChar(set[0], 0);
                            domains[i / 8].Flags = flags;
                        }
                        break;
                    }
            }
        }
    }
}
