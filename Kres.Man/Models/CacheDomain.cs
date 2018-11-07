using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.Serialization;
using System.Text;

using ProtoBuf;

namespace Kres.Man.Models
{
    [ProtoContract]
    [DataContract]
    public class CacheDomain
    {
        [ProtoMember(1)]
        [DataMember]
        public IEnumerable<byte> Proto_Crc64 { get; set; }

        [ProtoMember(2)]
        [DataMember]
        public int Accuracy { get; set; }

        [ProtoMember(3)]
        [DataMember]
        public IEnumerable<int> Flags { get; set; }

        public UInt64 Crc64
        {
            get
            {
                //return Convert.ToUInt64(Proto_Crc64.SelectMany(BitConverter.GetBytes).ToArray());
                var text = Encoding.ASCII.GetString(Proto_Crc64.ToArray());
                return Convert.ToUInt64(text);
            }
            set
            {
                //Proto_Crc64 = new[] { 0 }; 
                Proto_Crc64 = BitConverter.GetBytes(value);
            }
        }
    }
}
