using System;
using System.Collections.Generic;
using System.Threading.Tasks;

using System.Net.NetworkInformation;
using Microsoft.VisualBasic.FileIO;

namespace PingFlood
{
    class Program
    {
        public static IEnumerable<string> LoadDomains(string filename)
        {
            using (var parser = new TextFieldParser(filename))
            {
                parser.TextFieldType = FieldType.Delimited;
                parser.SetDelimiters(",");
                while (!parser.EndOfData)
                {
                    string[] fields = parser.ReadFields();
                    yield return fields[1];
                }
            }
        }

        static void Main(string[] args)
        {
            if (args.Length != 1)
            {
                Console.WriteLine("USAGE: PingFlood.exe list.csv");
                Console.WriteLine("Expected csv content:");
                Console.WriteLine("");
                Console.WriteLine("1, google.com");
                Console.WriteLine("2, facebook.com");

                return;
            }

            var list = LoadDomains(args[0]);
            foreach (var item in list)
            {
                Task.Run(() => 
                {
                    Ping pingSender = new Ping();
                    pingSender.SendAsync(item, null);
                });
            }

            Console.ReadKey();
        }
    }
}
