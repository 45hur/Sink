using System;
using System.IO;

namespace Kres.Man
{
    internal class FileHelper
    {
        internal static string GetContent(string filename)
        {
            using (var fs = new FileStream(filename, FileMode.Open, FileAccess.Read))
            using (var streamReader = new StreamReader(fs, true))
            {
                return streamReader.ReadToEnd();
            }
        }
    }
}