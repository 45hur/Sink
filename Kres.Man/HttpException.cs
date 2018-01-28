using System;
using System.Collections.Generic;
using System.Net;
using System.Text;

namespace Kres.Man
{
    class HttpException : Exception
    {
        public HttpStatusCode Status { get; internal set; }
        public HttpException(string message, HttpStatusCode status) : base(message)
        {
            this.Status = status;
        }
    }
}
