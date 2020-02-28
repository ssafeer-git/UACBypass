using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace Toolkit
{
    class BlackListedHashes
    {
        public string ProgramName { get; set; }
        public string SHA256Hash { get; set; }

        public BlackListedHashes(string program,string hash)
        {
            this.ProgramName = program;
            this.SHA256Hash = hash;
        }
    }
}
