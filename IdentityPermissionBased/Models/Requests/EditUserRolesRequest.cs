using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace IdentityPermissionBased.Models.Requests
{
    public class EditUserRolesRequest
    {
        public string id { get; set; }
        public List<string> roles { get; set; }
    }
}
