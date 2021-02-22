using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace IdentityPermissionBased.Models.Requests
{
    public class EditRolePermissionsRequest
    {
        public string id { get; set; }
        public List<string> claims { get; set; }
    }
}
