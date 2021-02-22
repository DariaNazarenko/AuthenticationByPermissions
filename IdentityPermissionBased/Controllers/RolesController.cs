using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using IdentityPermissionBased.Domain;
using IdentityPermissionBased.Models.Requests;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;

namespace IdentityPermissionBased.Controllers
{
    [Route("api/roles")]
    [ApiController]
    public class RolesController : ControllerBase
    {
        #region Private members
        private readonly RoleManager<IdentityRole> roleManager;
        private readonly UserManager<IdentityUser> userManager;
        private readonly Context context;
        private IdentityUser user;
        #endregion

        private enum Roles
        {
            Admin,
            SuperUser,
            RegisteredUser
        }
        private enum Permissoins
        {
            Read,
            WriteNew,
            Edit,
            Delete,
            Work_with_users
        }

        public RolesController(RoleManager<IdentityRole> roleManager, UserManager<IdentityUser> userManager, Context context)
        {
            this.roleManager = roleManager;
            this.userManager = userManager;
            this.context = context;
        }

        [HttpGet("allRoles")]
        [HttpGet]
        public IEnumerable<IdentityRole> GetRoles()
        {
            return roleManager.Roles.ToList();
        }

        [HttpPut("editUserRoles")]
        public async Task<IActionResult> Edit([FromBody] EditUserRolesRequest request)
        {
            // never remove role RegisteredUser ??
            request.roles.Add("RegisteredUser");

            // check wether roles from request are appropriate 
            bool check = true;
            foreach (var item in request.roles)
            {
                if (!Enum.IsDefined(typeof(Roles), item))
                {
                    check = false;
                }
            }

            if (check)
            {
                // get the user
                user = await userManager.FindByIdAsync(request.id);

                if (user != null)
                {
                    // get the list of user`s roles
                    var userRoles = await userManager.GetRolesAsync(user);
                    // get the list of user`s roles which were added
                    var addedRoles = request.roles.Except(userRoles);
                    // get the list of user`s roles which were deleted
                    var removedRoles = userRoles.Except(request.roles);

                    await userManager.AddToRolesAsync(user, addedRoles);

                    await userManager.RemoveFromRolesAsync(user, removedRoles);

                    return Ok();
                }
                else
                {
                    return NotFound();
                }
            }
            else
            {
                return BadRequest("Invalid role");
            }
        }

        [HttpPut("editUserPermissions")]
        public async Task<IActionResult> EditUserPermissions([FromBody] EditUserPermissionsRequest request)
        {
            bool check = true;

            // check wether permissions from request are appropriate 
            foreach (var item in request.claims)
            {
                if (!Enum.IsDefined(typeof(Permissoins), item))
                {
                    check = false;
                }
            }

            if (check)
            {
                user = await userManager.FindByIdAsync(request.id);

                if (user != null)
                {
                    // get the list of user`s permissions
                    var userClaims = await userManager.GetClaimsAsync(user);
                    List<string> userClaimsValue = new List<string>();
                    foreach (var item in userClaims)
                    {
                        userClaimsValue.Add(item.Value);
                    }

                    // get the list of user`s permissions which were added
                    var addedClaimsValue = request.claims.Except(userClaimsValue).ToList();
                    // get the list of user`s permissions which were deleted
                    var removedClaimsValue = userClaimsValue.Except(request.claims).ToList();

                    var addedClaims = new List<Claim>();
                    for (int i = 0; i < addedClaimsValue.Count; i++)
                    {
                        addedClaims.Add(new Claim(type: "Permission", addedClaimsValue[i]));
                    }

                    var removedClaims = new List<Claim>();
                    for (int i = 0; i < removedClaimsValue.Count; i++)
                    {
                        removedClaims.Add(new Claim(type: "Permission", removedClaimsValue[i]));
                    }

                    await userManager.AddClaimsAsync(user, addedClaims);
                    await userManager.RemoveClaimsAsync(user, removedClaims);

                    return Ok();
                }

                return NotFound();
            }
            else
            {
                return BadRequest("Invalid permission");
            }
        }










        [HttpPost("createRole")]
        public async Task<IActionResult> CreateRole([FromBody] string name)
        {
            if (!string.IsNullOrEmpty(name))
            {
                IdentityResult result = await roleManager.CreateAsync(new IdentityRole(name));
                if (result.Succeeded)
                {
                    return new JsonResult(200);
                }
                else
                {
                    return new JsonResult(500);
                }
            }
            return BadRequest("wrong request");
        }


        [HttpPost("addPermissionForRole")]
        public async Task<IActionResult> AddPermissionForRole([FromBody] EditRolePermissionsRequest request)
        {
            bool check = true;
            foreach (var item in request.claims)
            {
                if (!Enum.IsDefined(typeof(Permissoins), item))
                {
                    check = false;
                }
            }

            if (check)
            {
                // get the role
                var role = await roleManager.FindByIdAsync(request.id);

                if (role != null)
                {
                    var claims = new List<Claim>();
                    for (int i = 0; i < request.claims.Count; i++)
                    {
                        claims.Add(new Claim(type: "Permission", request.claims[i]));
                    }

                    foreach (var item in claims)
                    {
                        await roleManager.AddClaimAsync(role, item);
                    }

                    return Ok();
                }

                return NotFound();
            }
            else
                return BadRequest("Invallid permission");
        }
    }
}
