using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using IdentityPermissionBased.Domain;
using IdentityPermissionBased.Models;
using IdentityPermissionBased.Models.Requests;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace IdentityPermissionBased.Controllers
{
    [Route("api/authentication")]
    [ApiController]
    public class AuthenticationController : ControllerBase
    {
        #region Private members
        private readonly UserManager<IdentityUser> userManager;
        private readonly SignInManager<IdentityUser> signInManager;
        private readonly RoleManager<IdentityRole> roleManager;
        private readonly Context context;
        private IdentityResult identityResult;
        private IdentityUser user;
        #endregion

        public AuthenticationController(UserManager<IdentityUser> userManager, SignInManager<IdentityUser> signInManager, RoleManager<IdentityRole> roleManager, Context context)
        {
            this.userManager = userManager;
            this.signInManager = signInManager;
            this.roleManager = roleManager;
            this.context = context;
        }

        // Registration users
        [HttpPost]
        [Route("registration")]
        public async Task<IActionResult> Registration([FromBody] RegistrationRequest request)
        {
            if (ModelState.IsValid)
            {
                user = new IdentityUser()
                {
                    UserName = request.Email,
                    Email = request.Email
                };

                identityResult = await userManager.CreateAsync(user, request.Password);

                if (identityResult.Succeeded)
                {
                    await userManager.AddToRoleAsync(user, "RegisteredUser");

                    return Ok(new { identityResult.Succeeded });
                }
                else
                {
                    return StatusCode(500, new { identityResult.Succeeded });
                }
            }

            return StatusCode(400, new { ModelState.IsValid });
        }

        // Login user
        // POST: api/authentication/token
        [HttpPost("token")]
        public async Task<IActionResult> GetToken([FromBody] AuthenticationRequest request)
        {
            var signInRez = await signInManager.PasswordSignInAsync(request.Email, request.Password, false, false);

            if (signInRez.Succeeded)
            {
                user = await userManager.FindByNameAsync(request.Email);
                var userRoles = await userManager.GetRolesAsync(user);
                var userPermissions = await userManager.GetClaimsAsync(user);// get UserClaims(Permissions)

                IList<IdentityRole> roles = new List<IdentityRole>();
                foreach (var item in userRoles)
                {
                    roles.Add(await roleManager.FindByNameAsync(item));
                }

                IList<Claim> rolePermissions = new List<Claim>();
                foreach (var item in roles)
                {
                    var claims = await roleManager.GetClaimsAsync(item);
                    foreach (var claim in claims)
                    {
                        rolePermissions.Add(claim); // get RoleClaims(Permissions)
                    }
                }
                var permissoins = userPermissions.Union(rolePermissions).ToList();// all permissions (role + user)

                await userManager.RemoveAuthenticationTokenAsync(user, AuthOptions.ISSUER, "RefreshToken");
                var refresh_jwtToken = await userManager.GenerateUserTokenAsync(user, AuthOptions.ISSUER, "RefreshToken");
                await userManager.SetAuthenticationTokenAsync(user, AuthOptions.ISSUER, "RefreshToken", refresh_jwtToken);

                string access_jwtToken = TokenFactory.GetAccessToken(user, permissoins);
               
                return new JsonResult(new { access_jwtToken, refresh_jwtToken });
            }

            return StatusCode(500, new { signInRez.Succeeded });
        }

        // Refresh access_jwtToken
        // POST: api/authentication/refresh-token
        [HttpPost("refresh-token")]
        public async Task<IActionResult> RefreshUserToken([FromBody] string refreshToken)
        {
            var token = await context.UserTokens.FirstOrDefaultAsync(refT => refT.Value == refreshToken);// check if token exists

            if (token != null)
            {
                user = await userManager.FindByIdAsync(token.UserId);

                // new refresh token
                await userManager.RemoveAuthenticationTokenAsync(user, AuthOptions.ISSUER, "RefreshToken");
                var refresh_jwtToken = await userManager.GenerateUserTokenAsync(user, AuthOptions.ISSUER, "RefreshToken");
                await userManager.SetAuthenticationTokenAsync(user, AuthOptions.ISSUER, "RefreshToken", refresh_jwtToken);

                // new access token
                var userRoles = await userManager.GetRolesAsync(user);
                var userPermissions = await userManager.GetClaimsAsync(user);// get UserClaims(Permissions)

                IList<IdentityRole> roles = new List<IdentityRole>();
                foreach (var item in userRoles)
                {
                    roles.Add(await roleManager.FindByNameAsync(item));
                }

                IList<Claim> rolePermissions = new List<Claim>();
                foreach (var item in roles)
                {
                    var claims = await roleManager.GetClaimsAsync(item);
                    foreach (var claim in claims)
                    {
                        rolePermissions.Add(claim); // get RoleClaims(Permissions)
                    }
                }
                var permissoins = userPermissions.Union(rolePermissions).ToList();// all permissions (role + user)

                string access_jwtToken = TokenFactory.GetAccessToken(user, permissoins);


                return new JsonResult(new { access_jwtToken, refresh_jwtToken });
            }

            return NotFound();
        }

    }
}
