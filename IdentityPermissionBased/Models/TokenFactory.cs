using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Identity;
using Microsoft.IdentityModel.Tokens;

namespace IdentityPermissionBased.Models
{
    public class TokenFactory
    {
        public static string GetAccessToken(IdentityUser user, IList<Claim> permissions)
        {
            var claimsData = new List<Claim> { new Claim(type: ClaimTypes.NameIdentifier, user.UserName) };

            //generate Claim permissions
            for (int i = 0; i < permissions.Count; i++)
            {
                claimsData.Add(permissions[i]);
            }

            var access_token = new JwtSecurityToken(
                issuer: AuthOptions.ISSUER,
                audience: AuthOptions.AUDIENCE,
                claims: claimsData,
                expires: DateTime.Now.AddMinutes(AuthOptions.LIFETIME),
                signingCredentials: new SigningCredentials(AuthOptions.GetSymmetricSecurityKey(), SecurityAlgorithms.HmacSha256Signature)
            );

            return new JwtSecurityTokenHandler().WriteToken(access_token);
        }
    }
}
