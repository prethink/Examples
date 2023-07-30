using Microsoft.AspNetCore.Identity;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using WebAPI.JWT.Auth.Models;

namespace WebAPI.JWT.Auth.Services
{
    public class JWTHandler
    {
        public const string JWT_NAME        = "name";
        public const string JWT_ROLE        = "role";
        public const string JWT_USER_ID     = "userId";

        private IConfiguration _config;
        public JWTHandler(IConfiguration config)
        {
            _config = config;
        }

        public int RefreshTokenLifeTimeIsRemember       => int.Parse(_config["JWT:RefreshTokenLifeTimeInDaysIsRemebmer"]);
        public int RefreshTokenLifeTimeNotRemember      => int.Parse(_config["JWT:RefreshTokenLifeTimeInDaysNotRemeber"]);
        public int AccessTokenLifeTime                  => int.Parse(_config["JWT:AccessTokenLifeTimeInMinutes"]);
        private string _secret                          => _config["JWT:Secret"];
        private string _audience                        => _config["JWT:Audience"];
        private string _issuer                          => _config["JWT:Issuer"];

        /// <summary>
        /// Получение клаймов на основе пользователя
        /// </summary>
        /// <param name="user"></param>
        /// <param name="userManager"></param>
        /// <returns></returns>
        public async Task<List<Claim>> GetClaimByUser(User user, UserManager<User> userManager)
        {
            var userRoles = await userManager.GetRolesAsync(user);

            var authClaims = new List<Claim>
                {
                    new Claim(JWT_NAME, user.UserName),
                    new Claim(JWT_USER_ID, user.Id),
                    new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
                };

            foreach (var userRole in userRoles)
            {
                authClaims.Add(new Claim(JWT_ROLE, userRole));
            }

            return authClaims;
        }

        /// <summary>
        /// Попытка преобразовать полученные токены в клаймы
        /// </summary>
        /// <param name="token">Токен</param>
        public ClaimsPrincipal? GetClaimDataFromToken(string? token)
        {
            var tokenValidationParameters = new TokenValidationParameters
            {
                ValidateAudience = false,
                ValidateIssuer = false,
                ValidateIssuerSigningKey = true,
                IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_secret)),
                ValidateLifetime = false,
                NameClaimType = JWT_NAME,
                RoleClaimType = JWT_ROLE,

            };
            var tokenHandler = new JwtSecurityTokenHandler();


            var principal = tokenHandler.ValidateToken(token, tokenValidationParameters, out SecurityToken securityToken);
            if (securityToken is not JwtSecurityToken jwtSecurityToken || !jwtSecurityToken.Header.Alg.Equals(SecurityAlgorithms.HmacSha256, StringComparison.InvariantCultureIgnoreCase))
                throw new SecurityTokenException("Invalid token");

            return principal;

        }


        /// <summary>
        /// Генерация токена на основе клаймов
        /// </summary>
        public JwtSecurityToken CreateToken(List<Claim> authClaims)
        {
            var authSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_secret));

            var token = new JwtSecurityToken(
                issuer: _issuer,
                audience: _audience,
                expires: DateTime.Now.Add(TimeSpan.FromMinutes(AccessTokenLifeTime)),
                claims: authClaims,
                signingCredentials: new SigningCredentials(authSigningKey, SecurityAlgorithms.HmacSha256)
                );

            return token;
        }

        /// <summary>
        /// Генерация RefreshToken
        /// </summary>
        public string GenerateRefreshToken()
        {
            var randomNumber = new byte[64];
            using var rng = RandomNumberGenerator.Create();
            rng.GetBytes(randomNumber);
            return Convert.ToBase64String(randomNumber);
        }
    }
}
