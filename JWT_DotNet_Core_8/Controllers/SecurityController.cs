using JWT_DotNet_Core_8.Extensions;
using JWT_DotNet_Core_8.Models;
using JWT_DotNet_Core_8.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;

namespace JWT_DotNet_Core_8.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class SecurityController : ControllerBase
    {
        private readonly IAppSettingData _appConfig;

        /// <summary>
        /// Initializes a new instance of the <see cref="SecurityController"/> class.
        /// </summary>
        /// <param name="appConfig">The app configuration data.</param>
        public SecurityController(IAppSettingData appConfig)
        {
            _appConfig = appConfig;
        }

        /// <summary>
        /// Generates a JWT token for the provided user.
        /// </summary>
        /// <param name="user">The user for whom the token should be generated.</param>
        /// <returns>A JWT token if the user is valid, otherwise an Unauthorized status code.</returns>
        [AllowAnonymous]
        [HttpPost]
        [Route("/token")]
        public async Task<TokenResponse> Token(LoginModel user)
        {
            TokenResponse response = new TokenResponse();
            try
            {
                if (user.Username == "admin" && user.Password == "admin")
                {                   
                    var authClaims = new List<Claim>
                        {
                            new Claim("Id", Guid.NewGuid().ToString()),
                            new Claim(JwtRegisteredClaimNames.Sub, user.Username),
                            new Claim(JwtRegisteredClaimNames.Email, user.Username),
                            new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
                        };
                    authClaims.Add(new Claim(ClaimTypes.Role, "ADMIN"));
                    authClaims.Add(new Claim(ClaimTypes.Name, user.Username));
                  
                    var token = CreateToken(authClaims);
                    var refreshToken = GenerateRefreshToken();
                    response.AccessToken = new JwtSecurityTokenHandler().WriteToken(token);                      
                    _ = int.TryParse(_appConfig.AppSettingValue("Jwt:RefreshTokenValidityInDays"), out int refreshTokenValidityInDays);
                    response.RefreshToken = refreshToken;
                    response.RefreshTokenExpiryTime = DateTime.Now.AddDays(refreshTokenValidityInDays);
                    response.Message = "Success";
                    //save token details with expiry time to use in refresh token and validate during refresh token concept 
                    return response;

                }
                else
                {
                    response.Message = "fail";
                    return response;
                }
            }
            catch (Exception ex)
            {
                response.Message = "exception";
                return response;
            }
        }
        [HttpPost]
        [Route("refresh-token")]
        public async Task<TokenResponse>  RefreshToken(TokenModel tokenModel)
        {
            TokenResponse response = new TokenResponse();
            if (tokenModel is null)
            {
                response.Message = "Invalid client request";
                return response;
            }

            string? accessToken = tokenModel.AccessToken;
            string? refreshToken = tokenModel.RefreshToken;

            var principal = GetPrincipalFromExpiredToken(accessToken);
            if (principal == null)
            {
                response.Message = "Invalid access token or refresh token";
                return response;                
            }

              string username = principal.Identity.Name;

            //var user = use db validation if username exists or not 

            //if (user == null || user.RefreshToken != refreshToken || user.RefreshTokenExpiryTime <= DateTime.Now)
            //{
            //    return BadRequest("Invalid access token or refresh token");
            //}

            //var newAccessToken = CreateToken(principal.Claims.ToList());
            var token = CreateToken(principal.Claims.ToList());
            var newrefreshToken = GenerateRefreshToken();
            _ = int.TryParse(_appConfig.AppSettingValue("Jwt:RefreshTokenValidityInDays"), out int refreshTokenValidityInDays);
            response.RefreshToken = newrefreshToken;
            response.RefreshTokenExpiryTime = DateTime.Now.AddDays(refreshTokenValidityInDays);
            response.AccessToken = new JwtSecurityTokenHandler().WriteToken(token);

            response.Message = "Success";

            return response;
        }
        private ClaimsPrincipal? GetPrincipalFromExpiredToken(string? token)
        {
            var tokenValidationParameters = new TokenValidationParameters
            {
                ValidateAudience = false,
                ValidateIssuer = false,
                ValidateIssuerSigningKey = true,
                IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_appConfig.AppSettingValue("Jwt:Key"))),
                ValidateLifetime = false
            };

            var tokenHandler = new JwtSecurityTokenHandler();
            var principal = tokenHandler.ValidateToken(token, tokenValidationParameters, out SecurityToken securityToken);
            if (securityToken is not JwtSecurityToken jwtSecurityToken || !jwtSecurityToken.Header.Alg.Equals(SecurityAlgorithms.HmacSha256, StringComparison.InvariantCultureIgnoreCase))
                throw new SecurityTokenException("Invalid token");

            return principal;

        }
        private JwtSecurityToken CreateToken(List<Claim> authClaims)
        {
            var authSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_appConfig.AppSettingValue("Jwt:Key")));
            _ = int.TryParse(_appConfig.AppSettingValue("Jwt:TokenValidityInMinutes"), out int tokenValidityInMinutes);

            var token = new JwtSecurityToken(
                issuer: _appConfig.AppSettingValue("Jwt:Issuer"),
                audience: _appConfig.AppSettingValue("Jwt:Audience"),
                expires: DateTime.Now.AddMinutes(tokenValidityInMinutes),
                claims: authClaims,
                signingCredentials: new SigningCredentials(authSigningKey, SecurityAlgorithms.HmacSha256)
                );

            return token;
        }
        private static string GenerateRefreshToken()
        {
            var randomNumber = new byte[64];
            using var rng = RandomNumberGenerator.Create();
            rng.GetBytes(randomNumber);
            return Convert.ToBase64String(randomNumber);
        }
    }
}
