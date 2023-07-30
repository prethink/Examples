using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using WebAPI.JWT.Auth.Data;
using WebAPI.JWT.Auth.Models.DTO;
using WebAPI.JWT.Auth.Models;
using WebAPI.JWT.Auth.Services;
using WebAPI.JWT.Auth.Extensions;

namespace WebAPI.JWT.Auth.Controllers
{
    [Authorize]
    [Route("api/[controller]")]
    [ApiController]
    public class AuthController : ControllerBase
    {
        private readonly AppDbContext _context;
        private readonly UserManager<User> _userManager;
        private readonly RoleManager<IdentityRole> _roleManager;
        private readonly SignInManager<User> _signInManager;
        private readonly JWTHandler _jwt;
        public AuthController(
            AppDbContext context,
            UserManager<User> userManager,
            RoleManager<IdentityRole> roleManager,
            SignInManager<User> signInManager,
            JWTHandler jwt)
        {
            _jwt = jwt;
            _context = context;
            _userManager = userManager;
            _signInManager = signInManager;
            _roleManager = roleManager;
        }

        /// <summary>
        /// Регистрация нового пользователя
        /// </summary>
        /// <param name="model">RegisterDTO</param>
        [AllowAnonymous]
        [HttpPost]
        [Route("register")]
        public async Task<IActionResult> Register([FromBody] RegisterDTO model)
        {
            if(ModelState.IsValid)
            {
                var userExists = await _userManager.FindByNameAsync(model.Username);
                if (userExists != null)
                    return StatusCode(
                        StatusCodes.Status500InternalServerError, 
                        new ErrorResponceDTO { Message = $"Пользователь {model.Username} уже существует!" }
                        );

                User user = new()
                {
                    Id = Guid.NewGuid().ToString(),
                    UserName = model.Username,
                    SecurityStamp = Guid.NewGuid().ToString(),
                };

                var result = await _userManager.CreateAsync(user, model.Password);
                if (!result.Succeeded)
                {
                    return StatusCode(
                        StatusCodes.Status500InternalServerError,
                        new ErrorResponceDTO
                        {
                            Message = "Не удалось создать нового пользователя",
                            Errors = result.Errors.Select(x => x.Description).ToList()
                        });
                }
                if(! await _roleManager.RoleExistsAsync(Constants.ROLE_ADMINISTRATOR))
                {
                    await _roleManager.CreateAsync(new IdentityRole { Name = Constants.ROLE_ADMINISTRATOR });
                }
                await _userManager.AddToRoleAsync(user, Constants.ROLE_ADMINISTRATOR);
                return Ok(new { userId = user.Id });
            }
            else
            {
                var errors = ModelState.GetErrors();
                return StatusCode(StatusCodes.Status500InternalServerError, new ErrorResponceDTO { Message = "Ошибка валидации данных.", Errors = errors });
            }
        }

        /// <summary>
        /// Авторизация пользователя
        /// </summary>
        /// <param name="userLogin">LoginDTO</param>
        [AllowAnonymous]
        [HttpPost]
        [Route("Login")]
        public async Task<IActionResult> Login([FromBody] LoginDTO userLogin)
        {
            if (ModelState.IsValid)
            {
                var user = await _userManager.FindByNameAsync(userLogin.Login);
                if(user == null)
                {
                    return StatusCode(
                          StatusCodes.Status500InternalServerError,
                          new ErrorResponceDTO { Message = $"Пользователь {userLogin.Login} не найденю" }
                          );
                }

                bool resultAuth = await _userManager.CheckPasswordAsync(user, userLogin.Password);
                if(!resultAuth)
                {
                    return StatusCode(
                          StatusCodes.Status500InternalServerError,
                          new ErrorResponceDTO { Message = $"Неправильный логин или пароль." }
                          );
                }

                var claims = await _jwt.GetClaimByUser(user, _userManager);
                var userRoles = await _userManager.GetRolesAsync(user);

                var token = _jwt.CreateToken(claims);
                var refreshToken = _jwt.GenerateRefreshToken();

                int refreshTokenValidityInDays = userLogin.IsRemember ?
                    _jwt.RefreshTokenLifeTimeIsRemember :
                    _jwt.RefreshTokenLifeTimeNotRemember;

                user.RefreshToken = refreshToken;
                user.IsRemember = userLogin.IsRemember;
                user.RefreshTokenExpiryTime = DateTime.Now.AddDays(refreshTokenValidityInDays);

                await _userManager.UpdateAsync(user);

                return Ok(new ResponceTokenDTO
                {
                    UserId = user.Id,
                    UserName = user.UserName,
                    AccessToken = new JwtSecurityTokenHandler().WriteToken(token),
                    RefreshToken = refreshToken,
                });

            }
            else
            {
                var errors = ModelState.GetErrors();
                return StatusCode(StatusCodes.Status500InternalServerError, new ErrorResponceDTO { Message = "Ошибка валидации данных.", Errors = errors });
            }
        }


        [HttpPost]
        [Route("logout")]
        public async Task<IActionResult> LogOut()
        {
            //var accessToken = await HttpContext.Authentication.GetTokenAsync("access_token");
            //var securityTokenHandler = new JwtSecurityTokenHandler();
            //var descriptedToken = securityTokenHandler.ReadJwtToken(accessToken);

            var identity = HttpContext.User.Identity as ClaimsIdentity;
            string username = identity?.Name;

            if (!string.IsNullOrEmpty(username))
            {
                return StatusCode(StatusCodes.Status500InternalServerError);
            }

            var user = await _userManager.FindByNameAsync(username);
            if (user == null)
            {
                return StatusCode(StatusCodes.Status500InternalServerError);
            }

            user.RefreshToken = null;
            await _userManager.UpdateAsync(user);
            return Ok();
        }

        /// <summary>
        /// Обновление токена
        /// </summary>
        /// <param name="tokenModel"></param>
        [AllowAnonymous]
        [HttpPost]
        [Route("refresh-token")]
        public async Task<IActionResult> RefreshToken(TokenValidationDTO tokenModel)
        {
            if(ModelState.IsValid)
            {
                string accessToken = tokenModel.AccessToken;
                string refreshToken = tokenModel.RefreshToken;
                var principal = _jwt.GetClaimDataFromToken(accessToken);
                if (principal == null)
                {
                    return BadRequest("Invalid access token or refresh token");
                }

                string username = principal.Identity.Name;

                var user = await _userManager.FindByNameAsync(username);

                if (user == null || user.RefreshToken != refreshToken || user.RefreshTokenExpiryTime <= DateTime.Now)
                {
                    return BadRequest("Invalid access token or refresh token");
                }
                var claims = await _jwt.GetClaimByUser(user, _userManager);
                var newAccessToken = _jwt.CreateToken(claims);
                var newRefreshToken = _jwt.GenerateRefreshToken();
                int refreshTokenValidityInDays = user.IsRemember ?
                    _jwt.RefreshTokenLifeTimeIsRemember :
                    _jwt.RefreshTokenLifeTimeNotRemember;


                user.RefreshToken = newRefreshToken;
                user.RefreshTokenExpiryTime = DateTime.Now.AddDays(refreshTokenValidityInDays);
                await _userManager.UpdateAsync(user);
                return new ObjectResult(new ResponceTokenDTO
                {
                    UserId = user.Id,
                    UserName = user.UserName,
                    AccessToken = new JwtSecurityTokenHandler().WriteToken(newAccessToken),
                    RefreshToken = newRefreshToken,
                });
            }
            else
            {
                var errors = ModelState.GetErrors();
                return StatusCode(StatusCodes.Status500InternalServerError, new ErrorResponceDTO { Message = "Ошибка валидации данных.", Errors = errors });
            }
        }

        [Authorize(Roles = Constants.ROLE_ADMINISTRATOR)]
        [HttpPost]
        [Route("revoke/{username}")]
        public async Task<IActionResult> Revoke(string username)
        {
            var user = await _userManager.FindByNameAsync(username);
            if (user == null) 
                return BadRequest("Invalid user name");

            user.RefreshToken = null;
            await _userManager.UpdateAsync(user);

            return NoContent();
        }

        [Authorize(Roles = Constants.ROLE_ADMINISTRATOR)]
        [HttpPost]
        [Route("revoke-all")]
        public async Task<IActionResult> RevokeAll()
        {
            var users = _userManager.Users.ToList();
            foreach (var user in users)
            {
                user.RefreshToken = null;
                await _userManager.UpdateAsync(user);
            }

            return Ok();
        }
    }
}
