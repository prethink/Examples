using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using System.Reflection.Metadata;
using WebAPI.JWT.Auth.Models;

namespace WebAPI.JWT.Auth.Controllers
{
    [Authorize]
    [Route("api/[controller]")]
    [ApiController]
    public class TestController : ControllerBase
    {
        [Authorize(Roles = Constants.ROLE_ADMINISTRATOR)]
        [HttpGet("CheckRoleOne")]
        public async Task<IActionResult> CheckRoleAdmin()
        {
            return Ok();
        }

        [Authorize(Roles = "None")]
        [HttpGet("CheckRoleNone")]
        public async Task<IActionResult> CheckRoleNone()
        {
            return Ok();
        }

        [Authorize(Roles = "None," + Constants.ROLE_ADMINISTRATOR)]
        [HttpGet("CheckRoleNoneAdmin")]
        public async Task<IActionResult> CheckRoleNoneAdmin()
        {
            return Ok();
        }

        [AllowAnonymous]
        [HttpGet("CheckAnonymous")]
        public async Task<IActionResult> CheckAnonymous()
        {
            return Ok();
        }

        [Authorize]
        [HttpGet("CheckAuthorizes")]
        public async Task<IActionResult> CheckAuthorizes()
        {
            return Ok();
        }
    }
}
