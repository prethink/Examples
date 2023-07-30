using Microsoft.AspNetCore.Identity;

namespace WebAPI.JWT.Auth.Models
{
    public class User : IdentityUser<string>
    {
        /// <summary>
        /// 
        /// </summary>
        public string? RefreshToken { get; set; }

        /// <summary>
        /// 
        /// </summary>
        public DateTime? RefreshTokenExpiryTime { get; set; }

        /// <summary>
        /// 
        /// </summary>
        public bool IsRemember { get; set; }
    }
}
