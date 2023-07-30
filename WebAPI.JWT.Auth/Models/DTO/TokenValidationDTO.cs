using System.ComponentModel.DataAnnotations;

namespace WebAPI.JWT.Auth.Models.DTO
{
    public class TokenValidationDTO
    {
        [Required]
        public string AccessToken { get; set; }
        [Required]
        public string RefreshToken { get; set; }
    }
}
