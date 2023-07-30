using System.ComponentModel.DataAnnotations;

namespace WebAPI.JWT.Auth.Models.DTO
{
    public class RegisterDTO
    {
        [Required]
        public string Username { get; set; }
        [Required]
        public string Password { get; set; }
    }
}
