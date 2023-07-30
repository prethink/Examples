using System.ComponentModel.DataAnnotations;

namespace WebAPI.JWT.Auth.Models.DTO
{
    public class LoginDTO
    {
        [Required]
        public string Login { get; set; }
        [Required]
        public string Password { get; set; }
        [Required]
        public bool IsRemember { get; set; }
    }
}
