namespace WebAPI.JWT.Auth.Models.DTO
{
    public class ResponceTokenDTO 
    {
        public string UserId { get; set; }
        public string UserName { get; set; }
        public string AccessToken { get; set; }
        public string RefreshToken { get; set; }
    }
}
