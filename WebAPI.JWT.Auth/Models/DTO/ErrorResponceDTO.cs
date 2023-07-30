namespace WebAPI.JWT.Auth.Models.DTO
{
    public class ErrorResponceDTO
    {
        public string Message { get; set; }
        public List<string> Errors { get; set; } = new();
    }
}
