using Microsoft.AspNetCore.Mvc.ModelBinding;

namespace WebAPI.JWT.Auth.Extensions
{
    public static class ModelStateExtension
    {
        public static List<string> GetErrors(this ModelStateDictionary state)
        {
            // Получить список ошибок
            var errors = state.Values.SelectMany(v => v.Errors)
                                          .Select(e => e.ErrorMessage)
                                          .ToList();

            return errors;
        }
    }
}
