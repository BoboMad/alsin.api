using System.ComponentModel.DataAnnotations;

namespace Alsin.Api.Controllers.Auth.DTOs
{
    public class RegisterRequestDto
    {
        [Required(ErrorMessage = "First name is required")]
        [StringLength(50, MinimumLength = 2, ErrorMessage = "First name must be between 2 and 50 characters")]
        [RegularExpression(@"^[a-zA-Z\s'-]+$", ErrorMessage = "First name must contain only letters, spaces, hyphens, or apostrophes")]
        public string FirstName { get; set; }

        [Required(ErrorMessage = "Last name is required")]
        [StringLength(50, MinimumLength = 2, ErrorMessage = "Last name must be between 2 and 50 characters")]
        [RegularExpression(@"^[a-zA-Z\s'-]+$", ErrorMessage = "Last name must contain only letters, spaces, hyphens, or apostrophes")]
        public string LastName { get; set; }

        [Required(ErrorMessage = "Email is required")]
        [EmailAddress(ErrorMessage = "Invalid email format")]
        public string Email { get; set; }

        [Required(ErrorMessage = "Password is required")]
        [RegularExpression(@"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$",
        ErrorMessage = "Password must be at least 8 characters, with uppercase, lowercase, number, and special character")]
        public string Password { get; set; }
        [Required(ErrorMessage = "Date of birth is required")]
        [MinimumAge(18, ErrorMessage = "User must be at least 18 years old")]
        public DateTime DateOfBirth { get; set; }
    }

    public class MinimumAgeAttribute : ValidationAttribute
    {
        private readonly int _minimumAge;

        public MinimumAgeAttribute(int minimumAge)
        {
            _minimumAge = minimumAge;
        }

        protected override ValidationResult IsValid(object value, ValidationContext validationContext)
        {
            if (value is DateTime dateOfBirth)
            {
                var today = DateTime.Today;
                var age = today.Year - dateOfBirth.Year;
                if (dateOfBirth > today.AddYears(-age)) age--;
                return age >= _minimumAge
                    ? ValidationResult.Success
                    : new ValidationResult(ErrorMessage);
            }
            return new ValidationResult("Invalid date of birth");
        }
    }
}
