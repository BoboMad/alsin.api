namespace Alsin.Api.Controllers.Auth.DTOs
{
    public class RegisterRequestDto
    {
            public string Email { get; set; }
            public string Password { get; set; }
            public string FirstName { get; set; }
            public string LastName { get; set; }
            public DateTime DateOfBirth { get; set; }
            public string Country { get; set; }
            public string City { get; set; }
            public string AddressLine { get; set; }
            public string ZipCode { get; set; }
            public string PhoneNumber { get; set; }
    }
}
