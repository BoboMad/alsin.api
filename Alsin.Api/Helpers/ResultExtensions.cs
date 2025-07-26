using Microsoft.AspNetCore.Mvc;

namespace Alsin.Api.Helpers
{
    public static class ResultExtensions
    {
        public static IActionResult OkMessage(this ControllerBase controller, string message)
            => controller.Ok(new { message });

        public static IActionResult CreatedMessage(this ControllerBase controller, string message)
            => controller.Created(string.Empty, new { message });

        public static IActionResult NoContentMessage(this ControllerBase controller, string message)
            => controller.StatusCode(204, new { message });

        public static IActionResult BadRequestMessage(this ControllerBase controller, string message)
            => controller.BadRequest(new { message });

        public static IActionResult UnauthorizedMessage(this ControllerBase controller, string message)
            => controller.Unauthorized(new { message });

        public static IActionResult ForbiddenMessage(this ControllerBase controller, string message)
            => controller.StatusCode(403, new { message });

        public static IActionResult NotFoundMessage(this ControllerBase controller, string message)
            => controller.NotFound(new { message });

        public static IActionResult ConflictMessage(this ControllerBase controller, string message)
            => controller.Conflict(new { message });

        public static IActionResult InternalServerErrorMessage(this ControllerBase controller, string message)
            => controller.StatusCode(500, new { message });
    }
}
