using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using LoginRequest = TestAPI.DTOs.LoginRequest;
using RegisterRequest = TestAPI.DTOs.RegisterRequest;

[ApiController]
[Route("api/[controller]")]
public class AuthController : ControllerBase
{
    private readonly UserService _userService;

    public AuthController(UserService userService)
    {
        _userService = userService;
    }

    [HttpPost("register")]
    public async Task<IActionResult> Register(RegisterRequest request)
    {
        IdentityResult result = await _userService.RegisterAsync(request);
        if (result.Succeeded)
        {
            return Ok(new { message = "Registered successfully" });
        }

        return BadRequest(result.Errors);
    }

    [HttpPost("login")]
    public async Task<IActionResult> Login(LoginRequest request)
    {
        string token = await _userService.LoginAsync(request);
        return Ok(new { Token = token });
    }
}