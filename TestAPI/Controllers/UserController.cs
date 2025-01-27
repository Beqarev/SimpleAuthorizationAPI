// Controllers/AuthController.cs

using Microsoft.AspNetCore.Identity.Data;
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
        try
        {
            await _userService.RegisterAsync(request);
            return Ok("Registration successful.");
        }
        catch (Exception ex)
        {
            return BadRequest(ex.Message);
        }
    }

    [HttpPost("login")]
    public async Task<IActionResult> Login(LoginRequest request)
    {
        try
        {
            await _userService.LoginAsync(request);
            return Ok("Login successful.");
        }
        catch (Exception ex)
        {
            return BadRequest(ex.Message);
        }
    }
}