using System.ComponentModel.DataAnnotations;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using SecurityAuditDashboard.Core.Entities;
using SecurityAuditDashboard.Core.Interfaces;

namespace SecurityAuditDashboard.Web.Pages.Account;

public class LoginModel : PageModel
{
    private readonly SignInManager<ApplicationUser> _signInManager;
    private readonly ILogger<LoginModel> _logger;
    private readonly ILoginAttemptRepository _loginAttemptRepository;

    public LoginModel(
        SignInManager<ApplicationUser> signInManager,
        ILogger<LoginModel> logger,
        ILoginAttemptRepository loginAttemptRepository)
    {
        _signInManager = signInManager;
        _logger = logger;
        _loginAttemptRepository = loginAttemptRepository;
    }

    [BindProperty]
    public InputModel Input { get; set; } = new();

    public string ReturnUrl { get; set; } = "/";

    [TempData]
    public string ErrorMessage { get; set; } = "";

    public class InputModel
    {
        [Required]
        [EmailAddress]
        public string Email { get; set; } = "";

        [Required]
        [DataType(DataType.Password)]
        public string Password { get; set; } = "";

        [Display(Name = "Remember me?")]
        public bool RememberMe { get; set; }
    }

    public async Task OnGetAsync(string? returnUrl = null)
    {
        if (!string.IsNullOrEmpty(ErrorMessage))
        {
            ModelState.AddModelError(string.Empty, ErrorMessage);
        }

        returnUrl ??= Url.Content("~/");

        // Clear the existing external cookie to ensure a clean login process
        await HttpContext.SignOutAsync(IdentityConstants.ExternalScheme);

        ReturnUrl = returnUrl;
    }

    public async Task<IActionResult> OnPostAsync(string? returnUrl = null)
    {
        returnUrl ??= Url.Content("~/");

        if (ModelState.IsValid)
        {
            // This doesn't count login failures towards account lockout
            // To enable password failures to trigger account lockout, set lockoutOnFailure: true
            var result = await _signInManager.PasswordSignInAsync(Input.Email, Input.Password, Input.RememberMe, lockoutOnFailure: true);
            
            // Log the attempt
            var ipAddress = HttpContext.Connection.RemoteIpAddress?.ToString() ?? "Unknown";
            var userAgent = Request.Headers["User-Agent"].ToString();

            if (result.Succeeded)
            {
                _logger.LogInformation("User logged in.");
                
                // Record successful attempt
                var user = await _signInManager.UserManager.FindByEmailAsync(Input.Email);
                if (user != null)
                {
                    await _loginAttemptRepository.AddAsync(new LoginAttempt
                    {
                        UserId = user.Id,
                        IpAddress = ipAddress,
                        UserAgent = userAgent,
                        Success = true,
                        Timestamp = DateTime.UtcNow
                    });
                }

                return LocalRedirect(returnUrl);
            }
            if (result.RequiresTwoFactor)
            {
                return RedirectToPage("./LoginWith2fa", new { ReturnUrl = returnUrl, RememberMe = Input.RememberMe });
            }
            if (result.IsLockedOut)
            {
                _logger.LogWarning("User account locked out.");
                return RedirectToPage("./Lockout");
            }
            else
            {
                // Record failed attempt
                var user = await _signInManager.UserManager.FindByEmailAsync(Input.Email);
                await _loginAttemptRepository.AddAsync(new LoginAttempt
                {
                    UserId = user?.Id ?? "unknown",
                    IpAddress = ipAddress,
                    UserAgent = userAgent,
                    Success = false,
                    FailureReason = "Invalid credentials",
                    Timestamp = DateTime.UtcNow
                });

                ModelState.AddModelError(string.Empty, "Invalid login attempt.");
                return Page();
            }
        }

        // If we got this far, something failed, redisplay form
        return Page();
    }
}
