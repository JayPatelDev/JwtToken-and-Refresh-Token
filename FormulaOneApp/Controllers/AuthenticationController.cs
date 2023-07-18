using FormulaOneApp.Configurations;
using FormulaOneApp.Data;
using FormulaOneApp.Models;
using FormulaOneApp.Models.DTOs;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Configuration.UserSecrets;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using RestSharp;
using RestSharp.Authenticators;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace FormulaOneApp.Controllers
{
    [Route(template:"api/[controller]")] //api/authentication
    [ApiController]
    public class AuthenticationController : ControllerBase
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly IConfiguration _configuration;
        private readonly IOptions<JwtConfig> _jwtConfig;
        private readonly AppDbContext _context;
        private readonly TokenValidationParameters _tokenValidationParameters;

        public AuthenticationController(UserManager<ApplicationUser> userManager, IConfiguration configuration, IOptions<JwtConfig> jwtConfig, AppDbContext context, TokenValidationParameters tokenValidationParameters)
        {
            _context = context;
            _userManager = userManager;
            _configuration = configuration;
            _jwtConfig = jwtConfig;
            _tokenValidationParameters = tokenValidationParameters;
        }

        [HttpPost]
        [Route(template:"Register")]
        public async Task<IActionResult> Register([FromBody] UserRegistrationRequestDto requestDto)
        {
            // validate the incoming request
            if(ModelState.IsValid)
            {
                //Checking if the email already exist
                var user_exist = await _userManager.FindByEmailAsync(requestDto.Email);

                if (user_exist != null) 
                {
                    return BadRequest(error: new AuthResult()
                    {
                        Result = false,
                        Errors = new List<string>()
                        {
                            "Email already exist"
                        }
                    });
                }

                //create a user
                var new_user = new ApplicationUser()
                {
                    Email = requestDto.Email,
                    UserName = requestDto.Email,
                    EmailConfirmed = false
                };

                //var is_created = await _userManager.CreateAsync(new_user, requestDto.Password);
                var is_created = await _userManager.CreateAsync(new_user, requestDto.Password);

                if (is_created.Succeeded)
                {
                    var code = await _userManager.GenerateEmailConfirmationTokenAsync(new_user);

                    var email_body = $"Please confirm your email address <a href=\"#URL#\">Click here</a>";

                    // https://localhost:8080/authentication/verifyemail/userid=asda&code=dasdaa
                    var callback_url = Request.Scheme + "://" + Request.Host + Url.Action("ConfirmEmail", controller: "Authentication",
                        values: new { userId = new_user.Id, code = code });

                    var body = email_body.Replace(oldValue: "#URL#",
                        newValue: callback_url);

                    //Send Email
                    var result = SendEmail(body, new_user.Email);

                    if (result)
                        return Ok("Please verify your email, through verification email that we have send");

                    return Ok("Please request an email verification link");

                    //Generate the token
                    //var token = GenerateJwtToken(new_user);

                    //return Ok(new AuthResult()
                    //{
                    //    Result = true,
                    //    Token = token
                    //});
                }

                return BadRequest(error: new AuthResult()
                {
                    Errors = new List<string>()
                    {
                        "Server error"
                    },
                    Result = false
                });
            }

            return BadRequest();
        }

        [Route(template:"ConfirmEmail")]
        [HttpGet]
        public async Task<IActionResult> ConfirmEmail(string userId, string code)
        {
            if(userId == null || code == null)
            {
                return BadRequest(new AuthResult()
                {
                    Errors = new List<string>()
                    {
                        "Invalid email confirmation url"
                    }
                });
            }
            var user = await _userManager.FindByIdAsync(userId);

            if (user == null)
            {
                return BadRequest(new AuthResult()
                {
                    Errors = new List<string>()
                    {
                        "Invalid email paramters"
                    }
                });
            }

           // code = Encoding.UTF8.GetString(Convert.FromBase64String(code));

            var result = await _userManager.ConfirmEmailAsync(user, code);
            var status = result.Succeeded
                ? "Thankyou for confirming your email"
                : "Your email is not confirmed please try again later";
            return Ok(status);
        }

        [HttpPost]
        [Route(template:"Login")]
        public async Task<IActionResult> Login([FromBody] UserLoginRequestDto loginRequest)
        {
            if(ModelState.IsValid)
            {
                //check if the user exists
                var existing_user = await _userManager.FindByEmailAsync(loginRequest.Email);

                if (existing_user == null)
                    return BadRequest(error: new AuthResult()
                    {
                        Errors = new List<string>()
                        {
                            "Invalid payload"
                        },
                        Result = false
                    });

                if(!existing_user.EmailConfirmed)
                    return BadRequest(error: new AuthResult()
                    {
                        Errors = new List<string>()
                        {
                            "Email needs to be confirmed"
                        },
                        Result = false
                    });

                var isCorrect = await _userManager.CheckPasswordAsync(existing_user, loginRequest.Password);

                if (!isCorrect)
                    return BadRequest(error: new AuthResult()
                    {
                        Errors = new List<string>()
                        {
                            "Invalid credentials"
                        },
                        Result = false
                    });

                var jwtToken = await GenerateJwtToken(existing_user);

                return Ok(jwtToken);
            }

            return BadRequest(error: new AuthResult()
            { 
                Errors = new List<string>()
                {
                    "Invalid payload"
                },
                Result = false
            });
        }

        [HttpPost]
        [Route(template:"RefreshToken")]
        public async Task<IActionResult> RefereshToken([FromBody] TokenRequest tokenRequest)
        {
            if(ModelState.IsValid)
            {
                var result = VerifyAndGenerateToken(tokenRequest);

                if(result == null)
                    return BadRequest(new AuthResult()
                    {
                        Errors = new List<string>()
                        {
                            "Invalid Parameters"
                        },

                        Result = false
                    });

                return Ok(new AuthResult()
                {
                    Token = result.Result.Token,
                    RefreshToken = result.Result.RefreshToken,
                    Result= true
                });
            }

            return BadRequest(new AuthResult()
            {
                Errors = new List<string>()
                {
                    "Invalid Parameters"
                },
                Result = false
                
            });
        }

        private async Task<AuthResult> GenerateJwtToken(ApplicationUser user)
        {
            var jwtTokenHandler = new JwtSecurityTokenHandler();

            var key = Encoding.UTF8.GetBytes(_jwtConfig.Value.Secret /*_configuration.GetSection(key: "JwtConfig:Secret").Value*/);

            //Token Descriptor
            var tokenDescriptor = new SecurityTokenDescriptor()
            {
                Subject = new ClaimsIdentity(new[]
                {
                    new Claim(type:"Id", value:user.Id),
                    new Claim(type:JwtRegisteredClaimNames.Sub,value:user.Email),
                    new Claim(type:JwtRegisteredClaimNames.Email,value:user.Email),
                    new Claim(type:JwtRegisteredClaimNames.Jti, value:Guid.NewGuid().ToString()),
                    new Claim(type:JwtRegisteredClaimNames.Iat, value:DateTime.Now.ToUniversalTime().ToString())
                }),

                Expires = DateTime.UtcNow.Add(TimeSpan.Parse(_jwtConfig.Value.ExpiryTimeFrame.ToString())),// Set expiration time (e.g., 1 hour from now)
                NotBefore = DateTime.UtcNow, // Set the token as valid starting from the current time
                SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(key), algorithm:SecurityAlgorithms.HmacSha256)
            };

            var token = jwtTokenHandler.CreateToken(tokenDescriptor);
            var jwtToken = jwtTokenHandler.WriteToken(token);

            var refrehToken = new RefreshToken()
            {
                JwtId = token.Id,
                Token = RandomStringGeneration(23),// Generate a refresh token
                AddedDate = DateTime.UtcNow,
                ExpriyDate = DateTime.UtcNow.AddMonths(6),
                IsRevoked = false,
                IsUsed = false,
                UserId = user.Id
            };

            await _context.RefreshTokens.AddAsync(refrehToken);
            await _context.SaveChangesAsync();
            return new AuthResult()
            {
                Token = jwtToken,
                RefreshToken = refrehToken.Token,
                Result = true
            };
        }
        
        private async Task<AuthResult> VerifyAndGenerateToken(TokenRequest tokenRequest)
        {
            var jwtTokenHandler = new JwtSecurityTokenHandler();

            try
            {
                _tokenValidationParameters.ValidateLifetime = false; //for testing 

                var tokenInVerification = jwtTokenHandler.ValidateToken(tokenRequest.Token, _tokenValidationParameters, out var validedToken);
                if (validedToken is JwtSecurityToken jwtSecurityToken)
                {
                    var result = jwtSecurityToken.Header.Alg.Equals(SecurityAlgorithms.HmacSha256, StringComparison.InvariantCultureIgnoreCase);
                    if (result == false)
                        return null;
                }

                //var utcExpiryDate = long.Parse(tokenInVerification.Claims.FirstOrDefault(x => x.Type == JwtRegisteredClaimNames.Exp).Value); //1689710893
                var utcExpirySeconds = long.Parse(tokenInVerification.Claims.FirstOrDefault(x => x.Type == JwtRegisteredClaimNames.Exp).Value);
                var utcExpiryTime = DateTimeOffset.FromUnixTimeSeconds(utcExpirySeconds);
                var localExpiryTime = utcExpiryTime.ToLocalTime().AddMinutes(-1); ;

                //var expiryDate = UnixTimeStampToDateTime(utcExpiryDate);

                if(localExpiryTime > DateTime.Now)
                {
                    return new AuthResult()
                    {
                        Result = false,
                        Errors = new List<string>()
                        {
                            "Expired Token"
                        }
                    };
                }

                var storedToken = await _context.RefreshTokens.FirstOrDefaultAsync(x => x.Token == tokenRequest.RefreshToken);

                if (storedToken == null)
                    return new AuthResult()
                    {
                        Result = false,
                        Errors = new List<string>()
                        {
                            "Invalid Token"
                        }
                    };

                if (storedToken.IsUsed)
                    return new AuthResult()
                    {
                        Result = false,
                        Errors = new List<string>()
                        {
                            "Invalid Token"
                        }
                    };

                if (storedToken.IsRevoked)
                    return new AuthResult()
                    {
                        Result = false,
                        Errors = new List<string>()
                        {
                            "Invalid Token"
                        }
                    };

                var jti = tokenInVerification.Claims.FirstOrDefault(x => x.Type == JwtRegisteredClaimNames.Jti).Value;

                if(storedToken.JwtId != jti)
                    return new AuthResult()
                    {
                        Result = false,
                        Errors = new List<string>()
                        {
                            "Invalid Token"
                        }
                    };

                if (storedToken.ExpriyDate < DateTime.UtcNow)
                    return new AuthResult()
                    {
                        Result = false,
                        Errors = new List<string>()
                        {
                            "Expired Token"
                        }
                    };

                storedToken.IsUsed = true;
                _context.RefreshTokens.Update(storedToken);
                await _context.SaveChangesAsync();

                var dbUser = await _userManager.FindByIdAsync(storedToken.UserId);

                return await GenerateJwtToken(dbUser);
            }
            catch (Exception ex)
            {
                return new AuthResult()
                {
                    Result = false,
                    Errors = new List<string>()
                    {
                        "Server error"
                    }
                };
            }
        }

        private DateTime UnixTimeStampToDateTime(long unixTimeStamp)
        {
            var dateTimeVal = new DateTime(1970, 1, 1, 0, 0, 0, 0,DateTimeKind.Utc);
            dateTimeVal = dateTimeVal.AddSeconds(unixTimeStamp).ToUniversalTime();

            return dateTimeVal;
        }
        private bool SendEmail(string body, string email)
        {
            // create client
            var client = new RestClient(baseUrl: "https://api.mailgun.net/v3");

            var request = new RestRequest(resource: "", Method.Post);

            //client.Authenticator = new HttpBasicAuthenticator(username: "api", password:_configuration.GetSection(key: "EmailConfig:API_KEY").Value);
            var apiKey = _configuration.GetValue<string>("EmailConfig:API_KEY");
            var encodedApiKey = Convert.ToBase64String(Encoding.UTF8.GetBytes($"api:{apiKey}"));
            request.AddParameter("Authorization", $"Basic {encodedApiKey}", ParameterType.HttpHeader);

            request.AddParameter(name: "domain", value: "sandbox85db7fc547244572ae20b21117e7db59.mailgun.org", ParameterType.UrlSegment);
            request.Resource= "{domain}/messages";
            request.AddParameter(name:"from", value: "Jay Patel Sandbox Mailgum <postmaster@sandbox85db7fc547244572ae20b21117e7db59.mailgun.org>");
            request.AddParameter(name: "to", value: "jaypatel2799.jp@gmail.com");
            request.AddParameter(name: "subject", value: "Email verification");
            request.AddParameter(name:"text", value: body);
            request.Method = Method.Post;

            var response = client.Execute(request);

            return response.IsSuccessful;
        }

        private string RandomStringGeneration(int length)
        {
            var random = new Random();
            var chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890abcdefghijklmnopqrstuvwxyz_";
            return new string(Enumerable.Repeat(chars, length).Select(s => s[random.Next(s.Length)]).ToArray());
        }
    }
}
