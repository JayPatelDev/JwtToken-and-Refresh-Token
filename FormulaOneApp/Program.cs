using FormulaOneApp.Configurations;
using FormulaOneApp.Data;
using FormulaOneApp.Models;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;

using Microsoft.IdentityModel.Tokens;
using System.Text;

namespace FormulaOneApp
{
    public class Program
    {
        public static void Main(string[] args)
        {
            var builder = WebApplication.CreateBuilder(args);

            // Add services to the container.

            builder.Services.AddControllers();
            // Learn more about configuring Swagger/OpenAPI at https://aka.ms/aspnetcore/swashbuckle
            builder.Services.AddEndpointsApiExplorer();
            builder.Services.AddSwaggerGen();

            builder.Services.AddDbContext<AppDbContext>(optionsAction: options =>
            options.UseSqlite(builder.Configuration.GetConnectionString(name: "DefaultConnection")));

            builder.Services.Configure<JwtConfig>(builder.Configuration.GetSection("JwtConfig"));

            var key = Encoding.ASCII.GetBytes(builder.Configuration.GetSection("JwtConfig:Secret").Value);

            var tokenValidationParameter = new TokenValidationParameters()
            {
                ValidateIssuerSigningKey = true,
                IssuerSigningKey = new SymmetricSecurityKey(key),
                ValidateIssuer = false, // for development purpose
                ValidateAudience = false, // for development purpose
                RequireExpirationTime = false, // for development purpose
                ValidateLifetime = true
            };

            builder.Services.AddAuthentication(configureOptions: options =>
            {
                options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
                options.DefaultScheme = JwtBearerDefaults.AuthenticationScheme;
                options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
            })
                .AddJwtBearer(jwt =>
                {
                    
                    //var key = Encoding.ASCII.GetBytes(builder.Configuration.GetSection("JwtConfig")["Secret"]);
                    

                    jwt.SaveToken = true;
                    jwt.TokenValidationParameters = tokenValidationParameter;
                });

            //builder.Services.AddIdentity<ApplicationUser, IdentityRole>()
            //    .AddEntityFrameworkStores<AppDbContext>();

            //builder.Services.AddDefaultIdentity<IdentityUser>(configureOptions: options => options.SignIn.RequireConfirmedAccount = false)
            //    .AddEntityFrameworkStores<AppDbContext>();
            builder.Services.AddIdentity<ApplicationUser, IdentityRole>()
                .AddEntityFrameworkStores<AppDbContext>()
                .AddUserManager<UserManager<ApplicationUser>>()
                .AddDefaultTokenProviders(); // Add this line to configure the default token providers

            builder.Services.AddSingleton(tokenValidationParameter);

            //builder.Services.AddIdentity<ApplicationUser, IdentityRole>(options =>
            //{
            //    options.SignIn.RequireConfirmedAccount = false;
            //    // Add any other desired Identity options here
            //})
            //.AddEntityFrameworkStores<AppDbContext>();

            //builder.Services.ConfigureApplicationCookie(options =>
            //{
            //    options.Cookie.Name = "YourCustomCookieName";
            //    options.Cookie.SameSite = SameSiteMode.Strict;
            //    // Add any other desired cookie authentication options
            //});


            var app = builder.Build();

            // Configure the HTTP request pipeline.
            if (app.Environment.IsDevelopment())
            {
                app.UseSwagger();
                app.UseSwaggerUI();
            }

            app.UseHttpsRedirection();

            app.UseAuthentication();
            app.UseAuthorization();


            app.MapControllers();

            app.Run();
        }
    }
}

