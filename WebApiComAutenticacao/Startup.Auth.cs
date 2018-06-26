using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Security.Principal;
using System.Text;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using WebApiComAutenticacao.TokenProvider;

namespace WebApiComAutenticacao
{
    public partial class Startup
    {
        public void ConfigureJwtAuthService(IServiceCollection services)
        {
            var signingKey = new SymmetricSecurityKey(Encoding.ASCII.GetBytes(Configuration.GetSection("TokenAuthentication:SecretKey").Value));

            var tokenValidationParameters = new TokenValidationParameters
            {
                // The signing key must match!
                ValidateIssuerSigningKey = true,
                IssuerSigningKey = signingKey,
                // Validate the JWT Issuer (iss) claim
                ValidateIssuer = true,
                ValidIssuer = Configuration.GetSection("TokenAuthentication:Issuer").Value,
                // Validate the JWT Audience (aud) claim
                ValidateAudience = true,
                ValidAudience = Configuration.GetSection("TokenAuthentication:Audience").Value,
                // Validate the token expiry
                ValidateLifetime = false,
                // If you want to allow a certain amount of clock drift, set that here:
                ClockSkew = TimeSpan.Zero
            };


            services.AddAuthentication(
                  // Seta o JWT como default de autenticação
                  options =>
                  {
                      options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
                      options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
                  }
                )
                .AddJwtBearer(options => {
                    options.Audience = Configuration.GetSection("TokenAuthentication:Audience").Value;
                    options.TokenValidationParameters = tokenValidationParameters;
                    options.RequireHttpsMetadata = false;
                });


            services.BuildServiceProvider();
            var serviceProvider = services.BuildServiceProvider();

            //resolve implementations
            //_userService = serviceProvider.GetService<IUserService>();
        }

         private void ConfigureAuth(IApplicationBuilder app)
        {
            //app.UseAuthentication();

            var signingKey = new SymmetricSecurityKey(Encoding.ASCII.GetBytes(Configuration.GetSection("TokenAuthentication:SecretKey").Value));
            
            var tokenProviderOptions = new TokenProviderOptions
            {
                Path = Configuration.GetSection("TokenAuthentication:TokenPath").Value,
                Audience = Configuration.GetSection("TokenAuthentication:Audience").Value,
                Issuer = Configuration.GetSection("TokenAuthentication:Issuer").Value,
                SigningCredentials = new SigningCredentials(signingKey, SecurityAlgorithms.HmacSha256),
                IdentityResolver = GetIdentityAsync
            };

            app.UseMiddleware<TokenProviderMiddleware>(Options.Create(tokenProviderOptions));
            
        }

        //private IUserService _userService;
        private async Task<ClaimsIdentity> GetIdentityAsync(string username, string password)
        {

            //var result = await _userService.GetByCredentialAsync(username, password);
            //if (result != null)
            //{
            //    return new ClaimsIdentity(new GenericIdentity(username, "Token"),
            //        new Claim[] {
            //            new Claim(ClaimTypes.NameIdentifier, result.Id.ToString()),
            //            new Claim("name", result.Name ?? ""),
            //    });
            //}
            //else
            //    return null;
            if (username == "TEST" && password == "TEST123")
            {
                return new ClaimsIdentity(new GenericIdentity(username, "Token"),
                        new Claim[] {
                            new Claim(ClaimTypes.NameIdentifier, username),
                            new Claim(ClaimTypes.Name, username),
                    });
            }

            
            // Credentials are invalid, or account doesn't exist
            return null;
        }

    }
}
