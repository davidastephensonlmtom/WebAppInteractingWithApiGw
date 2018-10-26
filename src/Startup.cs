using System;
using System.Diagnostics;
using System.Security.Claims;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.Clients.ActiveDirectory;
using WebAppInteractingWithApiGw.Cache;

namespace WebAppInteractingWithApiGw
{
    public class Startup
    {
        public Startup(IConfiguration configuration)
        {
            Configuration = configuration;
        }

        public IConfiguration Configuration { get; }

        // This method gets called by the runtime. Use this method to add services to the container.
        public void ConfigureServices(IServiceCollection services)
        {
            services.AddAuthentication(sharedOptions =>
                {
                    sharedOptions.DefaultScheme = CookieAuthenticationDefaults.AuthenticationScheme;
                    sharedOptions.DefaultChallengeScheme = OpenIdConnectDefaults.AuthenticationScheme;
                })
                //Configure Open Id Connect
                .AddOpenIdConnect(o =>
                {
                    o.Authority = Configuration.GetValue<string>("CSAzureAdConfigSettings:Instance") + Configuration.GetValue<string>("CSAzureAdConfigSettings:TenantId");

                    o.ClientId = Configuration.GetValue<string>("CSAzureAdConfigSettings:ClientId");
                    o.ClientSecret = Configuration.GetValue<string>("CSAzureAdConfigSettings:ClientSecret");
                    o.CallbackPath = Configuration.GetValue<string>("CSAzureAdConfigSettings:CallbackPath");
                    
                    //https://docs.microsoft.com/en-us/dotnet/api/microsoft.aspnetcore.authentication.remoteauthenticationoptions.savetokens?view=aspnetcore-2.1
                    o.SaveTokens = true;

                    //https://docs.microsoft.com/en-us/azure/active-directory/develop/v2-permissions-and-consent#offlineaccess
                    o.Scope.Add("offline_access");

                    // Without overriding the response type (which by default is id_token), the OnAuthorizationCodeReceived event is not called.
                    // but instead OnTokenValidated event is called. Here we request both so that OnTokenValidated is called first which 
                    // ensures that context.Principal has a non-null value when OnAuthorizeationCodeReceived is called
                    o.ResponseType = "id_token code";

                    // Subscribing to the OIDC events
                    o.Events.OnAuthorizationCodeReceived = async context =>
                    {
                        //Begin - request for on-behalf-of access code
                        //Use ADAL to swap the Id_token for an access token
                        //Extract the code from the response notification

                        //https://docs.microsoft.com/en-us/azure/active-directory/develop/v2-oauth2-on-behalf-of-flow#first-case-access-token-request-with-a-shared-secret
                        const string jwtBearerUrn = "urn:ietf:params:oauth:grant-type:jwt-bearer";

                        string id_token = context.JwtSecurityToken.RawData;

                        // Acquire a Token for the Graph API and cache it using ADAL. In the TodoListController, we'll use the cache to acquire a token for the Todo List API
                        ClaimsPrincipal claimsPrincipal = context.Principal;

                        //Get one of the unique user identifier
                        string userObjectId = claimsPrincipal.FindFirstValue("http://schemas.microsoft.com/identity/claims/objectidentifier") ??
                                              claimsPrincipal.FindFirstValue(ClaimTypes.Upn) ??
                                              claimsPrincipal.FindFirstValue(ClaimTypes.Email);


                        var credential = new ClientCredential(context.Options.ClientId, context.Options.ClientSecret);
                        var userAssertion = new UserAssertion(id_token, jwtBearerUrn, userObjectId);
                        var authContext = new AuthenticationContext(context.Options.Authority, new NaiveSessionCache(userObjectId, context.HttpContext.Session));
                        var apiurl = Configuration.GetValue<string>("CSAzureAdConfigSettings:APIGWBaseUrl");
                        AuthenticationResult authResult = await authContext.AcquireTokenAsync(apiurl, credential, userAssertion);

                        // Notify the OIDC middleware that we already took care of code redemption.
                        context.HandleCodeRedemption(authResult.AccessToken, context.ProtocolMessage.IdToken);
                        //End - request for on-behalf-of access code

                        context.Properties.AllowRefresh = true;

                    };
                })
                .AddCookie(o =>
                {
                    o.Events = new CookieAuthenticationEvents
                    {
                        OnValidatePrincipal = context =>
                        {
                            context.ShouldRenew = true;

                            return Task.CompletedTask;
                        }
                    };
                });

            //The IdleTimeout indicates how long the session can be idle before its contents are abandoned. Each session access resets the timeout.
            // You may be wish to extended the Session timeout from 20 minutes to x number of minutes or days. 
            // The HTTP Session cache uses this time interval to retain or clear out the on-behalf-of tokens from cache.
            // If the on-behalf-of token is cleared from the cache, then the application should acquire a new access_token to call Common Service API-GW
            services.AddSession(o => o.IdleTimeout = TimeSpan.FromDays(1));

            services.AddMvc().AddSessionStateTempDataProvider();
        }

        // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
        public void Configure(IApplicationBuilder app, IHostingEnvironment env, DiagnosticListener diagnosticListener)
        {
            if (env.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
            }
            else
            {
                app.UseExceptionHandler("/Home/Error");
            }

            app.UseStaticFiles();

            app.UseSession(); // Needs to be app.UseAuthentication() and app.UseMvc() otherwise you will get an exception "Session has not been configured for this application or request."
            app.UseAuthentication();
            app.UseMvc(routes =>
            {
                routes.MapRoute(
                    name: "default",
                    template: "{controller=Home}/{action=Index}/{id?}");
            });

        }
    }


}
