using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Security.Claims;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Clients.ActiveDirectory;
using Newtonsoft.Json;
using WebAppInteractingWithApiGw.Cache;
using WebAppInteractingWithApiGw.Models;

namespace WebAppInteractingWithApiGw.Controllers
{
    [Authorize]
    public class MasterDataController : Controller
    {
        private IConfiguration Configuration { get; }
        //Inject IOptions when strong type is available instead of IConfiguration
        public MasterDataController(IConfiguration configuration)
        {
            Configuration = configuration;
        }

        public async Task<IActionResult> Index()
        {
            var resources = await GetResourceFromCommonServiceApiGwAsync();
            return View(resources);
        }

        private async Task<List<Resource>> GetResourceFromCommonServiceApiGwAsync()
        {
            #region Get Token response
            var token = await GetTokenResponse();
            #endregion

            #region Get Client Certificate from cert store

            var clientCertificateThumbprint = Configuration.GetValue<string>("CSAzureAdConfigSettings:ClientCertificateThumbprint");
            var clientCertificate = GetClientCertificateFromStoreByThumbprint(clientCertificateThumbprint);
            if (clientCertificate == null)
            {
                throw new Exception("Client Certificate should not be null.");
            }
            #endregion

            #region Get Data by making HTTP call to API-GW endpoint
            var handler = new HttpClientHandler();
            handler.ClientCertificates.Add(clientCertificate);
            using (var httpClient = new HttpClient(handler))
            {
                //Set Common Service API GW Base URL
                httpClient.BaseAddress = new Uri(Configuration.GetValue<string>("CSAzureAdConfigSettings:APIGWBaseUrl"));
                //Set Bearer access token
                httpClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue(token.AccessTokenType, token.AccessToken);
                httpClient.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
                var response = await httpClient.GetAsync(Configuration.GetValue<string>("CSAzureAdConfigSettings:ResourcePath"));

               if (response.IsSuccessStatusCode)
                {
                    var responseAsString = await response.Content.ReadAsStringAsync();
                    var resources = JsonConvert.DeserializeObject<List<Resource>>(responseAsString);
                    return resources;
                }
                else
                {
                   throw new Exception(response.Content.ReadAsStringAsync().Result);
                }
            }
            #endregion
        }

        private async Task<AuthenticationResult> GetTokenResponse()
        {
            string clientId = Configuration.GetValue<string>("CSAzureAdConfigSettings:ClientId");
            string clientSecret = Configuration.GetValue<string>("CSAzureAdConfigSettings:ClientSecret");
            string resource = Configuration.GetValue<string>("CSAzureAdConfigSettings:APIGWBaseUrl");

            //Get one of the unique user identifier
            string userObjectId = User.FindFirstValue("http://schemas.microsoft.com/identity/claims/objectidentifier") ??
                                  User.FindFirstValue(ClaimTypes.Upn) ??
                                  User.FindFirstValue(ClaimTypes.Email);

            var authority = Configuration.GetValue<string>("CSAzureAdConfigSettings:Instance") +
                            Configuration.GetValue<string>("CSAzureAdConfigSettings:TenantId");

            var authContext = new AuthenticationContext(authority, new NaiveSessionCache(userObjectId, HttpContext.Session));
            var credential = new ClientCredential(clientId, clientSecret);
            var userIdentifier = new UserIdentifier(userObjectId,UserIdentifierType.UniqueId);
            AuthenticationResult authResult = null;
            try
            {
                //https://github.com/AzureAD/azure-activedirectory-library-for-dotnet/wiki/AcquireTokenSilentAsync-using-a-cached-token
                authResult = await authContext.AcquireTokenSilentAsync(resource, credential, userIdentifier);
            }
            catch (AdalSilentTokenAcquisitionException)
            {
                var result = await authContext.AcquireTokenAsync(resource, credential);
            }
            
            return authResult;
        }

        private X509Certificate2 GetClientCertificateFromStoreByThumbprint(string thumbprint)
        {
            if (string.IsNullOrEmpty(thumbprint))
            {
                throw new ArgumentNullException(nameof(thumbprint), "Argument 'thumbprint' cannot be 'null' or 'string.empty'");
            }

            using (var userCaStore = new X509Store(StoreName.My, StoreLocation.CurrentUser))
            {
                userCaStore.Open(OpenFlags.ReadOnly);
                var certificatesInStore = userCaStore.Certificates;
                var findResult = certificatesInStore.Find(X509FindType.FindByThumbprint, thumbprint, true);
                if (findResult.Count <=0 )
                {
                    throw new Exception("Certificate not found");
                }

                var clientCertificate = findResult[0];
                return clientCertificate;
            }
        }
    }
}