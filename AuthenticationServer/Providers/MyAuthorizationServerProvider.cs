using System;
using System.Collections.Generic;
using System.Security.Claims;
using System.Threading.Tasks;
using Microsoft.AspNet.Identity;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.OAuth;

namespace AuthenticationServer.Providers
{
    public class MyAuthorizationServerProvider : OAuthAuthorizationServerProvider
    {
        private const string CLIENT_ID = "MyApp";
        private const string CLIENT_SECRET = "MySecret";
        private const string APP_NAME = "My App";

        public override async Task ValidateClientAuthentication(OAuthValidateClientAuthenticationContext context)
        {
            string clientId = string.Empty;
            string clientSecret = string.Empty;

            if (!context.TryGetBasicCredentials(out clientId, out clientSecret))
            {
                context.TryGetFormCredentials(out clientId, out clientSecret);
            }

            if (context.ClientId == null)
            {
                context.Rejected();
                context.SetError("invalid_client", "Client credentials could not be retrieved through the Authorization header.");
                return;
            }

            try
            {
                if (clientId == CLIENT_ID && clientSecret == CLIENT_SECRET)
                {
                    ApplicationClient client = new ApplicationClient();

                    client.Id = clientId;
                    client.AllowedGrant = OAuthGrant.ResourceOwner;
                    client.ClientSecretHash = new PasswordHasher().HashPassword(clientSecret);
                    client.Name = APP_NAME;
                    client.CreatedOn = DateTimeOffset.UtcNow;

                    context.OwinContext.Set<ApplicationClient>("oauth:client", client);

                    context.Validated(clientId);
                }
                else
                {
                    // Client could not be validated.
                    context.Rejected();
                    context.SetError("invalid_client", "Client credentials are invalid.");
                }
            }
            catch (Exception ex)
            {
                string errorMessage = ex.Message;
                context.Rejected();
                context.SetError("server_error");
            }

            return;
        }

        public override async Task GrantResourceOwnerCredentials(OAuthGrantResourceOwnerCredentialsContext context)
        {
            ApplicationClient client = context.OwinContext.Get<ApplicationClient>("oauth:client");

            if (string.IsNullOrEmpty(context.UserName) || string.IsNullOrEmpty(context.Password))
            {
                context.Rejected();
                context.SetError("invalid_request", "No username or password are provided.");
                return;
            }

            if (context.UserName != "John" && context.Password != "Smith")
            {
                context.Rejected();                
                context.SetError("invalid_grant", "The username or password is incorrect.");
                return;
            }

            if (client.AllowedGrant != OAuthGrant.ResourceOwner)
            {
                context.Rejected();
                context.SetError("invalid_grant", "The resource owner credentials are invalid or resource owner does not exist.");
                return;
            }

            try
            {
                ClaimsIdentity identity = new ClaimsIdentity(context.Options.AuthenticationType);
                identity.AddClaim(new Claim(ClaimTypes.Name, context.UserName));
                
                // This roles will be used to authorize the access to the Resource Server.
                identity.AddClaim(new Claim(ClaimTypes.Role, "PowerUsers"));

                // This is a custom claim and it will be passed to the Resource Server.
                identity.AddClaim(new Claim("application:info", "Some extended info are stored here."));

                // These Properties will be returned to the client.
                var props = new AuthenticationProperties(new Dictionary<string, string>
                {
                    { 
                        "name", "John"
                    },
                    { 
                        "surname", "Smith"
                    },
                    { 
                        "age", "40"
                    },
                    { 
                        "gender", "Male"
                    }
                });

                var ticket = new AuthenticationTicket(identity, props);
                context.Validated(ticket);

            }
            catch
            {
                context.Rejected(); 
                context.SetError("server_error");
            }
        }

        public override Task TokenEndpoint(OAuthTokenEndpointContext context)
        {
            foreach (KeyValuePair<string, string> property in context.Properties.Dictionary)
            {
                context.AdditionalResponseParameters.Add(property.Key, property.Value);
            }
            return Task.FromResult<object>(null);
        }

        //public override Task TokenEndpointResponse(OAuthTokenEndpointResponseContext context)
        //{
        //    return base.TokenEndpointResponse(context);
        //}

        public override async Task GrantRefreshToken(OAuthGrantRefreshTokenContext context)
        {
            ApplicationClient client = context.OwinContext.Get<ApplicationClient>("oauth:client");

            // var originalClient = context.Ticket.Properties.Dictionary["as:client_id"];
            var currentClient = context.ClientId;

            // enforce client binding of refresh token
            if (client.Id != currentClient)
            {
                context.Rejected();
                return;
            }

            // chance to change authentication ticket for refresh token requests
            var newId = new ClaimsIdentity(context.Ticket.Identity);
            newId.AddClaim(new Claim("newClaim", "refreshToken"));

            var newTicket = new AuthenticationTicket(newId, context.Ticket.Properties);
            context.Validated(newTicket);
        }

    }
}
