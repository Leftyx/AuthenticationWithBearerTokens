using System;
using System.Threading.Tasks;
using System.Web.Http;
using Microsoft.Owin;
using Owin;
using Microsoft.Owin.Security.OAuth;

[assembly: OwinStartup(typeof(AuthenticationServer.Startup))]

namespace AuthenticationServer
{
    public class Startup
    {
        public static void Configuration(IAppBuilder app)
        {
            app.UseWelcomePage("/");
            app.UseErrorPage();

            HttpConfiguration config = new HttpConfiguration();

            app.UseCors(Microsoft.Owin.Cors.CorsOptions.AllowAll);

            var OAuthOptions = new OAuthAuthorizationServerOptions
            {
                AllowInsecureHttp = true,
                TokenEndpointPath = new PathString("/oauth/Token"),
                AccessTokenExpireTimeSpan = TimeSpan.FromHours(8),
                Provider = new Providers.MyAuthorizationServerProvider(),
                RefreshTokenProvider = new Providers.MyRefreshTokenProvider(DateTime.UtcNow.AddHours(8))
            };
            app.UseOAuthAuthorizationServer(OAuthOptions);
            app.UseOAuthBearerAuthentication(new OAuthBearerAuthenticationOptions());

            config.SuppressDefaultHostAuthentication();
            config.Filters.Add(new HostAuthenticationFilter(OAuthDefaults.AuthenticationType));

            // There's no public API here. It's just an authentication server.

            //config.MapHttpAttributeRoutes();
            //app.UseWebApi(config);
        }
    }
}
