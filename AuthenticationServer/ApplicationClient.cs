using System;

namespace AuthenticationServer
{
    class ApplicationClient
    {
        public string Id { get; set; }
        public string Name { get; set; }
        public string ClientSecretHash { get; set; }
        public OAuthGrant AllowedGrant { get; set; }
        public DateTimeOffset CreatedOn { get; set; }
    }
}
