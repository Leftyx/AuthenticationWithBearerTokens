using System;

namespace AuthenticationServer
{
    public enum OAuthGrant
    {
        Code = 1,
        Implicit = 2,
        ResourceOwner = 3,
        Client = 4
    }
}
