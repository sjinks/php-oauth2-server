<?php

namespace WildWolf\OAuth2\Request;

use Psr\Http\Message\ServerRequestInterface;

class TokenRequestFactory
{
    public static function create(ServerRequestInterface $req)
    {
        $params     = $req->getParsedBody();
        $grant_type = $params['grant_type'] ?? null;

        switch ($grant_type) {
            case 'authorization_code': return AuthorizationCodeRequest::fromRequest($req);
            case 'password':           return PasswordRequest::fromRequest($req);
            case 'client_credentials': return ClientCredentialsRequest::fromRequest($req);
            case 'refresh_token':      return RefreshTokenRequest::fromRequest($req);
            default:                   return BaseTokenRequest::fromRequest($req);
        }
    }
}
