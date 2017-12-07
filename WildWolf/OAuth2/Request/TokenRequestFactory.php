<?php

namespace WildWolf\OAuth2\Request;

use Psr\Http\Message\ServerRequestInterface;

class TokenRequestFactory
{
    public static $class_map = [
        'authorization_code' => AuthorizationCodeRequest::class,
        'password'           => PasswordRequest::class,
        'client_credentials' => ClientCredentialsRequest::class,
        'refresh_token'      => RefreshTokenRequest::class,
    ];

    public static function create(ServerRequestInterface $req)
    {
        $params     = $req->getParsedBody();
        $grant_type = $params['grant_type'] ?? null;
        $class      = self::$class_map[$grant_type] ?? BaseTokenRequest::class;

        return $class::fromRequest($req);
    }
}
