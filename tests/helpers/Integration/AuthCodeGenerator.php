<?php

namespace Test\Helpers\Integration;

use WildWolf\OAuth2\Interfaces\AuthorizationCodeGeneratorInterface;
use WildWolf\OAuth2\Request\AuthorizeRequest;

class AuthCodeGenerator implements AuthorizationCodeGeneratorInterface
{
    /**
     * @var \PDO
     */
    private $pdo;

    public function __construct(\PDO $pdo)
    {
        $this->pdo = $pdo;
    }

    public function generateAuthorizationCode(AuthorizeRequest $request) : string
    {
        // Don't do that in production
        $token        = md5(random_bytes(16));
        $expires      = time() + 60;
        $client_id    = (string)$request->getClientId();
        $redirect_uri = (string)$request->getRedirectUri();
        $scope        = (string)$request->getScope();

        $stmt = $this->pdo->prepare("INSERT INTO access_token (token, expires, client_id, redirect_uri, scope) VALUES (?, ?, ?, ?, ?)");
        $stmt->execute([$token, $expires, $client_id, $redirect_uri, $scope]);

        return $token;
    }
}