<?php

namespace Test\Helpers\Integration;

use WildWolf\OAuth2\Interfaces\ImplicitGrantAccessTokenGeneratorInterface;
use WildWolf\OAuth2\Request\AuthorizeRequest;
use WildWolf\OAuth2\Response\BaseResponse;
use WildWolf\OAuth2\Response\AccessTokenResponse;

class ImplicitFlowTokenGenerator implements ImplicitGrantAccessTokenGeneratorInterface
{
    /**
     * @var \PDO
     */
    private $pdo;

    public function __construct(\PDO $pdo)
    {
        $this->pdo = $pdo;
    }

    public function generateImplicitGrantAccessToken(AuthorizeRequest $request) : BaseResponse
    {
        // Don't do that in production
        $token   = md5(random_bytes(16));
        $expires = time() + 3600;
        $scope   = (string)$request->getScope();

        $stmt = $this->pdo->prepare("INSERT INTO authorization (code, token_type, expires, scope) VALUES (?, ?, ?, ?)");
        $stmt->execute([$token, 'bearer', $expires, $scope]);

        return new AccessTokenResponse($token, 'bearer', $expires, '', $scope);
    }

}
