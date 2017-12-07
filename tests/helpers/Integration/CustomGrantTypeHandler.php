<?php

namespace Test\Helpers\Integration;

use WildWolf\OAuth2\Interfaces\GrantTypeInterface;
use WildWolf\OAuth2\Request\BaseTokenRequest;
use WildWolf\OAuth2\Response\BaseResponse;
use WildWolf\OAuth2\Response\AccessTokenResponse;

class CustomGrantTypeHandler implements GrantTypeInterface
{
    /**
     * @var \PDO
     */
    private $pdo;

    public function __construct(\PDO $pdo)
    {
        $this->pdo = $pdo;
    }

    public function generateAccessToken(BaseTokenRequest $request) : BaseResponse
    {
        // Don't do that in production
        $token   = md5(random_bytes(16));
        $expires = time() + 3600;
        $params  = $request->getRequest()->getParsedBody();
        $scope   = $params['scope'] ?? '';

        $stmt = $this->pdo->prepare("INSERT INTO authorization (code, token_type, expires, scope) VALUES (?, ?, ?, ?)");
        $stmt->execute([$token, 'custom', $expires, $scope]);

        return new AccessTokenResponse($token, 'custom', $expires, '', $scope);
    }
}
