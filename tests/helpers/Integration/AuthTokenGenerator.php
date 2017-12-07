<?php

namespace Test\Helpers\Integration;

use WildWolf\OAuth2\Interfaces\TokenGeneratorInterface;
use WildWolf\OAuth2\Interfaces\ClientVerifierInterface;
use WildWolf\OAuth2\Request\BaseTokenRequest;
use WildWolf\OAuth2\Response\BaseResponse;
use WildWolf\OAuth2\Response\ErrorResponse;
use PHPUnit\Framework\Assert;
use WildWolf\OAuth2\Request\AuthorizationCodeRequest;
use WildWolf\OAuth2\Response\AccessTokenResponse;

class AuthTokenGenerator implements TokenGeneratorInterface, ClientVerifierInterface
{
    /**
     * @var \PDO
     */
    private $pdo;

    /**
     * @var ErrorResponse|null
     */
    private $error = null;

    public function __construct(\PDO $pdo)
    {
        $this->pdo = $pdo;
    }

    public function verifyClient(BaseTokenRequest $request) : bool
    {
        $this->error = null;

        $auth = $request->getAuthenticationData();
        if ($auth) {
            list($client, $secret) = $auth;

            $stmt = $this->pdo->prepare("SELECT 0 FROM client_secret WHERE client_id = ? AND client_secret = ?");
            $stmt->execute([$client, $secret]);
            if ($stmt->fetch() === false) {
                $this->error = new ErrorResponse('invalid_client');
                $this->error->setStatusCode(401);
                $this->error->setHeader('WWW-Authenticate', 'basic realm="Area 51"');
                return false;
            }
        }

        return true;
    }

    public function getClientVerificationError() : ErrorResponse
    {
        return $this->error;
    }

    public function generateAccessToken(BaseTokenRequest $req) : BaseResponse
    {
        Assert::assertInstanceOf(AuthorizationCodeRequest::class, $req);

        /**
         * @var AuthorizationCodeRequest $req
         */
        $now  = time();
        $code = (string)$req->getCode();
        $uri  = (string)$req->getRedirectUri();
        $cid  = (string)$req->getClientId();

        $stmt = $this->pdo->prepare("SELECT * FROM access_token WHERE token = ?");
        $stmt->execute([$code]);
        $row  = $stmt->fetch(\PDO::FETCH_ASSOC);

        if ($cid != $row['client_id'] || $uri != $row['redirect_uri'] || $now >= $row['expires']) {
            return new ErrorResponse('invalid_grant');
        }

        $token   = md5(random_bytes(16));
        $refresh = md5(random_bytes(16));
        $expires = time() + 3600;
        $scope   = $row['scope'];

        $stmt = $this->pdo->prepare("INSERT INTO authorization (code, token_type, expires, scope) VALUES (?, ?, ?, ?)");
        $stmt->execute([$token, 'bearer', $expires, $scope]);

        $stmt = $this->pdo->prepare("INSERT INTO refresh_token (token, expires, code) VALUES (?, ?, ?)");
        $stmt->execute([$refresh, time() + 86400, $token]);

        return new AccessTokenResponse($token, 'bearer', $expires, $refresh, $scope);
    }
}
