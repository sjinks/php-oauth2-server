<?php

namespace Test\Helpers\Integration;

use WildWolf\OAuth2\Interfaces\AuthorizerInterface;
use WildWolf\OAuth2\Request\AuthorizeRequest;
use WildWolf\OAuth2\Response\ErrorResponse;

class Authorizer implements AuthorizerInterface
{
    /**
     * @var \PDO
     */
    private $pdo;

    /**
     * @var ErrorResponse|null
     */
    private $error = null;

    /**
     * @var AuthorizeRequest|null
     */
    private $request = null;

    /**
     * @var string
     */
    private $redirect_uri = '';

    public function __construct(\PDO $pdo)
    {
        $this->pdo = $pdo;
    }

    public function getAuthorizerValidationError() : ErrorResponse
    {
        return $this->error;
    }

    public function initializeAuthorizer(AuthorizeRequest $request)
    {
        $this->request = $request;
    }

    public function getRedirectUri() : string
    {
        return $this->redirect_uri;
    }

    public function validateAuthorizeRequest() : bool
    {
        $client_id = $this->request->getClientId();

        $stmt = $this->pdo->prepare("SELECT * FROM client WHERE client_id = ?");
        $stmt->execute([$client_id]);
        $row  = $stmt->fetch(\PDO::FETCH_ASSOC);

        if (false === $row) {
            $this->error = new ErrorResponse('unauthorized_client', 'client_id');
            return false;
        }

        $redirect_uri = $row['redirect_uri'];
        if ($redirect_uri != $this->request->getRedirectUri()) {
            $this->error = new ErrorResponse('unauthorized_client', 'redirect_uri');
            return false;
        }

        $this->redirect_uri = $redirect_uri;
        return true;
    }
}
