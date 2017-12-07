<?php

namespace WildWolf\OAuth2\Endpoint;

use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Message\ResponseInterface;
use WildWolf\OAuth2\Interfaces\GrantTypeInterface;
use WildWolf\OAuth2\Interfaces\TokenEndpointInterface;
use WildWolf\OAuth2\Request\BaseTokenRequest;
use WildWolf\OAuth2\Request\TokenRequestFactory;
use WildWolf\OAuth2\Response\ErrorResponse;

class TokenEndpoint implements TokenEndpointInterface
{
    /**
     * @var ServerRequestInterface
     */
    protected $request;

    /**
     * @var BaseTokenRequest
     */
    protected $tokenRequest;

    /**
     * @var ErrorResponse
     */
    protected $error = null;

    /**
     * @var GrantTypeInterface[]
     */
    protected $gt_handlers;

    public function initialize(ServerRequestInterface $request, array $handlers)
    {
        $this->request      = $request;
        $this->tokenRequest = TokenRequestFactory::create($request);
        $this->gt_handlers  = $handlers;
    }

    public function handleTokenRequest(ResponseInterface $response) : ResponseInterface
    {
        if (!$this->validateTokenRequest()) {
            return $this->error->toResponseInterface($response);
        }

        $token = $this->gt_handlers[$this->tokenRequest->getGrantType()];
        $resp  = $token->generateAccessToken($this->tokenRequest);

        if ($resp instanceof ErrorResponse) {
            $this->error = $resp;
        }

        return $resp->toResponseInterface($response);
    }

    protected function validateTokenRequest() : bool
    {
        $this->error = null;

        if (!$this->tokenRequest->validate()) {
            $this->error = new ErrorResponse('invalid_request', 'The request is invalid.');
            return false;
        }

        if (!$this->validateGrantType($this->tokenRequest->getGrantType())) {
            return false;
        }

        return true;
    }

    protected function validateGrantType(string $gt)
    {
        if (!isset($this->gt_handlers[$gt])) {
            $this->error = new ErrorResponse(
                'unsupported_grant_type',
                sprintf('The authorization grant type "%s" is not supported by the authorization server.', $gt)
            );

            return false;
        }

        return true;
    }
}
