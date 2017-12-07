<?php

namespace Test\Helpers;

use WildWolf\OAuth2\Interfaces\AuthorizerInterface;
use WildWolf\OAuth2\Request\AuthorizeRequest;
use WildWolf\OAuth2\Response\BaseResponse;
use WildWolf\OAuth2\Response\ErrorResponse;
use WildWolf\OAuth2\Interfaces\AuthorizationCodeGeneratorInterface;
use WildWolf\OAuth2\Interfaces\ImplicitGrantAccessTokenGeneratorInterface;
use WildWolf\OAuth2\Response\AccessTokenResponse;

class SampleAuthorizer implements AuthorizerInterface, AuthorizationCodeGeneratorInterface, ImplicitGrantAccessTokenGeneratorInterface
{
    /**
     * @var AuthorizeRequest
     */
    private $request;

    private $response = [
        'error' => false, 'uri' => '', 'code' => 'abcd'
    ];

    public function setResponse($error, $uri = '', $code = 'xxx')
    {
        $this->response = [
            'error' => $error,
            'uri'   => $uri,
            'code'  => $code,
        ];
    }

    public function initializeAuthorizer(AuthorizeRequest $request)
    {
        $this->request = $request;
    }

    public function getRedirectUri() : string
    {
        return $this->response['uri'];
    }

    public function validateAuthorizeRequest() : bool
    {
        return false === $this->response['error'];
    }

    public function getAuthorizerValidationError() : ErrorResponse
    {
        return new ErrorResponse($this->response['error']);
    }

    public function generateAuthorizationCode(AuthorizeRequest $request) : string
    {
        return $this->response['code'];
    }

    public function generateImplicitGrantAccessToken(AuthorizeRequest $request) : BaseResponse
    {
        return new AccessTokenResponse($this->response['code']);
    }
}
