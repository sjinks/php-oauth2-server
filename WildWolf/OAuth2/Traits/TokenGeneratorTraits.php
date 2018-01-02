<?php

namespace WildWolf\OAuth2\Traits;

use WildWolf\OAuth2\Request\BaseTokenRequest;
use WildWolf\OAuth2\Response\ErrorResponse;
use WildWolf\OAuth2\Response\BaseResponse;
use WildWolf\OAuth2\Request\AuthorizationCodeRequest;
use WildWolf\OAuth2\Request\PasswordRequest;
use WildWolf\OAuth2\Request\ClientCredentialsRequest;
use WildWolf\OAuth2\Request\RefreshTokenRequest;

trait TokenGeneratorTraits
{
    /**
     * @param BaseTokenRequest $request
     * @return bool|ErrorResponse
     */
    public function verifyClient(BaseTokenRequest $request)
    {
        $auth = $request->getAuthenticationData();

        $client_id     = $auth[0] ?? '';
        $client_secret = $auth[1] ?? '';
        return $this->verifyClientCredentials($client_id, $client_secret, $request);
    }

    public function generateAccessToken(BaseTokenRequest $req) : BaseResponse
    {
        static $map = [
            'authorization_code' => 'handleAuthorizationCodeRequest',
            'password'           => 'handlePasswordRequest',
            'client_credentials' => 'handleClientCredentialsRequest',
            'refresh_token'      => 'handleRefreshTokenRequest'
        ];

        $gt     = $req->getGrantType();
        $method = $map[$gt] ?? 'handleTokenRequest';
        return $this->$method($req);
    }

    protected function handleAuthorizationCodeRequest(AuthorizationCodeRequest $req) : BaseResponse
    {
        return new ErrorResponse('unsupported_grant_type');
    }

    protected function handlePasswordRequest(PasswordRequest $req) : BaseResponse
    {
        return new ErrorResponse('unsupported_grant_type');
    }

    protected function handleClientCredentialsRequest(ClientCredentialsRequest $req) : BaseResponse
    {
        return new ErrorResponse('unsupported_grant_type');
    }

    protected function handleRefreshTokenRequest(RefreshTokenRequest $req) : BaseResponse
    {
        return new ErrorResponse('unsupported_grant_type');
    }

    protected function handleTokenRequest(BaseTokenRequest $req) : BaseResponse
    {
        return new ErrorResponse('unsupported_grant_type');
    }

    protected function verifyClientCredentials($client_id, $client_secret, BaseTokenRequest $request)
    {
        return new ErrorResponse('invalid_client');
    }
}
