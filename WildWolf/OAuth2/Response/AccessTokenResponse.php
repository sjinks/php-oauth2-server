<?php

namespace WildWolf\OAuth2\Response;

class AccessTokenResponse extends BaseResponse
{
    protected $access_token;
    protected $token_type;
    protected $expires_in;
    protected $refresh_token;
    protected $scope;

    public function __construct(string $access_token, string $token_type = 'bearer', int $expires_in = 3600, string $refresh_token = '', string $scope = '')
    {
        $this->setStatusCode(200);

        $this->access_token  = $access_token;
        $this->token_type    = $token_type;
        $this->expires_in    = $expires_in;
        $this->refresh_token = $refresh_token;
        $this->scope         = $scope;
    }

    public function toArray() : array
    {
        $r = [
            'access_token' => $this->getAccessToken(),
            'token_type'   => $this->getTokenType(),
            'expires_in'   => $this->getExpiresIn(),
        ];

        $rt = $this->getRefreshToken();
        $sc = $this->getScope();

        if ($rt) {
            $r['refresh_token'] = $rt;
        }

        if ($sc) {
            $r['scope'] = $sc;
        }

        return $r;
    }

    public function getAccessToken() : string
    {
        return $this->access_token;
    }

    public function getTokenType() : string
    {
        return $this->token_type;
    }

    public function getExpiresIn() : int
    {
        return $this->expires_in;
    }

    public function getRefreshToken() : string
    {
        return $this->refresh_token;
    }

    public function getScope() : string
    {
        return $this->scope;
    }

    public function nullifyRefreshToken()
    {
        $this->refresh_token = '';
    }
}
