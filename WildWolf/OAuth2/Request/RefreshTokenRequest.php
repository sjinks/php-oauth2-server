<?php

namespace WildWolf\OAuth2\Request;

use Psr\Http\Message\ServerRequestInterface;

class RefreshTokenRequest extends BaseTokenRequest
{
    protected $refresh_token;
    protected $scope;

    /**
     * {@inheritDoc}
     * @see \WildWolf\OAuth2\Request\BaseTokenRequest::createFromRequest()
     * @see https://tools.ietf.org/html/rfc6749#section-6
     */
    protected function createFromRequest(ServerRequestInterface $req)
    {
        parent::createFromRequest($req);
        $p = $req->getParsedBody();

        $this->refresh_token = $p['refresh_token'] ?? null;
        $this->scope         = $p['scope']         ?? null;

        return $this;
    }

    /**
     * {@inheritDoc}
     * @see \WildWolf\OAuth2\Request\BaseTokenRequest::validate()
     * @see https://tools.ietf.org/html/rfc6749#section-6
     */
    public function validate() : bool
    {
        return
               parent::validate()
            && $this->refresh_token !== null
        ;
    }

    public function getRefreshToken()
    {
        return $this->refresh_token;
    }

    public function getScope()
    {
        return $this->scope;
    }
}
