<?php

namespace WildWolf\OAuth2\Request;

use Psr\Http\Message\ServerRequestInterface;

class ClientCredentialsRequest extends BaseTokenRequest
{
    protected $scope;

    /**
     * {@inheritDoc}
     * @see \WildWolf\OAuth2\Request\BaseTokenRequest::createFromRequest()
     * @see https://tools.ietf.org/html/rfc6749#section-4.4
     */
    protected function createFromRequest(ServerRequestInterface $req)
    {
        parent::createFromRequest($req);
        $p = $req->getParsedBody();

        $this->scope = $p['scope'] ?? null;

        return $this;
    }

    /**
     * {@inheritDoc}
     * @see \WildWolf\OAuth2\Request\BaseTokenRequest::validate()
     * @see https://tools.ietf.org/html/rfc6749#section-4.4.2
     */
    public function validate() : bool
    {
        return
               parent::validate()
            && count($this->getAuthenticationData()) == 2
        ;
    }

    public function getScope()
    {
        return $this->scope;
    }
}
