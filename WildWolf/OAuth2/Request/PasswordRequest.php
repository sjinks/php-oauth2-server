<?php

namespace WildWolf\OAuth2\Request;

use Psr\Http\Message\ServerRequestInterface;

class PasswordRequest extends BaseTokenRequest
{
    protected $username;
    protected $password;
    protected $scope;

    /**
     * {@inheritDoc}
     * @see \WildWolf\OAuth2\Request\BaseTokenRequest::createFromRequest()
     * @see https://tools.ietf.org/html/rfc6749#section-4.3
     */
    protected function createFromRequest(ServerRequestInterface $req)
    {
        parent::createFromRequest($req);
        $p = $req->getParsedBody();

        $this->username = $p['username'] ?? null;
        $this->password = $p['password'] ?? null;
        $this->scope    = $p['scope']    ?? null;

        return $this;
    }

    /**
     * {@inheritDoc}
     * @see \WildWolf\OAuth2\Request\BaseTokenRequest::validate()
     * @see https://tools.ietf.org/html/rfc6749#section-4.3.2
     */
    public function validate() : bool
    {
        return
               parent::validate()
            && $this->username !== null
            && $this->password !== null
        ;
    }

    public function getUsername()
    {
        return $this->username;
    }

    public function getPassword()
    {
        return $this->password;
    }

    public function getScope()
    {
        return $this->scope;
    }
}
