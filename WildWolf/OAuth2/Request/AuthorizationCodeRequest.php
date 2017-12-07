<?php

namespace WildWolf\OAuth2\Request;

use Psr\Http\Message\ServerRequestInterface;

class AuthorizationCodeRequest extends BaseTokenRequest
{
    protected $code;
    protected $redirect_uri;
    protected $scope;

    /**
     * {@inheritDoc}
     * @see \WildWolf\OAuth2\Request\BaseTokenRequest::createFromRequest()
     * @see https://tools.ietf.org/html/rfc6749#section-4.1.3
     */
    protected function createFromRequest(ServerRequestInterface $req)
    {
        parent::createFromRequest($req);
        $p = $req->getParsedBody();

        $this->code         = $p['code']         ?? null;
        $this->redirect_uri = $p['redirect_uri'] ?? null;
        $this->scope        = $p['scope']        ?? null;

        return $this;
    }

    /**
     * {@inheritDoc}
     * @see \WildWolf\OAuth2\Request\BaseTokenRequest::validate()
     * @see https://tools.ietf.org/html/rfc6749#section-4.1.3
     */
    public function validate() : bool
    {
        return
               parent::validate()
            && !empty($this->code)
            && (count($this->getAuthenticationData()) == 2 || $this->getClientId() !== null)
        ;
    }

    public function getCode()
    {
        return $this->code;
    }

    public function getRedirectUri()
    {
        return $this->redirect_uri;
    }

    public function getScope()
    {
        return $this->scope;
    }
}
