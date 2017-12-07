<?php

namespace WildWolf\OAuth2;

use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Message\ResponseInterface;
use WildWolf\OAuth2\Interfaces\AuthorizerInterface;
use WildWolf\OAuth2\Interfaces\AuthorizeEndpointInterface;
use WildWolf\OAuth2\Interfaces\GrantTypeInterface;
use WildWolf\OAuth2\Interfaces\TokenEndpointInterface;
use WildWolf\OAuth2\Interfaces\ResponseTypeInterface;
use WildWolf\OAuth2\Endpoint\AuthorizeEndpoint;
use WildWolf\OAuth2\Endpoint\TokenEndpoint;

class Server
{
    /**
     * @var ServerRequestInterface
     */
    protected $request;

    /**
     * @var ResponseInterface
     */
    protected $response;

    /**
     * @var ResponseTypeInterface[]
     */
    protected $rt_handlers;

    /**
     * @var GrantTypeInterface[]
     */
    protected $gt_handlers;

    /**
     * @var AuthorizerInterface
     */
    protected $authorizer;

    /**
     * @var AuthorizeEndpointInterface
     */
    protected $authorize_ep;

    /**
     * @var TokenEndpointInterface
     */
    protected $token_ep;

    /**
     * @var string
     */
    protected $auth_ep_class = AuthorizeEndpoint::class;

    /**
     * @var string
     */
    protected $token_ep_class = TokenEndpoint::class;

    /**
     * @param ServerRequestInterface $request
     * @param ResponseInterface $response
     */
    public function __construct(ServerRequestInterface $request, ResponseInterface $response)
    {
        $this->request  = $request;
        $this->response = $response;
    }

    /**
     * @param string $class
     * @return self
     */
    public function setAuthorizeEndpoint(string $class) : self
    {
        $this->auth_ep_class = $class;
        return $this;
    }

    /**
     * @param string $class
     * @return self
     */
    public function setTokenEndpoint(string $class) : self
    {
        $this->token_ep_class = $class;
        return $this;
    }

    /**
     * @param AuthorizerInterface $authorizer
     * @return self
     */
    public function setAuthorizer(AuthorizerInterface $authorizer) : self
    {
        if ($this->authorizer !== $authorizer) {
            $this->authorizer   = $authorizer;
            $this->authorize_ep = null;
        }

        return $this;
    }

    /**
     * @param string $type
     * @param ResponseTypeInterface $handler
     * @return self
     */
    public function addResponseTypeHandler(string $type, ResponseTypeInterface $handler) : self
    {
        $this->rt_handlers[$type] = $handler;
        $this->authorize_ep       = null;
        return $this;
    }

    /**
     * @param string $type
     * @param GrantTypeInterface $handler
     * @return self
     */
    public function addGrantTypeHandler(string $type, GrantTypeInterface $handler) : self
    {
        $this->gt_handlers[$type] = $handler;
        $this->token_ep           = null;
        return $this;
    }

    /**
     * @param bool $deny
     * @return \Psr\Http\Message\ResponseInterface
     */
    public function handleAuthorizeRequest(bool $deny)
    {
        $ep = $this->getAuthorizeEndpoint();
        return $ep->handleAuthorizeRequest($this->response, $deny);
    }

    /**
     * @return boolean|\Psr\Http\Message\ResponseInterface
     */
    public function validateAuthorizeRequest()
    {
        $ep = $this->getAuthorizeEndpoint();
        if ($ep->validateRequest()) {
            return true;
        }

        return $ep->getError($this->response);
    }

    public function handleTokenRequest()
    {
        $ep = $this->getTokenEndpoint();
        return $ep->handleTokenRequest($this->response);
    }

    /**
     * @return \WildWolf\OAuth2\Interfaces\AuthorizeEndpointInterface
     */
    private function getAuthorizeEndpoint() : AuthorizeEndpointInterface
    {
        if (!$this->authorize_ep) {
            $class              = $this->auth_ep_class;
            $this->authorize_ep = new $class;
            $this->authorize_ep->initialize($this->request, $this->authorizer, $this->rt_handlers);
        }

        return $this->authorize_ep;
    }

    /**
     * @return TokenEndpointInterface
     */
    private function getTokenEndpoint() : TokenEndpointInterface
    {
        if (!$this->token_ep) {
            $class          = $this->token_ep_class;
            $this->token_ep = new $class;
            $this->token_ep->initialize($this->request, $this->gt_handlers);
        }

        return $this->token_ep;
    }
}
