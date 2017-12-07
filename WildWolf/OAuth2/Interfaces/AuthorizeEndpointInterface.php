<?php

namespace WildWolf\OAuth2\Interfaces;

use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;

interface AuthorizeEndpointInterface
{
    public function initialize(ServerRequestInterface $request, AuthorizerInterface $authorizer, array $handlers);
    public function getError(ResponseInterface $response) : ResponseInterface;
    public function handleAuthorizeRequest(ResponseInterface $response, bool $deny = false) : ResponseInterface;
    public function validateRequest() : bool;
}
