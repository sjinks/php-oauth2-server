<?php

namespace WildWolf\OAuth2\Interfaces;

use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;

interface TokenEndpointInterface
{
    public function initialize(ServerRequestInterface $request, array $handlers);
    public function handleTokenRequest(ResponseInterface $response) : ResponseInterface;
}
