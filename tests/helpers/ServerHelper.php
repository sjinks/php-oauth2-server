<?php

namespace Test\Helpers;

use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Message\ResponseInterface;
use WildWolf\OAuth2\Server;
use Zend\Diactoros\ServerRequestFactory;
use Zend\Diactoros\Response;

class ServerHelper extends Server
{
    public function __construct()
    {
        parent::__construct(ServerRequestFactory::fromGlobals(), new Response());
    }

    public function setRequest(ServerRequestInterface $req)
    {
        $this->request = $req;
    }

    public function setResponse(ResponseInterface $resp)
    {
        $this->response = $resp;
    }
}
