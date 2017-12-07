<?php

namespace Test;

use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ServerRequestInterface;
use WildWolf\OAuth2\Endpoint\TokenEndpoint;
use WildWolf\OAuth2\Interfaces\TokenGeneratorInterface;
use WildWolf\OAuth2\Request\BaseTokenRequest;
use WildWolf\OAuth2\Response\BaseResponse;
use WildWolf\OAuth2\Response\ErrorResponse;
use WildWolf\OAuth2\Request\TokenRequestFactory;
use Zend\Diactoros\ServerRequestFactory;
use Zend\Diactoros\Response;

class TokenEndpointTest extends TestCase
{
    private static function getTE()
    {
        return new class extends TokenEndpoint
        {
            public function __construct()
            {
                parent::initialize(
                    ServerRequestFactory::fromGlobals(),
                    [
                        'secret' => new class implements TokenGeneratorInterface
                        {
                            public function generateAccessToken(BaseTokenRequest $req) : BaseResponse
                            {
                                return new ErrorResponse('unauthorized_client');
                            }
                        },
                    ]
                );
            }

            public function getErrorResponse()
            {
                $result = $this->error;
                $this->error = null;
                return $result;
            }

            public function setRequest(ServerRequestInterface $req)
            {
                $this->request      = $req;
                $this->tokenRequest = TokenRequestFactory::create($req);
            }
        };
    }

    public function testUnsupportedGrantType()
    {
        $te = self::getTE();

        $request = ServerRequestFactory::fromGlobals(['REQUEST_METHOD' => 'POST'], [], ['grant_type' => 'unknown']);
        $te->setRequest($request);

        $response = $te->handleTokenRequest(new Response());
        $this->assertEquals(400, $response->getStatusCode());

        $error = $te->getErrorResponse();
        $this->assertNotNull($error);
        $this->assertEquals('unsupported_grant_type', $error->getError());
    }

    public function testMissingGrantType()
    {
        $te = self::getTE();

        $request = ServerRequestFactory::fromGlobals(['REQUEST_METHOD' => 'POST']);
        $te->setRequest($request);

        $response = $te->handleTokenRequest(new Response());
        $this->assertEquals(400, $response->getStatusCode());

        $error = $te->getErrorResponse();
        $this->assertNotNull($error);
        $this->assertEquals('invalid_request', $error->getError());
    }

    public function testHandleTokenRequest()
    {
        $te = self::getTE();
        $request = ServerRequestFactory::fromGlobals(['REQUEST_METHOD' => 'POST'], [], ['grant_type' => 'secret']);
        $te->setRequest($request);

        $response = $te->handleTokenRequest(new Response());
        $this->assertEquals(400, $response->getStatusCode());

        $error = $te->getErrorResponse();
        $this->assertNotNull($error);
        $this->assertEquals('unauthorized_client', $error->getError());
    }
}
