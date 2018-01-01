<?php

namespace Test;

use PHPUnit\Framework\TestCase;
use WildWolf\OAuth2\Interfaces\ClientVerifierInterface;
use WildWolf\OAuth2\Interfaces\TokenGeneratorInterface;
use WildWolf\OAuth2\GrantType\DefaultGrantTypeHandler;
use WildWolf\OAuth2\Request\BaseTokenRequest;
use WildWolf\OAuth2\Response\BaseResponse;
use WildWolf\OAuth2\Response\AccessTokenResponse;
use WildWolf\OAuth2\Response\ErrorResponse;
use Zend\Diactoros\ServerRequestFactory;

class DefaultGrantTypeHandlerTest extends TestCase
{
    private static function getTGI()
    {
        return new class implements TokenGeneratorInterface
        {
            public function generateAccessToken(BaseTokenRequest $req) : BaseResponse
            {
                return new AccessTokenResponse('ABCD');
            }
        };
    }

    private function getCVI()
    {
        return new class implements ClientVerifierInterface
        {
            public function verifyClient(BaseTokenRequest $request)
            {
                return true;
            }
        };
    }

    private function getTGCVI()
    {
        return new class implements TokenGeneratorInterface, ClientVerifierInterface
        {
            public function generateAccessToken(BaseTokenRequest $req) : BaseResponse
            {
                return new AccessTokenResponse('ABCD');
            }

            public function verifyClient(BaseTokenRequest $request)
            {
                return new ErrorResponse('server_error');
            }
        };
    }

    public function testCreateSeparateInterfaces()
    {
        $request = ServerRequestFactory::fromGlobals([], [], ['grant_type' => 'xxx']);
        $handler = new DefaultGrantTypeHandler(self::getTGI(), self::getCVI());
        $req     = BaseTokenRequest::fromRequest($request);
        $actual  = $handler->generateAccessToken($req);

        $this->assertInstanceOf(BaseResponse::class, $actual);
        $this->assertInstanceOf(AccessTokenResponse::class, $actual);
    }

    public function testCreateSingleInterafce()
    {
        $request = ServerRequestFactory::fromGlobals([], [], ['grant_type' => 'xxx']);
        $handler = new DefaultGrantTypeHandler(self::getTGCVI());
        $req     = BaseTokenRequest::fromRequest($request);
        $actual  = $handler->generateAccessToken($req);

        $this->assertInstanceOf(BaseResponse::class, $actual);
        $this->assertInstanceOf(ErrorResponse::class, $actual);
    }
}
