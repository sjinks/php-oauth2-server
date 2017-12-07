<?php

namespace Test;

use PHPUnit\Framework\TestCase;
use WildWolf\OAuth2\Request\AuthorizationCodeRequest;
use WildWolf\OAuth2\Request\PasswordRequest;
use WildWolf\OAuth2\Request\ClientCredentialsRequest;
use WildWolf\OAuth2\Request\RefreshTokenRequest;
use WildWolf\OAuth2\Request\BaseTokenRequest;
use Zend\Diactoros\ServerRequestFactory;
use WildWolf\OAuth2\Request\TokenRequestFactory;

class TokenRequestFactoryTest extends TestCase
{
    /**
     * @dataProvider creationDataProvider
     */
    public function testCreation($grant_type, $class, $valid)
    {
        $request = ServerRequestFactory::fromGlobals(
            [],
            [],
            ['grant_type' => $grant_type],
            [],
            []
        );

        $res = TokenRequestFactory::create($request);
        $this->assertInstanceOf($class, $res);
        $this->assertEquals($class, get_class($res));
        $this->assertEquals($grant_type, $res->getGrantType());
        $this->assertEquals($valid, $res->validate());
        $this->assertNull($res->getClientId());
        $this->assertNull($res->getClientSecret());
        $this->assertSame($request, $res->getRequest());
    }

    public function creationDataProvider()
    {
        return [
            ['authorization_code', AuthorizationCodeRequest::class, false],
            ['password',           PasswordRequest::class,          false],
            ['client_credentials', ClientCredentialsRequest::class, false],
            ['refresh_token',      RefreshTokenRequest::class,      false],
            [null,                 BaseTokenRequest::class,         false],
            ['unknown',            BaseTokenRequest::class,         true]
        ];
    }
}
