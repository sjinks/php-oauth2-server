<?php

namespace Test;

use PHPUnit\Framework\TestCase;
use WildWolf\OAuth2\Interfaces\ImplicitGrantAccessTokenGeneratorInterface;
use WildWolf\OAuth2\Request\AuthorizeRequest;
use WildWolf\OAuth2\Response\BaseResponse;
use WildWolf\OAuth2\Response\AccessTokenResponse;
use WildWolf\OAuth2\ResponseType\Token;
use Zend\Diactoros\ServerRequestFactory;

class ResponseTypeTokenTest extends TestCase
{
    private static function getIGATGI()
    {
        return new class implements ImplicitGrantAccessTokenGeneratorInterface
        {
            public function generateImplicitGrantAccessToken(AuthorizeRequest $request) : BaseResponse
            {
                return new AccessTokenResponse('ABCD', 'bearer', 3600);
            }
        };
    }

    /**
     * @dataProvider getRedirectUriDataProvider
     * @param array $get
     * @param string $uri
     * @param string $expected
     */
    public function testGetRedirectUri(array $get, string $uri, string $expected)
    {
        $tkn = new Token(self::getIGATGI());
        $req = ServerRequestFactory::fromGlobals([], $get);
        $ar  = AuthorizeRequest::fromServerRequest($req);

        $actual = $tkn->getRedirectUri($ar, $uri);
        $this->assertEquals($expected, $actual);
    }

    public function getRedirectUriDataProvider()
    {
        return [
            [['state' => 'state'], 'https://example.com/',     'https://example.com/#access_token=ABCD&token_type=bearer&expires_in=3600&state=state'],
            [[],                   'https://example.com',      'https://example.com/#access_token=ABCD&token_type=bearer&expires_in=3600'],
            [[],                   'https://example.com:443',  'https://example.com:443/#access_token=ABCD&token_type=bearer&expires_in=3600'],
            [[],                   'https://example.com:443?', 'https://example.com:443/#access_token=ABCD&token_type=bearer&expires_in=3600'],
            [[],                   'https://example.com?a=b',  'https://example.com/?a=b#access_token=ABCD&token_type=bearer&expires_in=3600']
        ];
    }
}
