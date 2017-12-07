<?php

namespace Test;

use PHPUnit\Framework\TestCase;
use WildWolf\OAuth2\Interfaces\AuthorizationCodeGeneratorInterface;
use WildWolf\OAuth2\Request\AuthorizeRequest;
use WildWolf\OAuth2\ResponseType\Code;
use Zend\Diactoros\ServerRequestFactory;

class ResponseTypeCodeTest extends TestCase
{
    private static function getACGI()
    {
        return new class implements AuthorizationCodeGeneratorInterface
        {
            public function generateAuthorizationCode(AuthorizeRequest $request) : string
            {
                return 'ABCD';
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
        $code = new Code(self::getACGI());
        $req  = ServerRequestFactory::fromGlobals([], $get);
        $ar   = AuthorizeRequest::fromServerRequest($req);

        $actual = $code->getRedirectUri($ar, $uri);
        $this->assertEquals($expected, $actual);
    }

    public function getRedirectUriDataProvider()
    {
        return [
            [['state' => 'state'], 'https://example.com/',     'https://example.com/?code=ABCD&state=state'],
            [[],                   'https://example.com',      'https://example.com/?code=ABCD'],
            [[],                   'https://example.com:443',  'https://example.com:443/?code=ABCD'],
            [[],                   'https://example.com:443?', 'https://example.com:443/?code=ABCD'],
            [[],                   'https://example.com?a=b',  'https://example.com/?a=b&code=ABCD']
        ];
    }
}
