<?php

namespace Test;

use PHPUnit\Framework\TestCase;
use Zend\Diactoros\ServerRequestFactory;
use WildWolf\OAuth2\Request\AuthorizeRequest;

class AuthorizeRequestTest extends TestCase
{
    /**
     * @dataProvider creationDataProvider
     * @param array $in
     * @param array $out
     */
    public function testCreation(array $in, array $out)
    {
        $params  = [
            'response_type' => 'code',
            'client_id'     => 'client',
            'redirect_uri'  => 'http://example.com/',
            'scope'         => 'scope',
            'state'         => 'state',
        ];

        $request = ServerRequestFactory::fromGlobals([], $in);
        $ar      = AuthorizeRequest::fromServerRequest($request);

        $this->assertSame($request, $ar->getRequest());
        $this->assertEquals($out['response_type'], $ar->getResponseType());
        $this->assertEquals($out['client_id'],     $ar->getClientId());
        $this->assertEquals($out['redirect_uri'],  $ar->getRedirectUri());
        $this->assertEquals($out['scope'],         $ar->getScope());
        $this->assertEquals($out['state'],         $ar->getState());
    }

    public function creationDataProvider()
    {
        return [
            [
                [
                    'response_type' => 'code',
                    'client_id'     => 'client',
                    'redirect_uri'  => 'http://example.com/',
                    'scope'         => 'scope',
                    'state'         => 'state',
                ],
                [
                    'response_type' => 'code',
                    'client_id'     => 'client',
                    'redirect_uri'  => 'http://example.com/',
                    'scope'         => 'scope',
                    'state'         => 'state',
                ]
            ],
            [
                [
                    'response_type' => 'token code',
                    'client_id'     => 'client',
                    'redirect_uri'  => 'http://example.com/',
                    'scope'         => 'scope',
                    'state'         => 'state',
                ],
                [
                    'response_type' => 'code token',
                    'client_id'     => 'client',
                    'redirect_uri'  => 'http://example.com/',
                    'scope'         => 'scope',
                    'state'         => 'state',
                ]
            ],
            [
                [
                ],
                [
                    'response_type' => null,
                    'client_id'     => null,
                    'redirect_uri'  => null,
                    'scope'         => null,
                    'state'         => null,
                ]
            ]
        ];
    }
}
