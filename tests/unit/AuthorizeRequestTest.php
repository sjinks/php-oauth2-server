<?php

namespace Test;

use PHPUnit\Framework\TestCase;
use Zend\Diactoros\ServerRequestFactory;
use WildWolf\OAuth2\Request\AuthorizeRequest;
use WildWolf\OAuth2\Response\ErrorResponse;

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

    /**
     * @dataProvider validateDataProvider
     * @param array $in
     * @param array $expected
     */
    public function testValidate(array $in, array $expected)
    {
        $request = ServerRequestFactory::fromGlobals([], $in);
        $ar      = AuthorizeRequest::fromServerRequest($request);

        $result  = $ar->validate();

        if ($expected[0] === true) {
            $this->assertSame(true, $result);
        }
        else {
            $this->assertInstanceOf(ErrorResponse::class, $result);
            $this->assertEquals($expected[1], $result->getError());
            $this->assertEquals($expected[2], $result->getErrorDescription());
        }
    }

    public function validateDataProvider()
    {
        return [
            // Response Type
            [
                [
                    'client_id'     => 'client',
                    'redirect_uri'  => 'http://example.com/',
                    'scope'         => 'scope',
                    'state'         => 'state',
                ],
                [false, 'invalid_request', 'response_type parameter is absent or invalid.']
            ],
            [
                [
                    'response_type' => '',
                    'client_id'     => 'client',
                    'redirect_uri'  => 'http://example.com/',
                    'scope'         => 'scope',
                    'state'         => 'state',
                ],
                [false, 'invalid_request', 'response_type parameter is absent or invalid.']
            ],
            // Client ID
            [
                [
                    'response_type' => 'token',
                    'redirect_uri'  => 'http://example.com/',
                    'scope'         => 'scope',
                    'state'         => 'state',
                ],
                [false, 'invalid_request', 'client_id parameter is absent or invalid.']
            ],
            [
                [
                    'response_type' => 'token',
                    'client_id'     => '',
                    'redirect_uri'  => 'http://example.com/',
                    'scope'         => 'scope',
                    'state'         => 'state',
                ],
                [false, 'invalid_request', 'client_id parameter is absent or invalid.']
            ],
            // Redirect URI
            [
                [
                    'response_type' => 'token code',
                    'client_id'     => 'client',
                    'scope'         => 'scope',
                    'state'         => 'state',
                ],
                [true]
            ],
            [
                [
                    'response_type' => 'token code',
                    'client_id'     => 'client',
                    'redirect_uri'  => '',
                    'scope'         => 'scope',
                    'state'         => 'state',
                ],
                [true]
            ],
            [
                [
                    'response_type' => 'token code',
                    'client_id'     => 'client',
                    'redirect_uri'  => ':',
                    'scope'         => 'scope',
                    'state'         => 'state',
                ],
                [false, 'invalid_request', 'redirect_uri is not a valid URI.']
            ],
            [
                [
                    'response_type' => 'token code',
                    'client_id'     => 'client',
                    'redirect_uri'  => '/path',
                    'scope'         => 'scope',
                    'state'         => 'state',
                ],
                [false, 'invalid_request', 'redirect_uri is not an absolute URI.']
            ],
            [
                [
                    'response_type' => 'token code',
                    'client_id'     => 'client',
                    'redirect_uri'  => 'http://example.com/path#fragment',
                    'scope'         => 'scope',
                    'state'         => 'state',
                ],
                [false, 'invalid_request', 'redirect_uri must not contain a fragment component.']
            ],
            // OK
            [
                [
                    'response_type' => 'token code',
                    'client_id'     => 'client',
                    'redirect_uri'  => 'http://example.com/',
                    'scope'         => 'scope',
                    'state'         => 'state',
                ],
                [true]
            ]
        ];
    }
}
