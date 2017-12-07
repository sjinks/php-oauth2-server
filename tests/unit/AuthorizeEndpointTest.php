<?php

namespace Test;

use PHPUnit\Framework\TestCase;
use WildWolf\OAuth2\Endpoint\AuthorizeEndpoint;
use WildWolf\OAuth2\Interfaces\AuthorizerInterface;
use WildWolf\OAuth2\Interfaces\ResponseTypeInterface;
use WildWolf\OAuth2\Request\AuthorizeRequest;
use WildWolf\OAuth2\Response\ErrorResponse;
use Zend\Diactoros\ServerRequestFactory;
use Zend\Diactoros\Response;

class AuthorizeEndpointTest extends TestCase
{
    private static function getAE()
    {
        return new class extends AuthorizeEndpoint
        {
            public function __construct()
            {
                $this->rt_handlers['ok'] = 'something';

                parent::initialize(
                    ServerRequestFactory::fromGlobals(),
                    new class implements AuthorizerInterface
                    {
                        public $fail_tests = true;

                        public function initializeAuthorizer(AuthorizeRequest $request)
                        {
                        }

                        public function validateAuthorizeRequest() : bool
                        {
                            return !$this->fail_tests;
                        }

                        public function getRedirectUri() : string
                        {
                            return 'http://example.com/';
                        }

                        public function getAuthorizerValidationError() : ErrorResponse
                        {
                            return new ErrorResponse('temporarily_unavailable');
                        }
                    },
                    [
                        'ok' => new class implements ResponseTypeInterface
                        {
                            public function getRedirectUri(AuthorizeRequest $request, string $uri) : string
                            {
                                return $uri;
                            }
                        },
                    ]
                );
            }

            public function getAuthorizer()
            {
                return $this->authorizer;
            }

            public function getErrorResponse()
            {
                $result = $this->error;
                $this->error = null;
                return $result;
            }

            public function validateResponseType(string $rt = null) : bool
            {
                return parent::validateResponseType($rt);
            }

            public function validateClientId(string $cid = null) : bool
            {
                return parent::validateClientId($cid);
            }

            public function validateRedirectUri(string $uri = null) : bool
            {
                return parent::validateRedirectUri($uri);
            }

            public function setAuthorizeRequest(AuthorizeRequest $req)
            {
                $this->authRequest = $req;
            }
        };
    }

    /**
     * @dataProvider validateResponseTypeDataProvider
     * @param string|null $rt
     * @param bool $success
     * @param string $error
     */
    public function testValidateResponseType($rt, bool $success, string $error)
    {
        $ae     = self::getAE();
        $actual = $ae->validateResponseType($rt);

        $this->assertEquals($success, $actual);
        if (!$success) {
            $e = $ae->getErrorResponse();

            $this->assertNotNull($actual);
            $this->assertInstanceOf(ErrorResponse::class, $e);

            $this->assertEquals($error, $e->getError());
        }
    }

    public function validateResponseTypeDataProvider()
    {
        return [
            [null, false, 'invalid_request'],
            ['',   false, 'invalid_request'],
            ['xx', false, 'unsupported_response_type'],
            ['ok', true,  '']
        ];
    }

    /**
     * @dataProvider validateClientIdDataProvider
     * @param string|null $cid
     * @param bool $success
     * @param string $error
     */
    public function testValidateClientId($cid, bool $success, string $error)
    {
        $ae     = self::getAE();
        $actual = $ae->validateClientId($cid);

        $this->assertEquals($success, $actual);
        if (!$success) {
            $e = $ae->getErrorResponse();

            $this->assertNotNull($actual);
            $this->assertInstanceOf(ErrorResponse::class, $e);

            $this->assertEquals($error, $e->getError());
        }
    }

    public function validateClientIdDataProvider()
    {
        return [
            [null, false, 'invalid_request'],
            ['',   false, 'invalid_request'],
            ['ok', true,  '']
        ];
    }

    /**
     * @dataProvider validateRedirectUriDataProvider
     * @param string|null $uri
     * @param bool $success
     * @param string $error
     */
    public function testValidateRedirectUri($uri, bool $success, string $error)
    {
        $ae     = self::getAE();
        $actual = $ae->validateRedirectUri($uri);

        $this->assertEquals($success, $actual);
        if (!$success) {
            $e = $ae->getErrorResponse();

            $this->assertNotNull($actual);
            $this->assertInstanceOf(ErrorResponse::class, $e);

            $this->assertEquals($error, $e->getError());
        }
    }

    public function validateRedirectUriDataProvider()
    {
        return [
            [null,                    true,   ''],
            ['',                      true,   ''],
            [':',                     false,  'invalid_request'],
            ['/',                     false,  'invalid_request'],
            ['http://example.com/#x', false,  'invalid_request']
        ];
    }

    public function testValidateRequest()
    {
        $request = ServerRequestFactory::fromGlobals([], ['client_id' => 'cid', 'response_type' => 'ok']);
        $authreq = AuthorizeRequest::fromServerRequest($request);
        $ae      = self::getAE();
        $ae->setAuthorizeRequest($authreq);

        $ae->getAuthorizer()->fail_tests = true;

        $this->assertFalse($ae->validateRequest());

        $actual = $ae->getErrorResponse();
        $this->assertNotNull($actual);
        $this->assertInstanceOf(ErrorResponse::class, $actual);

        $this->assertEquals('temporarily_unavailable', $actual->getError());

        /**/

        $request = ServerRequestFactory::fromGlobals();
        $authreq = AuthorizeRequest::fromServerRequest($request);
        $ae->setAuthorizeRequest($authreq);

        $this->assertFalse($ae->validateRequest());

        $actual = $ae->getErrorResponse();
        $this->assertNotNull($actual);
        $this->assertInstanceOf(ErrorResponse::class, $actual);

        $this->assertEquals('invalid_request', $actual->getError());
    }

    public function testHandleAuthorizeRequest()
    {
        $request  = ServerRequestFactory::fromGlobals([], ['client_id' => 'cid', 'response_type' => 'ok']);
        $authreq  = AuthorizeRequest::fromServerRequest($request);
        $response = new Response();
        $ae       = self::getAE();
        $ae->setAuthorizeRequest($authreq);

        $ae->getAuthorizer()->fail_tests = true;

        $actual_response = $ae->handleAuthorizeRequest($response);
        $this->assertNotSame($response, $actual_response);

        $error_response  = $ae->getError(new Response());
        $this->assertEquals($error_response->getHeaders(),      $actual_response->getHeaders());
        $this->assertEquals($error_response->getStatusCode(),   $actual_response->getStatusCode());
        $this->assertEquals((string)$error_response->getBody(), (string)$actual_response->getBody());

        $error = $ae->getErrorResponse();
        $this->assertNotNull($error);
        $this->assertInstanceOf(ErrorResponse::class, $error);
        $this->assertEquals('temporarily_unavailable', $error->getError());

        /**/
        $response = new Response();
        $ae->getAuthorizer()->fail_tests = false;

        $actual_response = $ae->handleAuthorizeRequest($response);
        $this->assertNotSame($response, $actual_response);

        {
            $expected = new Response();
            $actual   = $ae->getError($expected);
            $this->assertSame($expected, $actual);
        }

        /**/
        $response = new Response();
        $ae->getAuthorizer()->fail_tests = false;

        $actual_response = $ae->handleAuthorizeRequest($response, true);
        $this->assertNotSame($response, $actual_response);

        $error = $ae->getErrorResponse();
        $this->assertNotNull($error);
        $this->assertInstanceOf(ErrorResponse::class, $error);
        $this->assertEquals('access_denied', $error->getError());
    }
}
