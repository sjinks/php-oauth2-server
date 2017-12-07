<?php

namespace Test;

use PHPUnit\Framework\TestCase;
use Zend\Diactoros\ServerRequestFactory;
use WildWolf\OAuth2\Request\BaseTokenRequest;
use function WildWolf\OAuth2\Request\apache_request_headers;

class BaseTokenRequestTest extends TestCase
{
    public static function setUpBeforeClass()
    {
        \Test\Helpers\MockFunctions::instance();
    }

    public static function tearDownAfterClass()
    {
        apache_request_headers([]);
    }

    /**
     * @dataProvider authenticationDataProvider
     * @param array $server
     * @param array $post
     * @param bool $outcome
     */
    public function testAuthenticatonData(array $server, array $post, bool $outcome)
    {
        $request = ServerRequestFactory::fromGlobals($server, [], $post);
        $btr     = BaseTokenRequest::fromRequest($request);
        $this->assertEquals($outcome, $btr->validate());
    }

    public function authenticationDataProvider()
    {
        return [
            [
                ['PHP_AUTH_USER' => 'user', 'PHP_AUTH_PW' => 'pass'],
                ['client_id' => 'user', 'client_secret' => 'secret', 'grant_type' => 'password'],
                false
            ],
            [
                [],
                ['client_secret' => 'secret', 'grant_type' => 'password'],
                false
            ],
            [
                ['PHP_AUTH_USER' => 'user', 'PHP_AUTH_PW' => 'pass', 'HTTP_AUTHORIZATION' => 'Basic dXNlcjpwYXNz', 'REDIRECT_HTTP_AUTHORIZATION' => 'basic dXNlcjpwYXNz'],
                ['grant_type' => 'password'],
                true
            ],
            [
                ['HTTP_AUTHORIZATION' => 'BASIC dXNlcjpwYXNz'],
                ['grant_type' => 'password'],
                true
            ],
            [
                ['REDIRECT_HTTP_AUTHORIZATION' => 'basic dXNlcjpwYXNz'],
                ['grant_type' => 'password'],
                true
            ],
        ];
    }

    /**
     * @dataProvider authenticationDataValuesProvider
     * @param array $server
     * @param array $post
     * @param array $headers
     * @param array $outcome
     */
    public function testAuthenticationDataValues(array $server, array $post, array $headers, array $outcome)
    {
        apache_request_headers($headers);
        $request = ServerRequestFactory::fromGlobals($server, [], $post);
        $btr     = BaseTokenRequest::fromRequest($request);
        $this->assertEquals($outcome, $btr->getAuthenticationData());
    }

    public function authenticationDataValuesProvider()
    {
        return [
            [
                ['PHP_AUTH_USER' => 'user', 'PHP_AUTH_PW' => 'pass'],
                ['grant_type' => 'password'],
                [],
                ['user', 'pass']
            ],
            [
                ['HTTP_AUTHORIZATION' => 'Basic dXNlcjpwYXNz'],
                ['grant_type' => 'password'],
                [],
                ['user', 'pass']
            ],
            [
                ['REDIRECT_HTTP_AUTHORIZATION' => 'basic dXNlcjpwYXNz'],
                ['grant_type' => 'password'],
                [],
                ['user', 'pass']
            ],
            [
                [],
                ['grant_type' => 'password'],
                ['Authorization' => 'basic dXNlcjpwYXNz'],
                ['user', 'pass']
            ],
            [
                [],
                ['client_id' => 'client', 'client_secret' => 'secret', 'grant_type' => 'password'],
                [],
                ['client', 'secret']
            ],
        ];
    }
}
