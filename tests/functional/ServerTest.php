<?php

namespace FunctionalTest;

use PHPUnit\Framework\TestCase;
use PHPUnit\DbUnit\TestCaseTrait;
use PHPUnit\DbUnit\DataSet\IDataSet;
use PHPUnit\DbUnit\Database\Connection;
use PHPUnit\DbUnit\DataSet\ArrayDataSet;
use Test\Helpers\ServerHelper;
use Test\Helpers\Integration\Authorizer;
use Test\Helpers\Integration\AuthCodeGenerator;
use Test\Helpers\Integration\ImplicitFlowTokenGenerator;
use WildWolf\OAuth2\ResponseType\Code;
use Zend\Diactoros\ServerRequestFactory;
use Zend\Diactoros\Response;
use WildWolf\OAuth2\ResponseType\Token;
use Test\Helpers\Integration\CustomGrantTypeHandler;
use Psr\Http\Message\ResponseInterface;
use WildWolf\OAuth2\GrantType\DefaultGrantTypeHandler;
use Test\Helpers\Integration\AuthTokenGenerator;

/**
 * @requires extension pdo_sqlite
 */
class ServerTest extends TestCase
{
    use TestCaseTrait {
        TestCaseTrait::setUp as dbSetUp;
    }

    /**
     * @var ServerHelper
     */
    public $server;

    ///
    /**
     * @var \PDO
     */
    static private $pdo = null;

    /**
     * @var Connection
     */
    private $conn = null;

    final protected function getConnection() : Connection
    {
        if ($this->conn === null) {
            if (self::$pdo === null) {
                self::$pdo = new \PDO('sqlite::memory:');
            }

            $this->conn = $this->createDefaultDBConnection(self::$pdo, ':memory:');

            self::$pdo->query("
CREATE TABLE IF NOT EXISTS client (
  client_id VARCHAR(255) NOT NULL PRIMARY KEY,
  client_secret VARCHAR(32) NOT NULL,
  redirect_uri VARCHAR(255) NOT NULL
)
            ");

            self::$pdo->query("
CREATE TABLE IF NOT EXISTS access_token (
  token VARCHAR(32) NOT NULL PRIMARY KEY,
  expires INTEGER NOT NULL,
  client_id VARCHAR(255) NOT NULL,
  redirect_uri VARCHAR(255) NOT NULL,
  scope VARCHAR(255) NOT NULL
)
");

            self::$pdo->query("
CREATE TABLE IF NOT EXISTS authorization (
  code VARCHAR(32) NOT NULL PRIMARY KEY,
  token_type VARCHAR(32) NOT NULL,
  expires INTEGER NOT NULL,
  scope VARCHAR(255) NOT NULL
)
");

            self::$pdo->query("
CREATE TABLE IF NOT EXISTS refresh_token (
  token VARCHAR(32) NOT NULL PRIMARY KEY,
  expires INTEGER NOT NULL,
  code VARCHAR(32) NOT NULL,
  FOREIGN KEY (code) REFERENCES authorization(code) ON DELETE CASCADE ON UPDATE CASCADE
)
");
        }

        return $this->conn;
    }

    protected function getDataSet() : IDataSet
    {
        return new ArrayDataSet([
            'client' => [
                [
                    'client_id'     => 'client',
                    'client_secret' => 'secret',
                    'redirect_uri'  => 'http://example.com/'
                ]
            ],
        ]);
    }
    ///

    protected function setUp()
    {
        $this->dbSetUp();

        $server     = new ServerHelper();
        $pdo        = $this->getConnection()->getConnection();
        $authorizer = new Authorizer($pdo);
        $acgen      = new AuthCodeGenerator($pdo);
        $tgen       = new ImplicitFlowTokenGenerator($pdo);
        $atgen      = new AuthTokenGenerator($pdo);
        $custom_gt  = new CustomGrantTypeHandler($pdo);
        $server->setAuthorizer($authorizer);
        $server->addResponseTypeHandler('code', new Code($acgen));
        $server->addResponseTypeHandler('token', new Token($tgen));
        $server->addGrantTypeHandler('custom', $custom_gt);
        $server->addGrantTypeHandler('authorization_code', new DefaultGrantTypeHandler($atgen));

        $this->server = $server;
    }

    /**
     * @dataProvider authorizerIntegrationValidationDataProvider
     */
    public function testAuthorizerIntegrationValidation(array $get, array $validation)
    {
        $this->server->setRequest(ServerRequestFactory::fromGlobals([], $get));

        $response = $this->server->validateAuthorizeRequest();
        if ($validation[0] === true) {
            $this->assertTrue($response);
        }
        else {
            $this->assertEquals($validation[1], $response->getStatusCode());
            $this->assertTrue($response->hasHeader('Content-Type'));
            $this->assertContains('application/json', $response->getHeaderLine('Content-Type'));

            $body = json_decode($response->getBody()->__toString(), true);

            $this->assertArrayHasKey('error', $body);
            $this->assertArrayHasKey('error_description', $body);

            $this->assertEquals($validation[2], $body['error']);
            $this->assertEquals($validation[3], $body['error_description']);

            ///////
            $this->server->setResponse(new Response());
            $response = $this->server->handleAuthorizeRequest(false);

            $this->assertEquals($validation[1], $response->getStatusCode());
            $this->assertTrue($response->hasHeader('Content-Type'));
            $this->assertContains('application/json', $response->getHeaderLine('Content-Type'));

            $body = json_decode($response->getBody()->__toString(), true);

            $this->assertArrayHasKey('error', $body);
            $this->assertArrayHasKey('error_description', $body);

            $this->assertEquals($validation[2], $body['error']);
            $this->assertEquals($validation[3], $body['error_description']);
        }
    }

    public function authorizerIntegrationValidationDataProvider()
    {
        return [
            [
                ['client_id' => 'unknown', 'response_type' => 'code', 'redirect_uri' => 'http://example.com/'],
                [false, 400, 'unauthorized_client', 'client_id']
            ],
            [
                ['client_id' => 'client', 'response_type' => 'code', 'redirect_uri' => 'http://evil.com/'],
                [false, 400, 'unauthorized_client', 'redirect_uri']
            ],
            [
                ['client_id' => 'client', 'response_type' => 'code', 'redirect_uri' => 'http://example.com/'],
                [true, 0, '', '']
            ]
        ];
    }

    /**
     * @param array $get
     * @param bool $deny
     * @param array $expected
     * @dataProvider authorizerIntegrationProvider
     */
    public function testAuthorizerIntegration(array $get, bool $deny, array $expected)
    {
        $this->server->setRequest(ServerRequestFactory::fromGlobals([], $get));
        $response = $this->server->handleAuthorizeRequest($deny);

        $this->assertEquals($expected[0], $response->getStatusCode());
        $params = [];
        if ($response->getStatusCode() == 302) {
            $this->assertTrue($response->hasHeader('Location'));
            $url = $response->getHeaderLine('Location');

            $this->assertEquals($expected[2], substr($url, 0, strlen($expected[2])));

            $part = parse_url($url, $expected[1]);
            parse_str($part, $params);
        }
        else {
            $this->assertTrue($response->hasHeader('Content-Type'));
            $this->assertContains('application/json', $response->getHeaderLine('Content-Type'));

            $params = json_decode($response->getBody()->__toString(), true);
        }

        foreach ($expected[3] as $key => $val) {
            $this->assertArrayHasKey($key, $params);
            if ($val !== null) {
                $this->assertEquals($val, $params[$key]);
            }
        }
    }

    public function authorizerIntegrationProvider()
    {
        return [
            // Successful authorization
            [
                ['client_id' => 'client', 'response_type' => 'code', 'redirect_uri' => 'http://example.com/'],
                false,
                [302, PHP_URL_QUERY, 'http://example.com/?', ['code' => null]]
            ],
            // Invalid request, no redirect
            [
                [],
                false,
                [400, 0, '', ['error' => 'invalid_request']]
            ],
            // Access denied, redirect
            [
                ['client_id' => 'client', 'response_type' => 'code', 'redirect_uri' => 'http://example.com/'],
                true,
                [302, PHP_URL_QUERY, 'http://example.com/?', ['error' => 'access_denied', 'error_description' => 'The user or authorization server denied the request.']]
            ],
            // Successful authorization, ensure state is preserved
            [
                ['client_id' => 'client', 'response_type' => 'code', 'redirect_uri' => 'http://example.com/', 'state' => 'some-state'],
                false,
                [302, PHP_URL_QUERY, 'http://example.com/?', ['code' => null, 'state' => 'some-state']]
            ],
            // Invalid request, ensure state is preserved
            [
                ['state' => 'some-state'],
                false,
                [400, 0, '', ['error' => 'invalid_request', 'state' => 'some-state']]
            ],
            // Implicit flow, ensure state is preserved
            [
                ['client_id' => 'client', 'response_type' => 'token', 'redirect_uri' => 'http://example.com/', 'state' => 'some-state'],
                false,
                [302, PHP_URL_FRAGMENT, 'http://example.com/#', ['access_token' => null, 'expires_in' => null, 'token_type' => 'bearer', 'state' => 'some-state']]
            ],
        ];
    }

    /**
     * @param array $post
     * @param array $expected
     * @dataProvider tokenGenerationDataProvider
     */
    public function testTokenGeneration(array $post, array $expected)
    {
        $this->server->setRequest(ServerRequestFactory::fromGlobals([], [], $post));
        $response = $this->server->handleTokenRequest();

        $this->assertEquals($expected[0], $response->getStatusCode());
        $this->assertTrue($response->hasHeader('Content-Type'));
        $this->assertContains('application/json', $response->getHeaderLine('Content-Type'));

        $params = json_decode($response->getBody()->__toString(), true);
        foreach ($expected[1] as $key => $val) {
            $this->assertArrayHasKey($key, $params);
            if ($val !== null) {
                $this->assertEquals($val, $params[$key]);
            }
        }
    }

    public function tokenGenerationDataProvider()
    {
        return [
            [
                ['grant_type' => 'custom'],
                [200, ['access_token' => null, 'expires_in' => null, 'token_type' => 'custom']]
            ],
            [
                ['grant_type' => 'unknown'],
                [400, ['error' => 'unsupported_grant_type', 'error_description' => 'The authorization grant type "unknown" is not supported by the authorization server.']]
            ],
        ];
    }

    private function sendRequest(array $get, array $post, string $method, array $params = []) : ResponseInterface
    {
        $request = ServerRequestFactory::fromGlobals(
            ['REQUEST_METHOD' => (empty($_POST) ? 'GET' : 'POST')],
            $get,
            $post
        );

        $this->server->setRequest($request);
        $this->server->setResponse(new Response());

        return $this->server->$method(...$params);
    }

    public function testIntegration_CodeGrant()
    {
        // Authorization Request
        $get  = ['client_id' => 'client', 'response_type' => 'code', 'redirect_uri' => 'http://example.com/'];
        $post = [];
        $response = $this->sendRequest($get, $post, 'handleAuthorizeRequest', [false]);

        $this->assertEquals(302, $response->getStatusCode());
        $this->assertTrue($response->hasHeader('Location'));

        $url    = $response->getHeaderLine('Location');
        $part   = parse_url($url, PHP_URL_QUERY);
        $params = [];
        parse_str($part, $params);

        $this->assertArrayHasKey('code', $params);
        $code = $params['code'];

        // Access Token Request
        $get  = [];
        $post = ['grant_type' => 'authorization_code', 'code' => $code, 'client_id' => 'client', 'redirect_uri' => 'http://example.com/'];
        $response = $this->sendRequest($get, $post, 'handleTokenRequest');

        $this->assertEquals(200, $response->getStatusCode());
        $this->assertTrue($response->hasHeader('Content-Type'));
        $this->assertContains('application/json', $response->getHeaderLine('Content-Type'));

        $params = json_decode($response->getBody()->__toString(), true);

        $this->assertArrayHasKey('access_token',  $params);
        $this->assertArrayHasKey('expires_in',    $params);
        $this->assertArrayHasKey('refresh_token', $params);
        $this->assertArrayHasKey('token_type',    $params);
        $this->assertEquals('bearer', strtolower($params['token_type']));
    }

    public function testIntegration_ImplicitFlow()
    {
        // Authorization Request
        $get  = ['client_id' => 'client', 'response_type' => 'token', 'redirect_uri' => 'http://example.com/'];
        $post = [];
        $response = $this->sendRequest($get, $post, 'handleAuthorizeRequest', [false]);

        $this->assertEquals(302, $response->getStatusCode());
        $this->assertTrue($response->hasHeader('Location'));

        $url    = $response->getHeaderLine('Location');
        $part   = parse_url($url, PHP_URL_FRAGMENT);
        $params = [];
        parse_str($part, $params);

        $this->assertArrayHasKey('access_token',  $params);
        $this->assertArrayHasKey('expires_in',    $params);
        $this->assertArrayNotHasKey('refresh_token', $params);
        $this->assertArrayHasKey('token_type',    $params);
        $this->assertEquals('bearer', strtolower($params['token_type']));
    }
}
