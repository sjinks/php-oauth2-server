<?php

namespace FunctionalTest;

use PHPUnit\Framework\TestCase;
use WildWolf\OAuth2\Endpoint\AuthorizeEndpoint;
use WildWolf\OAuth2\ResponseType\Code;
use WildWolf\OAuth2\ResponseType\Token;
use Zend\Diactoros\ServerRequestFactory;
use Zend\Diactoros\Response;
use Test\Helpers\SampleAuthorizer;

class AuthorizeEndpointTest extends TestCase
{
    /**
     * @dataProvider validationFailuresDataProvider
     */
    public function testValidationFailures($client_id, $response_type, $redirect_uri, $error, $error_desc)
    {
        $request = ServerRequestFactory::fromGlobals(
            [],
            ['client_id' => $client_id, 'response_type' => $response_type, 'redirect_uri' => $redirect_uri]
        );

        $response = new Response();

        $auth = new SampleAuthorizer();
        $ae = new AuthorizeEndpoint();
        $ae->initialize(
            $request,
            $auth,
            ['code' => new Code($auth)]
        );

        $valid    = $ae->validateRequest();
        $response = $ae->getError($response);

        $this->assertFalse($valid);
        $this->assertEquals(400, $response->getStatusCode());

        $body = (string)$response->getBody();
        $arr  = json_decode($body, true);

        $this->assertTrue(is_array($arr));
        $this->assertArrayHasKey('error', $arr);
        $this->assertArrayHasKey('error_description', $arr);
        $this->assertEquals($error, $arr['error']);
        $this->assertEquals($error_desc, $arr['error_description']);
    }

    /**
     * @dataProvider validationFailuresDataProvider
     */
    public function testHandleRequestFailures($client_id, $response_type, $redirect_uri, $error, $error_desc)
    {
        $request = ServerRequestFactory::fromGlobals(
            [],
            ['client_id' => $client_id, 'response_type' => $response_type, 'redirect_uri' => $redirect_uri]
        );

        $response = new Response();

        $auth = new SampleAuthorizer();
        $ae = new AuthorizeEndpoint();
        $ae->initialize(
            $request,
            $auth,
            ['code' => new Code($auth)]
        );

        $response = $ae->handleAuthorizeRequest($response, false);

        $this->assertEquals(400, $response->getStatusCode());

        $body = (string)$response->getBody();
        $arr  = json_decode($body, true);

        $this->assertTrue(is_array($arr));
        $this->assertArrayHasKey('error', $arr);
        $this->assertArrayHasKey('error_description', $arr);
        $this->assertEquals($error, $arr['error']);
        $this->assertEquals($error_desc, $arr['error_description']);
    }

    public function validationFailuresDataProvider()
    {
        return [
            ['',            'code', 'http://example.com/', 'invalid_request',           'client_id parameter is absent or invalid.'],
            ['test-client', '',     'http://example.com/', 'invalid_request',           'response_type parameter is absent or invalid.'],
            ['test-client', 'code', '/uri',                'invalid_request',           'redirect_uri is not an absolute URI.'],
            ['test-client', 'xxxx', 'http://example.com/', 'unsupported_response_type', 'The authorization server does not support obtaining an authorization code using method "xxxx".'],
            ['test-client', 'code', ':',                   'invalid_request',           'redirect_uri is not a valid URI.'],
            ['test-client', 'code', 'http://ex.com/#frag', 'invalid_request',           'redirect_uri must not contain a fragment component.'],
        ];
    }

    /**
     * @dataProvider authorizerValidationFailuresDataProvider
     */
    public function testAuthorizerValidationFailures($client_id, $response_type, $redirect_uri, $error)
    {
        $request = ServerRequestFactory::fromGlobals(
            [],
            ['client_id' => $client_id, 'response_type' => $response_type, 'redirect_uri' => $redirect_uri]
        );

        $response = new Response();

        $auth = new SampleAuthorizer();
        $ae = new AuthorizeEndpoint();
        $ae->initialize(
            $request,
            $auth,
            ['code' => new Code($auth)]
        );

        $auth->setResponse($error);

        $valid    = $ae->validateRequest();
        $response = $ae->getError($response);

        $this->assertFalse($valid);
        $this->assertEquals(400, $response->getStatusCode());

        $body = (string)$response->getBody();
        $arr  = json_decode($body, true);

        $this->assertTrue(is_array($arr));
        $this->assertArrayHasKey('error', $arr);
        $this->assertEquals($error, $arr['error']);
    }

    /**
     * @dataProvider authorizerValidationFailuresDataProvider
     */
    public function testAuthorizerValidationFailuresRedirect($client_id, $response_type, $redirect_uri, $error, $target)
    {
        $request = ServerRequestFactory::fromGlobals(
            [],
            ['client_id' => $client_id, 'response_type' => $response_type, 'redirect_uri' => $redirect_uri]
        );

        $response = new Response();

        $auth = new SampleAuthorizer();
        $ae = new AuthorizeEndpoint();
        $ae->initialize(
            $request,
            $auth,
            ['code' => new Code($auth)]
        );

        $auth->setResponse($error, $redirect_uri);

        $valid    = $ae->validateRequest();
        $response = $ae->getError($response);

        $this->assertFalse($valid);
        $this->assertEquals(302, $response->getStatusCode());
        $this->assertTrue($response->hasHeader('Location'));

        $uri = $response->getHeaderLine('Location');
        $this->assertEquals($target, $uri);
    }

    public function authorizerValidationFailuresDataProvider()
    {
        return [
            ['test-client', 'code', 'http://example.com/',     'access_denied', 'http://example.com/?error=access_denied'],
            ['test-client', 'code', 'http://example.com/?a=1', 'invalid_scope', 'http://example.com/?a=1&error=invalid_scope'],
        ];
    }

    public function testDenyAuth()
    {
        $request = ServerRequestFactory::fromGlobals(
            [],
            ['client_id' => 'client', 'response_type' => 'code']
        );

        $response = new Response();

        $auth = new SampleAuthorizer();
        $ae = new AuthorizeEndpoint();
        $ae->initialize(
            $request,
            $auth,
            ['code' => new Code($auth)]
        );

        $response = $ae->handleAuthorizeRequest($response, true);

        $this->assertEquals(400, $response->getStatusCode());

        $body = (string)$response->getBody();
        $arr  = json_decode($body, true);

        $this->assertTrue(is_array($arr));
        $this->assertArrayHasKey('error', $arr);
        $this->assertArrayHasKey('error_description', $arr);
        $this->assertEquals('access_denied', $arr['error']);
        $this->assertEquals('The user or authorization server denied the request.', $arr['error_description']);
    }

    public function testSuccessfulAuth()
    {
        $request = ServerRequestFactory::fromGlobals(
            [],
            ['client_id' => 'client', 'response_type' => 'code']
        );

        $response = new Response();

        $auth = new SampleAuthorizer();
        $ae = new AuthorizeEndpoint();
        $ae->initialize(
            $request,
            $auth,
            ['code' => new Code($auth)]
        );

        $auth->setResponse(false, 'https://example.com/', 'abcdef');

        $response = $ae->handleAuthorizeRequest($response);

        $this->assertEquals(302, $response->getStatusCode());

        $this->assertTrue($response->hasHeader('Location'));

        $uri = $response->getHeaderLine('Location');
        $this->assertEquals('https://example.com/?code=abcdef', $uri);
    }

    public function testImplicitGrant()
    {
        $request = ServerRequestFactory::fromGlobals(
            [],
            ['client_id' => 'client', 'response_type' => 'token']
        );

        $response = new Response();

        $auth = new SampleAuthorizer();
        $ae = new AuthorizeEndpoint();
        $ae->initialize(
            $request,
            $auth,
            ['token' => new Token($auth)]
        );

        $auth->setResponse(false, 'https://example.com/', 'abcdef');

        $response = $ae->handleAuthorizeRequest($response);

        $this->assertEquals(302, $response->getStatusCode());

        $this->assertTrue($response->hasHeader('Location'));

        $uri = $response->getHeaderLine('Location');
        $this->assertEquals('https://example.com/#access_token=abcdef&token_type=bearer&expires_in=3600', $uri);
    }
}

