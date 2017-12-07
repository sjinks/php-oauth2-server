<?php

namespace Test;

use PHPUnit\Framework\TestCase;
use WildWolf\OAuth2\Response\ErrorResponse;
use Zend\Diactoros\Response;

class ErrorResponseTest extends TestCase
{
    /**
     * @dataProvider creationDataProvider
     * @param string $error
     * @param string|null $desc
     * @param string|null $uri
     * @param array $expect
     */
    public function testCreation($error, $desc, $uri, array $expected)
    {
        $er = new ErrorResponse($error, $desc, $uri);
        $this->assertEquals($expected, $er->toArray());
        $this->assertEmpty($er->getExtraHeaders());
        $this->assertEquals(400, $er->getStatusCode());
        $this->assertEquals($expected['error'], $er->getError());
    }

    public function creationDataProvider()
    {
        return [
            ['invalid_request', null, null, ['error' => 'invalid_request']],
            ['invalid_request', null, '#',  ['error' => 'invalid_request', 'error_uri' => '#']],
            ['invalid_request', 'xxx', '#', ['error' => 'invalid_request', 'error_description' => 'xxx', 'error_uri' => '#']],
        ];
    }

    public function testExtraHeaders()
    {
        $response = new Response();
        $er = new ErrorResponse('access_denied');
        $this->assertEmpty($er->getExtraHeaders());

        $er->setHeader('header', 'value');
        $this->assertNotEmpty($er->getExtraHeaders());
        $this->assertEquals(['header' => 'value'], $er->getExtraHeaders());

        $r = $er->toResponseInterface($response);
        $this->assertTrue($r->hasHeader('header'));

        $er->setHeader('header', null);
        $this->assertEmpty($er->getExtraHeaders());

        $r = $er->toResponseInterface($response);
        $this->assertFalse($r->hasHeader('header'));

        $r = $er->toResponseInterface($response, [], 'http://example.com/');
        $this->assertEquals(302, $r->getStatusCode());
        $this->assertTrue($r->hasHeader('Location'));
        $loc = $r->getHeaderLine('Location');
        $exp = 'http://example.com/?error=access_denied';
        $this->assertEquals($exp, $loc);
    }
}
