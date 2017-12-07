<?php

namespace Test;

use PHPUnit\Framework\TestCase;
use WildWolf\OAuth2\Response\AccessTokenResponse;

class AccessTokenResponseTest extends TestCase
{
    /**
     * @dataProvider creationDataProvider
     * @param string $token
     * @param string $type
     * @param int $expires
     * @param string $refresh
     * @param string $scope
     * @param array $expected
     */
    public function testCreation(string $token, string $type, int $expires, string $refresh, string $scope, array $expected)
    {
        $atr = new AccessTokenResponse($token, $type, $expires, $refresh, $scope);

        $actual = $atr->toArray();
        $this->assertEquals($expected, $actual);

        $atr->nullifyRefreshToken();
        $actual = $atr->toArray();
        unset($expected['refresh_token']);
        $this->assertEquals($expected, $actual);
    }

    public function creationDataProvider()
    {
        return [
            [
                'abcdef', 'token', 86400, 'fedcba', 'scope',
                [
                    'access_token'  => 'abcdef',
                    'token_type'    => 'token',
                    'expires_in'    => 86400,
                    'refresh_token' => 'fedcba',
                    'scope'         => 'scope'
                ]
            ],
            [
                'abcdef', 'token', 86400, '', '',
                [
                    'access_token'  => 'abcdef',
                    'token_type'    => 'token',
                    'expires_in'    => 86400,
                ]
            ]
        ];
    }
}
