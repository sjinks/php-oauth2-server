<?php

namespace WildWolf\OAuth2\Request {

    function apache_request_headers(array $headers = null) : array
    {
        static $h = [];

        if ($headers !== null) {
            $h = $headers;
        }

        return $h;
    }

    function function_exists($function)
    {
        if ($function === 'apache_request_headers') {
            return true;
        }

        return \function_exists($function);
    }

}

namespace Test\Helpers {

class MockFunctions
{
    public static function instance()
    {
    }
}

}
