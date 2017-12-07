<?php

namespace WildWolf\OAuth2\Response;

use Psr\Http\Message\ResponseInterface;

abstract class BaseResponse
{
    private $status_code;
    private $extra_headers = [];

    abstract function toArray() : array;

    public function setStatusCode(int $code) : self
    {
        $this->status_code = $code;
        return $this;
    }

    public function getStatusCode() : int
    {
        return $this->status_code;
    }

    public function setHeader(string $key, string $value = null) : self
    {
        if (null === $value) {
            unset($this->extra_headers[$key]);
        }
        else {
            $this->extra_headers[$key] = $value;
        }

        return $this;
    }

    public function getExtraHeaders() : array
    {
        return $this->extra_headers;
    }

    public function toResponseInterface(ResponseInterface $response, array $extra = null, string $uri = null, string $sep = null) : ResponseInterface
    {
        $arr = $this->toArray() + (array)$extra;
        $h   = $this->getExtraHeaders();
        foreach ($h as $k => $v) {
            $response = $response->withHeader($k, $v);
        }

        if (!empty($uri)) {
            $sep = $sep ?? ((false === strpos($uri, '?')) ? '?' : '&');
            return $response
                ->withStatus(302)
                ->withHeader('Location', $uri . $sep . http_build_query($arr))
                ->withHeader('Pragma', 'no-cache')
            ;
        }

        $body = $response->getBody();
        $body->write(json_encode($arr));
        return $response
            ->withStatus($this->getStatusCode())
            ->withHeader('Cache-Control', 'no-store')
            ->withHeader('Pragma', 'no-cache')
            ->withHeader('Content-Type', 'application/json; charset=UTF-8')
            ->withBody($body)
        ;
    }
}
