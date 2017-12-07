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
        $response = $this->withExtraHeaders($response);
        $params   = $this->toArray() + (array)$extra;

        return empty($uri)
            ? $this->createJson($response, $params)
            : $this->createRedirect($response, $uri, $sep, $params)
        ;
    }

    private function withExtraHeaders(ResponseInterface $response) : ResponseInterface
    {
        $h = $this->getExtraHeaders();
        foreach ($h as $k => $v) {
            $response = $response->withHeader($k, $v);
        }

        return $response;
    }

    private function createRedirect(ResponseInterface $response, string $uri, $sep, array $params) : ResponseInterface
    {
        $sep = $sep ?? (((string)parse_url($uri, PHP_URL_QUERY)) ? '&' : '?');
        return $response
            ->withStatus(302)
            ->withHeader('Location', $uri . $sep . http_build_query($params))
            ->withHeader('Pragma', 'no-cache')
        ;
    }

    private function createJson(ResponseInterface $response, array $params) : ResponseInterface
    {
        $response->getBody()->write(json_encode($params));
        return $response
            ->withStatus($this->getStatusCode())
            ->withHeader('Cache-Control', 'no-store')
            ->withHeader('Pragma', 'no-cache')
            ->withHeader('Content-Type', 'application/json; charset=UTF-8')
        ;
    }
}
