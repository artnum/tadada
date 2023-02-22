<?php
namespace TaDaDa;

use Exception;

class Proxy {
    protected $auth;
    function __construct(Auth $auth) {
        $this->auth = $auth;
    }

    /* 
     * fetch url like https://example.com/proxy/[... urlid ...]/[... token ...]
     * in order to provide public url without much information
     */
    function fetch ($url) {
        try {
            $uparts = parse_url($url);
            $parts = explode('/', $uparts['path']);
            $parts = array_filter($parts, fn ($e) => !empty($e));
            if (count($parts) < 2) { throw new Exception(); }

            $token = str_replace(['_', '-', '.'], ['/', '+', '='], array_pop($parts));
            $id = array_pop($parts);
            
            if (empty($id) || empty($token)) { throw new Exception(); }

            $url = $this->auth->find_url(rawurldecode($token), rawurldecode($id));
            if (!$url) { throw new Exception(); }
            /* database store "hostname/whatever/path/is/url?query=value", we
            * remove the hostname and use the current hostname
            */
            $parts = explode('/', $url, 2); 
            if (count($parts) < 2) { throw new Exception(); }
            $url = 'https://' . $uparts['host'] . '/' . $parts[1];

            $c = curl_init($url);
            if ($c === false) { throw new Exception(); }
            if (!curl_setopt($c, CURLOPT_HEADERFUNCTION, function ($c, $header) {
                if (strlen($header) === 0) { return 0; }
                $h = strtolower($header);
                switch(strtolower($h)) {
                    case 'transfer-encoding':
                    case 'etag':
                    case 'date':
                    case 'te':
                    case 'trailer':
                    case 'vary':
                    case 'location':
                        header($header);
                        break;
                    default: 
                        if (str_starts_with($h, 'http')) {
                            http_response_code(trim(explode(' ', $h)[1]));
                            break;
                        }
                        if (str_starts_with($h, 'content')) {
                            header($header);
                            break;
                        }
                        break;
                }
                return strlen($header);
            })) { throw new Exception(); }
            if (!curl_setopt($c, CURLOPT_HTTPHEADER, [
                'Authorization: Bearer ' . $token,
                'X-Request-Id: ' . hash_hmac('sha1', $token, random_bytes(16))
            ])) {
                throw new Exception();
            }
            if (!curl_exec($c)) { throw new Exception(); }
            curl_close($c);
        } catch (Exception $e) {
            http_response_code(401);
            echo '<html><head><title>Unauthorized</title></head><body><h1>Unauthorized</h1></body></html>';
        }
    }
}