<?php

namespace emteknetnz\RestApi\Exceptions;

use Exception;

class RestApiEndpointException extends Exception
{
    public function __construct(string $message, int $httpStatusCode)
    {
        // Clean message of anything potentially malicious before return it in an json response
        $message = preg_replace('/[^a-z0-9\-_ ]/i', '', $message);
        parent::__construct($message, $httpStatusCode);
    }
}
