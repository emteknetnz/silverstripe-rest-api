<?php

namespace emteknetnz\RestApi\Exceptions;

use Exception;

class RestApiEndpointConfigException extends Exception
{
    public function __construct(string $message)
    {
        parent::__construct($message, 500);
    }
}
