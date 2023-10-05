<?php

namespace emteknetnz\RestApi\Tests\Controllers\RestApiTest;

use emteknetnz\RestApi\Controllers\RestApiEndpoint;
use emteknetnz\RestApi\Tests\Controllers\RestApiEndpointTest;
use SilverStripe\Dev\TestOnly;

/**
 * This class in only uses as a base class for the test classes in this directory.
 */
class TestCanMethodStatic implements TestOnly
{
    /** @internal */
    private static $canMethodsThatPass = [
        RestApiEndpointTest::VIEW => true,
        RestApiEndpointTest::CREATE => true,
        RestApiEndpointTest::EDIT => true,
        RestApiEndpointTest::DELETE => true,
    ];

    public static function canMethodResult(string $method): bool
    {
        return self::$canMethodsThatPass[$method];
    }

    public static function setCanMethodsThatPass(string $methods): void
    {
        self::$canMethodsThatPass[RestApiEndpointTest::VIEW] = false;
        self::$canMethodsThatPass[RestApiEndpointTest::CREATE] = false;
        self::$canMethodsThatPass[RestApiEndpointTest::EDIT] = false;
        self::$canMethodsThatPass[RestApiEndpointTest::DELETE] = false;
        foreach (explode(RestApiEndpointTest::DELIMITER, $methods) as $method) {
            if ($method === RestApiEndpoint::NONE) {
                continue;
            }
            self::$canMethodsThatPass[$method] = true;
        }
    }
}
