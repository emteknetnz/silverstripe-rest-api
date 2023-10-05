<?php

namespace emteknetnz\RestApi\Tests\Controllers\RestApiTest;

use emteknetnz\RestApi\Tests\Controllers\RestApiEndpointTest;

trait TestCanMethodsTrait
{
    public function canView($member = null)
    {
        return TestCanMethodStatic::canMethodResult(RestApiEndpointTest::VIEW);
    }

    public function canCreate($member = null, $context = [])
    {
        return TestCanMethodStatic::canMethodResult(RestApiEndpointTest::CREATE);
    }

    public function canEdit($member = null)
    {
        return TestCanMethodStatic::canMethodResult(RestApiEndpointTest::EDIT);
    }

    public function canDelete($member = null)
    {
        return TestCanMethodStatic::canMethodResult(RestApiEndpointTest::DELETE);
    }
}
