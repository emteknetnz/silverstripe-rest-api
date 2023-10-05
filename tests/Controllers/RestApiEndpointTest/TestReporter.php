<?php

namespace emteknetnz\RestApi\Tests\Controllers\RestApiTest;

use SilverStripe\Dev\TestOnly;
use emteknetnz\RestApi\Tests\Controllers\RestApiTest\TestCanMethodsTrait;
use SilverStripe\ORM\DataObject;

class TestReporter extends DataObject implements TestOnly
{
    use TestCanMethodsTrait;

    private static $db = [
        'Title' => 'Varchar',
    ];

    private static $table_name = 'TestReporter';
}
