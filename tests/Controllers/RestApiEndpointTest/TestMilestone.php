<?php

namespace emteknetnz\RestApi\Tests\Controllers\RestApiTest;

use SilverStripe\Dev\TestOnly;
use emteknetnz\RestApi\Tests\Controllers\RestApiTest\TestProject;
use emteknetnz\RestApi\Tests\Controllers\RestApiTest\TestCanMethodsTrait;
use SilverStripe\ORM\DataObject;
use SilverStripe\Versioned\Versioned;

class TestMilestone extends DataObject implements TestOnly
{
    use TestCanMethodsTrait;

    private static $db = [
        'Title' => 'Varchar',
    ];

    private static $has_one = [
        'TestProject' => TestProject::class,
    ];

    private static $table_name = 'TestMilestone';

    private static $extensions = [
        Versioned::class,
        TestVersionedExtension::class,
    ];
}
