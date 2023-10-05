<?php

namespace emteknetnz\RestApi\Tests\Controllers\RestApiTest;

use SilverStripe\Dev\TestOnly;
use emteknetnz\RestApi\Tests\Controllers\RestApiTest\TestTask;
use emteknetnz\RestApi\Tests\Controllers\RestApiTest\TestTeam;
use emteknetnz\RestApi\Tests\Controllers\RestApiTest\TestMilestone;
use emteknetnz\RestApi\Tests\Controllers\RestApiTest\TestCanMethodsTrait;
use SilverStripe\ORM\DataObject;

class TestProject extends DataObject implements TestOnly
{
    use TestCanMethodsTrait;

    private static $db = [
        'Title' => 'Varchar',
    ];

    private static $has_one = [
        'TestTeam' => TestTeam::class,
    ];

    private static $has_many = [
        'TestTasks' => TestTask::class,
        'TestMilestones' => TestMilestone::class,
    ];

    private static $table_name = 'TestProject';
}
