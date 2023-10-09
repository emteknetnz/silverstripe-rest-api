<?php

namespace emteknetnz\RestApi\Tests\Controllers\RestApiTest;

use SilverStripe\Dev\TestOnly;
use emteknetnz\RestApi\Tests\Controllers\RestApiTest\TestProject;
use emteknetnz\RestApi\Tests\Controllers\RestApiTest\TestReporter;
use emteknetnz\RestApi\Tests\Controllers\RestApiTest\TestCanMethodsTrait;
use SilverStripe\ORM\DataObject;
use SilverStripe\ORM\ValidationResult;
use emteknetnz\RestApi\Tests\Controllers\RestApiTest\TestVersionedExtension;
use SilverStripe\Versioned\Versioned;

class TestTask extends DataObject implements TestOnly
{
    use TestCanMethodsTrait;

    private static $db = [
        'Title' => 'Varchar',
        // Description and SomeDateTime are used in sort and filter tests
        'Description' => 'Varchar',
        'SomeDateTime' => 'Datetime',
        'NotInApi' => 'Varchar',
        // ACCESS
        'AccessPrivate' => 'Varchar',
        'AccessPermissionCode' => 'Varchar',
        // ALLOWED_OPERATIONS
        'AllowedOperationsView' => 'Varchar',
        'AllowedOperationsCreate' => 'Varchar',
        'AllowedOperationsEdit' => 'Varchar',
    ];

    private static $has_one = [
        'TestProject' => TestProject::class,
        'TestReporter' => TestReporter::class,
    ];

    private static $extensions = [
        Versioned::class,
        TestVersionedExtension::class,
    ];

    private static $table_name = 'TestTask';

    public function validate()
    {
        if ($this->Title !== '__INVALID__') {
            return parent::validate();
        }
        $result = new ValidationResult();
        $result->addError('This is a test error');
        return $result;
    }

    public function DataObjectMethod()
    {
        $taskIden = '0';
        if ($this->NotInApi) {
            preg_match('#([0-9]+)#', $this->NotInApi, $matches);
            $taskIden = $matches[1];
            return "TestTask $taskIden DataObjectMethod";
        }
        return "TestTask 00 DataObjectMethod";
    }
}
