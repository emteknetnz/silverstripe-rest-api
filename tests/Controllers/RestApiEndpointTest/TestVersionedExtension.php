<?php

namespace emteknetnz\RestApi\Tests\Controllers\RestApiTest;

use SilverStripe\Dev\TestOnly;
use SilverStripe\ORM\DataExtension;
use SilverStripe\Versioned\Versioned;

/**
 * Automatically publish a DataObject when it is written - this is to make asserting things easier
 */
class TestVersionedExtension extends DataExtension implements TestOnly
{
    public function onAfterWrite()
    {
        $this->owner->publishRecursive();
    }
}
