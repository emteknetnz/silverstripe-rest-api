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
    /**
     * @internal
     */
    private static $autoPublish = false;

    public static function enableAutoPublish(): void
    {
        self::$autoPublish = true;
    }

    public static function disableAutoPublish(): void
    {
        self::$autoPublish = false;
    }

    public function onAfterWrite()
    {
        if (self::$autoPublish) {
            $this->owner->publishRecursive();
        }
    }
}
