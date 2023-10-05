<?php

use SilverStripe\Dev\SapphireTest;
use App\Extensions\DirectorExtension;
use App\Controllers\RestApiEndpoint;
use emteknetnz\RestApi\Tests\Controllers\RestApiTest\TestApiEndpoint;
use SilverStripe\Core\Config\Config;

class DirectorExtensionTest extends SapphireTest
{
    public function testUpdateRules()
    {
        $path = 'api/v1/whatever';
        $extension = new DirectorExtension();
        $rules = [];
        $extension->updateRules($rules);
        $this->assertFalse(array_key_exists($path, $rules));
        $apiConfig = Config::inst()->get(TestApiEndpoint::class, 'api_config');
        $apiConfig[RestApiEndpoint::PATH] = $path;
        Config::modify()->set(TestApiEndpoint::class, 'api_config', $apiConfig);
        $extension->updateRules($rules);
        $this->assertTrue(array_key_exists($path, $rules));
    }
}
