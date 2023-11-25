<?php

namespace emteknetnz\RestApi\PermissionProviders;

use SilverStripe\Security\PermissionProvider;
use emteknetnz\RestApi\Controllers\RestApiEndpoint;

// This exists as a standalone class rather than simply putting it on RestApiEndpoint because that is an abstract
// class which cannot be instantiated and therefore cannot be used as a permission provider.
class ApiTokenPermissionProvider implements PermissionProvider
{
    public function providePermissions()
    {
        return [
            RestApiEndpoint::API_TOKEN_AUTHENTICATION => 'Use an API token',
        ];
    }
}
