<?php

namespace emteknetnz\RestApi\PermissionProviders;

use SilverStripe\Security\PermissionProvider;

class ApiTokenPermissionProvider implements PermissionProvider
{
    public const API_TOKEN_AUTHENTICATION = 'API_TOKEN_AUTHENTICATION';

    public function providePermissions()
    {
        return [
            self::API_TOKEN_AUTHENTICATION => 'Use an API token',
        ];
    }
}
