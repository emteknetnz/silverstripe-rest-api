<?php

namespace emteknetnz\RestApi\Extensions;

use emteknetnz\RestApi\Controllers\RestApiEndpoint;
use SilverStripe\Core\ClassInfo;
use SilverStripe\Core\Config\Config;
use SilverStripe\Core\Extension;

/**
 * This extension allows RestApiEndpoint classes to register their routes using
 * `private static $url_segment = 'api/whatever';` rather than having to use a separate yml file
 * This is similar to what `$url_segment` in LeftAndMain does for admin controllers
 */
class DirectorExtension extends Extension
{
    public function updateRules(array &$rules)
    {
        $addedRules = [];
        $config = Config::inst();
        foreach (ClassInfo::allClasses() as $class) {
            if (!is_a($class, RestApiEndpoint::class, true)) {
                continue;
            }
            $path = $config->get($class, 'api_config')[RestApiEndpoint::PATH] ?? null;
            if (is_null($path)) {
                continue;
            }
            $path = ltrim($path, '/');
            $rules[$path] = $class;
            $addedRules[] = $path;
        }
        // sort rules so that the ones added by this extension are at the top
        uksort($rules, function($a, $b) use ($addedRules) {
            $aWasAdded = in_array($a, $addedRules);
            $bWasAdded = in_array($b, $addedRules);
            if ($aWasAdded && !$bWasAdded) {
                return -1;
            }
            if (!$aWasAdded && $bWasAdded) {
                return 1;
            }
            return 0;
        });
    }
}
