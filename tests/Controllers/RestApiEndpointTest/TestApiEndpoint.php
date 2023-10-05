<?php

namespace emteknetnz\RestApi\Tests\Controllers\RestApiTest;

use App\Controllers\RestApiEndpoint;
use SilverStripe\Control\HTTPResponse;
use SilverStripe\Dev\TestOnly;
use SilverStripe\ORM\DataObject;
use SilverStripe\ORM\DataList;
use SilverStripe\Security\PermissionProvider;

class TestApiEndpoint extends RestApiEndpoint implements PermissionProvider, TestOnly
{
    public const TEST_API_ACCESS = 'TEST_API_ACCESS';

    // $url_segment is not normally used for classes that extend RestApi because it's normally only used
    // Controller::Link() - however for unit testing Link() is used by `extra_controllers` to wire things up
    private static $url_segment = 'testapiendpoint';

    private static $api_config = [
        RestApiEndpoint::ACCESS => RestApiEndpoint::PUBLIC,
        RestApiEndpoint::DATA_CLASS => TestTask::class,
        RestApiEndpoint::ALLOWED_OPERATIONS => RestApiEndpoint::VIEW_CREATE_EDIT_DELETE_ACTION,
        RestApiEndpoint::CACHE_MAX_AGE_VIEW => 55,
        RestApiEndpoint::FIELDS => [
            // Regular fields
            'title' => 'Title',
            'description' => 'Description',
            'someDateTime' => 'SomeDateTime',
            // DataObject method field
            'dataObjectMethod' => 'DataObjectMethod',
            // Fields with ACCESS
            'accessPrivate' => [
                RestApiEndpoint::ACCESS => RestApiEndpoint::LOGGED_IN,
                RestApiEndpoint::DATA_OBJECT_FIELD => 'AccessPrivate',
            ],
            'accessPermissionCode' => [
                RestApiEndpoint::ACCESS => self::TEST_API_ACCESS,
                RestApiEndpoint::DATA_OBJECT_FIELD => 'AccessPermissionCode',
            ],
            // Field with ALLOWED_OPERATIONS
            'allowedOperationsView' => [
                RestApiEndpoint::ALLOWED_OPERATIONS => self::VIEW,
                RestApiEndpoint::DATA_OBJECT_FIELD => 'AllowedOperationsView',
            ],
            'allowedOperationsCreate' => [
                RestApiEndpoint::ALLOWED_OPERATIONS => self::CREATE,
                RestApiEndpoint::DATA_OBJECT_FIELD => 'AllowedOperationsCreate',
            ],
            'allowedOperationsEdit' => [
                RestApiEndpoint::ALLOWED_OPERATIONS => self::EDIT,
                RestApiEndpoint::DATA_OBJECT_FIELD => 'AllowedOperationsEdit',
            ],
            // Relation with ACCESS_PERM_CODE
            'testReporter' => [
                RestApiEndpoint::RELATION => 'TestReporter',
                RestApiEndpoint::ACCESS => self::TEST_API_ACCESS,
                RestApiEndpoint::FIELDS => [
                    'title' => 'Title',
                ],
            ],
            // Relation with nested relations
            'testProject' => [
                RestApiEndpoint::RELATION => 'TestProject',
                RestApiEndpoint::FIELDS => [
                    'title' => 'Title',
                    // HasOne relation - single nested record
                    'testTeam' => [
                        RestApiEndpoint::RELATION => 'TestTeam',
                        RestApiEndpoint::FIELDS => [
                            // Datatype testing
                            'myBigInt' => 'MyBigInt',
                            'myBoolean' => 'MyBoolean',
                            'myCurrency' => 'MyCurrency',
                            'myDate' => 'MyDate',
                            'myDateTime' => 'MyDateTime',
                            // DBClassName
                            'myDecimal' => 'MyDecimal',
                            'myDouble' => 'MyDouble',
                            'myEnum' => 'MyEnum',
                            'myFloat' => 'MyFloat',
                            // ForeignKey
                            'myHTMLFragment' => 'MyHTMLFragment',
                            'myHTMLVarchar' => 'MyHTMLVarchar',
                            'myInt' => 'MyInt',
                            'myLocale' => 'MyLocale',
                            'myMoney' => 'MyMoney',
                            'myMutliEnum' => 'MyMutliEnum',
                            'myPercentage' => 'MyPercentage',
                            // PolymorphicForeignKey
                            // PrimaryKey
                            'myText' => 'MyText',
                            'myTime' => 'MyTime',
                            'myVarchar' => 'MyVarchar',
                            'myYear' => 'MyYear',
                            // standard title field
                            'title' => 'Title',
                        ],
                    ],
                    // HasMany relation - multiple nested records
                    'testMilestones' => [
                        RestApiEndpoint::RELATION => 'TestMilestones',
                        RestApiEndpoint::FIELDS => [
                            'title' => 'Title',
                        ],
                    ]
                ],
            ],
        ],
    ];

    public static $hooksCalled = [
        'onViewOne' => false,
        'onViewMany' => false,
        'onCreateBeforeWrite' => false,
        'onCreateAfterWrite' => false,
        'onEditBeforeWrite' => false,
        'onEditAfterWrite' => false,
        'onDeleteBeforeDelete' => false,
        'onDeleteAfterDelete' => false,
        'onBeforeSendResponse' => false,
    ];

    public function providePermissions()
    {
        return [
            self::TEST_API_ACCESS => 'Test API access',
        ];
    }

    public static function resetHooksCalled(): void
    {
        foreach (array_keys(self::$hooksCalled) as $key) {
            self::$hooksCalled[$key] = false;
        }
    }

    protected function onViewOne(DataObject $obj): void
    {
        self::$hooksCalled['onViewOne'] = true;
    }

    protected function onViewMany(DataList $objs): void
    {
        self::$hooksCalled['onViewMany'] = true;
    }

    protected function onCreateBeforeWrite(DataObject $obj): void
    {
        self::$hooksCalled['onCreateBeforeWrite'] = true;
    }

    protected function onCreateAfterWrite(DataObject $obj): void
    {
        self::$hooksCalled['onCreateAfterWrite'] = true;
    }

    protected function onEditBeforeWrite(DataObject $obj): void
    {
        self::$hooksCalled['onEditBeforeWrite'] = true;
    }

    protected function onEditAfterWrite(DataObject $obj): void
    {
        self::$hooksCalled['onEditAfterWrite'] = true;
    }

    protected function onDeleteBeforeDelete(DataObject $obj): void
    {
        self::$hooksCalled['onDeleteBeforeDelete'] = true;
    }

    protected function onDeleteAfterDelete(DataObject $obj): void
    {
        self::$hooksCalled['onDeleteAfterDelete'] = true;
    }

    protected function onBeforeSendResponse(HTTPResponse $response): void
    {
        self::$hooksCalled['onBeforeSendResponse'] = true;
    }
}
