<?php

namespace emteknetnz\RestApi\Tests\Controllers;

use emteknetnz\RestApi\Controllers\RestApiEndpoint;
use SilverStripe\Core\Config\Config;
use SilverStripe\Dev\FunctionalTest;
use SilverStripe\Control\Director;
use emteknetnz\RestApi\Tests\Controllers\RestApiTest\TestApiEndpoint;
use emteknetnz\RestApi\Tests\Controllers\RestApiTest\TestMilestone;
use emteknetnz\RestApi\Tests\Controllers\RestApiTest\TestTask;
use SilverStripe\Control\HTTPResponse;
use SilverStripe\Control\Controller;
use emteknetnz\RestApi\Tests\Controllers\RestApiTest\TestProject;
use emteknetnz\RestApi\Tests\Controllers\RestApiTest\TestReporter;
use emteknetnz\RestApi\Tests\Controllers\RestApiTest\TestTeam;
use emteknetnz\RestApi\Tests\Controllers\RestApiTest\TestCanMethodStatic;
use emteknetnz\RestApi\Exceptions\RestApiEndpointConfigException;
use SilverStripe\Security\SecurityToken;
use emteknetnz\RestApi\Tests\Controllers\RestApiTest\TestVersionedExtension;


# vendor/bin/phpunit app/tests/Controllers/RestApiTest.php flush=1

class RestApiEndpointTest extends FunctionalTest
{
    // Duplicating RestApi constants because they're not available within dataProviders only because for whatever
    // reason we get this error `Error: Class 'emteknetnz\RestApi\Controllers\RestApi' not found`
    // there is a unit test to valiate that these consts match those on RestApi
    // NOTE: these should also never change since this would be an API breaking change for downstream projects
    // keys
    public const PATH = 'PATH';
    public const DATA_CLASS = 'DATA_CLASS';
    public const FIELDS = 'FIELDS';
    public const DATA_OBJECT_FIELD = 'DATA_OBJECT_FIELD';
    public const RELATION = 'RELATION';
    public const ACCESS = 'ACCESS';
    public const ALLOWED_OPERATIONS = 'ALLOWED_OPERATIONS';
    public const CALL_CAN_METHODS = 'CALL_CAN_METHODS';
    public const CACHE_MAX_AGE_VIEW = 'CACHE_MAX_AGE_VIEW';
    public const CACHE_MAX_AGE_OPTIONS = 'CACHE_MAX_AGE_OPTIONS';
    public const LIMIT_DEFAULT = 'LIMIT_DEFAULT';
    public const LIMIT_MAX = 'LIMIT_MAX';
    // values
    public const PUBLIC = 'PUBLIC';
    public const LOGGED_IN = 'LOGGED_IN';
    public const NONE = 'NONE';
    public const CREATE = 'CREATE';
    public const VIEW = 'VIEW';
    public const EDIT = 'EDIT';
    public const DELETE = 'DELETE';
    public const ACTION = 'ACTION';
    public const DELIMITER = '_';
    public const CREATE_EDIT_DELETE_ACTION = 'CREATE_EDIT_DELETE_ACTION';
    public const VIEW_CREATE_EDIT_DELETE_ACTION = 'VIEW_CREATE_EDIT_DELETE_ACTION';
    // other consts
    public const CSRF_TOKEN_HEADER = 'x-csrf-token';

    // This is from TestApiEndpoint
    private const TEST_API_ACCESS = 'TEST_API_ACCESS';

    // These are used only on this test class
    private const AUTH_LEVEL_NONE = 0;
    private const AUTH_LEVEL_LOGGED_IN = 1;
    private const AUTH_LEVEL_PERM_CODE = 2;

    protected $usesDatabase = true;

    protected static $extra_dataobjects = [
        TestTask::class,
        TestProject::class,
        TestTeam::class,
        TestMilestone::class,
        TestReporter::class,
    ];

    protected static $extra_controllers = [
        TestApiEndpoint::class,
    ];

    private $endpointPath = 'testapiendpoint';

    protected function setUp(): void
    {
        parent::setUp();
        SecurityToken::enable();
        TestCanMethodStatic::setCanMethodsThatPass(self::VIEW_CREATE_EDIT_DELETE_ACTION);
        TestApiEndpoint::resetHooksCalled();
        TestVersionedExtension::enableAutoPublish();
        $this->setConfig(self::PATH, $this->endpointPath);
        // Create fixtures
        $testTeam = TestTeam::create([
            'Title' => 'TestTeam 01 Title',
             // TestTeam is a bit different from the others fixtures because it contains data for the
             // testing different field types
            'MyBigInt' => 1234567890,
            'MyBoolean' => true,
            'MyCurrency' => 999.1234567890,
            'MyDate' => '2020-11-22',
            'MyDateTime' => '2020-11-22 12:34:56',
            'MyDecimal' => 999.1234567890,
            'MyDouble' => 999.1234567890,
            'MyEnum' => 'Option2',
            'MyFloat' => 999.1234567890,
            'MyHTMLFragment' => '<strong>The quick brown fox</strong>',
            'MyHTMLVarchar' => '<strong>The quick brown fox</strong>',
            'MyInt' => 1234567890,
            'MyLocale' => 'en_NZ',
            'MyMutliEnum' => 'Option2,Option3',
            'MyPercentage' => 0.1234567890,
            'MyText' => 'Lorem ipsum',
            'MyTime' => '12:34:56',
            'MyVarchar' => 'Lorem ipsum',
            'MyYear' => 1989, // by default DBYear will output as an int rather than a string
        ]);
        $testTeam->MyMoney->setCurrency('NZD');
        $testTeam->MyMoney->setAmount(999.1234567890);
        $testTeamID = $testTeam->write();
        $testProjectID = TestProject::create([
            'Title' => 'TestProject 01 Title',
            'Private' => 'TestProject 01 Private',
            'TestTeamID' => $testTeamID,
        ])->write();
        TestProject::create([
            'Title' => 'TestProject 02 Title',
            'Private' => 'TestProject 02 Private',
        ])->write();
        TestMilestone::create([
            'Title' => 'TestMilestone 01 Title',
            'TestProjectID' => $testProjectID,
        ])->write();
        TestMilestone::create([
            'Title' => 'TestMilestone 02 Title',
            'TestProjectID' => $testProjectID,
        ])->write();
        $testReporterID = TestReporter::create([
            'Title' => 'TestReporter 01 Title',
        ])->write();
        TestReporter::create([
            'Title' => 'TestReporter 02 Title',
        ])->write();
        TestTask::create([
            'Title' => 'TestTask 01 Title',
            'Description' => 'Zoo',
            'SomeDateTime' => '1990-10-20 12:34:56',
            'NotInApi' => 'TestTask 01 NotInApi',
            'TestProjectID' => $testProjectID,
            'TestReporterID' => $testReporterID,
            'AccessPrivate' => 'TestTask 01 AccessPrivate',
            'AccessPermissionCode' => 'TestTask 01 AccessPermissionCode',
            'AllowedOperationsView' => 'TestTask 01 AllowedOperationsView',
            'AllowedOperationsCreate' => 'TestTask 01 AllowedOperationsCreate',
            'AllowedOperationsEdit' => 'TestTask 01 AllowedOperationsEdit',
        ])->write();
        TestTask::create([
            'Title' => 'TestTask 02 Title',
            'Description' => 'Yak',
            'SomeDateTime' => '1991-10-20 12:34:56',
            'NotInApi' => 'TestTask 02 NotInApi',
            'TestProjectID' => $testProjectID,
            'TestReporterID' => $testReporterID,
            'AccessPrivate' => 'TestTask 02 AccessPrivate',
            'AccessPermissionCode' => 'TestTask 02 AccessPermissionCode',
            'AllowedOperationsView' => 'TestTask 02 AllowedOperationsView',
            'AllowedOperationsCreate' => 'TestTask 02 AllowedOperationsCreate',
            'AllowedOperationsEdit' => 'TestTask 02 AllowedOperationsEdit',
        ])->write();
        TestTask::create([
            'Title' => 'TestTask 03 Title',
            'Description' => 'Yak',
            'SomeDateTime' => '1992-10-20 12:34:56',
            'NotInApi' => 'TestTask 03 NotInApi',
            'TestProjectID' => $testProjectID,
            'TestReporterID' => $testReporterID,
            'AccessPrivate' => 'TestTask 03 AccessPrivate',
            'AccessPermissionCode' => 'TestTask 03 AccessPermissionCode',
            'AllowedOperationsView' => 'TestTask 03 AllowedOperationsView',
            'AllowedOperationsCreate' => 'TestTask 03 AllowedOperationsCreate',
            'AllowedOperationsEdit' => 'TestTask 03 AllowedOperationsEdit',
        ])->write();
        TestTask::create([
            'Title' => 'TestTask 04 Title',
            'Description' => 'Xylophone',
            'SomeDateTime' => '1993-10-20 12:34:56',
            'NotInApi' => 'TestTask 04 NotInApi',
            'TestProjectID' => $testProjectID,
            'TestReporterID' => $testReporterID,
            'AccessPrivate' => 'TestTask 04 AccessPrivate',
            'AccessPermissionCode' => 'TestTask 04 AccessPermissionCode',
            'AllowedOperationsView' => 'TestTask 04 AllowedOperationsView',
            'AllowedOperationsCreate' => 'TestTask 04 AllowedOperationsCreate',
            'AllowedOperationsEdit' => 'TestTask 04 AllowedOperationsEdit',
        ])->write();
        // TestTask has the Versioned extension on it to support versioning tests
        foreach (TestTask::get() as $testTask) {
            $testTask->publishRecursive();
        }
    }

    /**
     * If this has failed it means someone has change the consts in RestApi which should never happen
     * because consts changing would be an API breaking change for downstream projects
     * as projects can also define endpoints config as strings in yml files
     */
    public function testConsts(): void
    {
        $testConsts = (new \ReflectionClass(__CLASS__))->getConstants();
        $restApiConsts = (new \ReflectionClass(RestApiEndpoint::class))->getConstants();
        foreach ($testConsts as $k => $v) {
            if (strpos($k, 'AUTH_LEVEL_') === 0 || $k === 'TEST_API_ACCESS') {
                continue;
            }
            $this->assertSame($v, $restApiConsts[$k]);
        }
        $testApiConsts = (new \ReflectionClass(RestApiEndpoint::class))->getConstants();
        foreach ($testApiConsts as $k => $v) {
            $this->assertSame($v, $testConsts[$k]);
        }
    }

    /**
     * @dataProvider provideAccess
     */
    public function testAccess(string $access, int $authLevel, int $expected): void
    {
        $this->setConfig(self::ACCESS, $access);
        $this->login($authLevel);
        $this->assertSame($expected, $this->req('GET')->getStatusCode());
    }

    public function provideAccess(): array
    {
        return [
            // Matrix - access [PUBLIC,LOGGED_IN,TEST_API_ACCESS] / authLevel [NONE,LOGGED_IN,PERM_CODE]
            'Matrix - access PUBLIC / authLevel NONE' => [
                'access' => self::PUBLIC,
                'authLevel' => self::AUTH_LEVEL_NONE,
                'expected' => 200,
            ],
            'Matrix - access PUBLIC / authLevel LOGGED_IN' => [
                'access' => self::PUBLIC,
                'authLevel' => self::AUTH_LEVEL_LOGGED_IN,
                'expected' => 200,
            ],
            'Matrix - access PUBLIC / authLevel PERM_CODE' => [
                'access' => self::PUBLIC,
                'authLevel' => self::AUTH_LEVEL_PERM_CODE,
                'expected' => 200,
            ],
            'Matrix - access LOGGED_IN / authLevel NONE' => [
                'access' => self::LOGGED_IN,
                'authLevel' => self::AUTH_LEVEL_NONE,
                'expected' => 401,
            ],
            'Matrix - access LOGGED_IN / authLevel LOGGED_IN' => [
                'access' => self::LOGGED_IN,
                'authLevel' => self::AUTH_LEVEL_LOGGED_IN,
                'expected' => 200,
            ],
            'Matrix - access LOGGED_IN / authLevel PERM_CODE' => [
                'access' => self::LOGGED_IN,
                'authLevel' => self::AUTH_LEVEL_PERM_CODE,
                'expected' => 200,
            ],
            'Matrix - access TEST_API_ACCESS / authLevel NONE' => [
                'access' => self::TEST_API_ACCESS,
                'authLevel' => self::AUTH_LEVEL_NONE,
                'expected' => 401,
            ],
            'Matrix - access TEST_API_ACCESS / authLevel LOGGED_IN' => [
                'access' => self::TEST_API_ACCESS,
                'authLevel' => self::AUTH_LEVEL_LOGGED_IN,
                'expected' => 403,
            ],
            'Matrix - access TEST_API_ACCESS / authLevel PERM_CODE' => [
                'access' => self::TEST_API_ACCESS,
                'authLevel' => self::AUTH_LEVEL_PERM_CODE,
                'expected' => 200,
            ],
        ];
    }

    public function testDisableCsrfToken(): void
    {
        // Disabling the security token in this test won't causes issues in other tests
        SecurityToken::disable();
        $this->setConfig(self::ACCESS, self::TEST_API_ACCESS);
        $this->login(self::AUTH_LEVEL_PERM_CODE);
        $id = TestTask::get()->first()->ID;
        $response = $this->req('GET', $id, null, null, null, null, 'missing');
        $this->assertFalse(SecurityToken::is_enabled());
        $this->assertSame(200, $response->getStatusCode());
    }

    /**
     * @dataProvider provideCsrfToken
     */
    public function testCsrfToken(
        string $access,
        string $csrfTokenType,
        int $expectedStatusCode
    ): void {
        $this->setConfig(self::ACCESS, $access);
        $this->login(self::AUTH_LEVEL_PERM_CODE);
        $id = TestTask::get()->first()->ID;
        $response = $this->req('GET', $id, null, null, null, null, $csrfTokenType);
        $this->assertTrue(SecurityToken::is_enabled());
        $this->assertSame($expectedStatusCode, $response->getStatusCode());
    }

    public function provideCsrfToken(): array
    {
        return [
            // Matrix - access [PUBLIC,LOGGED_IN,TEST_API_ACCESS] / $csrfTokenType [valid,invalid,missing]
            'Matrix - access PUBLIC / csrfTokenType valid' => [
                'access' => self::PUBLIC,
                'csrfTokenType' => 'valid',
                'expectedStatusCode' => 200,
            ],
            'Matrix - access PUBLIC / csrfTokenType invalid' => [
                'access' => self::PUBLIC,
                'csrfTokenType' => 'invalid',
                'expectedStatusCode' => 200,
            ],
            'Matrix - access PUBLIC / csrfTokenType missing' => [
                'access' => self::PUBLIC,
                'csrfTokenType' => 'missing',
                'expectedStatusCode' => 200,
            ],
            'Matrix - access LOGGED_IN / csrfTokenType valid' => [
                'access' => self::LOGGED_IN,
                'csrfTokenType' => 'valid',
                'expectedStatusCode' => 200,
            ],
            'Matrix - access LOGGED_IN / csrfTokenType invalid' => [
                'access' => self::LOGGED_IN,
                'csrfTokenType' => 'invalid',
                'expectedStatusCode' => 400,
            ],
            'Matrix - access LOGGED_IN / csrfTokenType missing' => [
                'access' => self::LOGGED_IN,
                'csrfTokenType' => 'missing',
                'expectedStatusCode' => 400,
            ],
            'Matrix - access TEST_API_ACCESS / csrfTokenType valid' => [
                'access' => self::TEST_API_ACCESS,
                'csrfTokenType' => 'valid',
                'expectedStatusCode' => 200,
            ],
            'Matrix - access TEST_API_ACCESS / csrfTokenType invalid' => [
                'access' => self::TEST_API_ACCESS,
                'csrfTokenType' => 'invalid',
                'expectedStatusCode' => 400,
            ],
            'Matrix - access TEST_API_ACCESS / csrfTokenType missing' => [
                'access' => self::TEST_API_ACCESS,
                'csrfTokenType' => 'missing',
                'expectedStatusCode' => 400,
            ],
        ];
    }

    /**
     * @dataProvider provideAllowedOperations
     */
    public function testAllowedOperations(string $method, array $operationTypesThatAllow): void
    {
        $this->setConfig(self::ACCESS, self::PUBLIC);
        $operationTypes = [
            self::VIEW,
            self::CREATE,
            self::EDIT,
            self::DELETE,
            self::ACTION,
            self::CREATE_EDIT_DELETE_ACTION,
            self::VIEW_CREATE_EDIT_DELETE_ACTION,
        ];
        foreach ($operationTypes as $operationType) {
            $this->setConfig(self::ALLOWED_OPERATIONS, $operationType);
            $expectStatusCode405 = !in_array($operationType, $operationTypesThatAllow);
            $id = in_array($method, ['GET', 'PATCH', 'DELETE', 'PUT']) ? TestTask::get()->first()->ID : null;
            $action = $method === 'PUT' ? '/publish' : null;
            $statusCode = $this->req($method, $id, $action)->getStatusCode();
            if ($expectStatusCode405) {
                $this->assertSame(405, $statusCode);
            } else {
                if (405 === $statusCode) {
                    $a=1;
                }
                $this->assertNotSame(405, $statusCode);
            }
        }
    }

    public function provideAllowedOperations(): array
    {
        return [
            // Matrix - method [GET,POST,PATCH,DELETE,ACTION]
            'Matrix - method GET' => [
                'method' => 'GET',
                'accessTypesThatAllow' => [
                    self::VIEW,
                    self::VIEW_CREATE_EDIT_DELETE_ACTION
                    ]
            ],
            'Matrix - method POST' => [
                'method' => 'POST',
                'accessTypesThatAllow' => [
                    self::CREATE,
                    self::CREATE_EDIT_DELETE_ACTION,
                    self::VIEW_CREATE_EDIT_DELETE_ACTION
                ]
            ],
            'Matrix - method PATCH' => [
                'method' => 'PATCH',
                'accessTypesThatAllow' => [
                    self::EDIT,
                    self::CREATE_EDIT_DELETE_ACTION,
                    self::VIEW_CREATE_EDIT_DELETE_ACTION
                ]
            ],
            'Matrix - method DELETE' => [
                'method' => 'DELETE',
                'accessTypesThatAllow' => [
                    self::DELETE,
                    self::CREATE_EDIT_DELETE_ACTION,
                    self::VIEW_CREATE_EDIT_DELETE_ACTION
                ]
            ],
            'Matrix - method PUT' => [
                'method' => 'PUT',
                'accessTypesThatAllow' => [
                    self::ACTION,
                    self::CREATE_EDIT_DELETE_ACTION,
                    self::VIEW_CREATE_EDIT_DELETE_ACTION,
                ]
            ],
        ];
    }

    /**
     * @dataProvider provideMethodAllowsId
     */
    public function testMethodAllowsId(string $method, bool $reqId, bool $expectStatusCode405)
    {
        $id = $reqId ? TestTask::get()->first()->ID : null;
        $response = $this->req($method, $id);
        $statusCode = $response->getStatusCode();
        if ($expectStatusCode405) {
            $this->assertSame(405, $statusCode);
        } else {
            $this->assertNotSame(405, $statusCode);
        }
    }

    public function provideMethodAllowsId(): array
    {
        return [
            // Matrix - method [GET,POST,PATCH,DELETE] / reqId [false,true]
            'Matrix - method GET / reqId false' => [
                'method' => 'GET',
                'reqId' => false,
                'expectStatusCode405' => false,
            ],
            'Matrix - method GET / reqId true' => [
                'method' => 'GET',
                'reqId' => true,
                'expectStatusCode405' => false,
            ],
            'Matrix - method POST / reqId false' => [
                'method' => 'POST',
                'reqId' => false,
                'expectStatusCode405' => false,
            ],
            'Matrix - method POST / reqId true' => [
                'method' => 'POST',
                'reqId' => true,
                'expectStatusCode405' => true,
            ],
            'Matrix - method PATCH / reqId false' => [
                'method' => 'PATCH',
                'reqId' => false,
                'expectStatusCode405' => true,
            ],
            'Matrix - method PATCH / reqId true' => [
                'method' => 'PATCH',
                'reqId' => true,
                'expectStatusCode405' => false,
            ],
            'Matrix - method DELETE / reqId false' => [
                'method' => 'DELETE',
                'reqId' => false,
                'expectStatusCode405' => true,
            ],
            'Matrix - method DELETE / reqId true' => [
                'method' => 'DELETE',
                'reqId' => true,
                'expectStatusCode405' => false,
            ],
        ];
    }

    /**
     * @dataProvider provideOptions
     */
    public function testOptions(string $allowedOperations, string $expected): void
    {
        $this->setConfig(self::ALLOWED_OPERATIONS, $allowedOperations);
        $response = $this->req('OPTIONS');
        $this->assertEquals(204, $response->getStatusCode());
        $this->assertSame($expected, $response->getHeader('Allow'));
        if (!$this->isFlushing()) {
            $this->assertSame(
                $this->cacheControl(true, 604800),
                $response->getHeader('Cache-Control')
            );
        }
    }

    public function provideOptions(): array
    {
        return [
            // Matrix - allowedOperations [NONE,CREATE_EDIT_DELETE_ACTION,VIEW_CREATE_EDIT_DELETE_ACTION,VIEW_EDIT]
            'allowedOperations NONE' => [
                'allowedOperations' => self::NONE,
                'expected' => 'OPTIONS'
            ],
            'allowedOperations CREATE_EDIT_DELETE' => [
                'allowedOperations' => self::CREATE_EDIT_DELETE_ACTION,
                'expected' => 'OPTIONS, POST, PATCH, DELETE, PUT',
            ],
            'allowedOperations VIEW_CREATE_EDIT_DELETE' => [
                'allowedOperations' => self::VIEW_CREATE_EDIT_DELETE_ACTION,
                'expected' => 'OPTIONS, GET, HEAD, POST, PATCH, DELETE, PUT',
            ],
            'allowedOperations VIEW_EDIT' => [
                'allowedOperations' => implode(self::DELIMITER, [self::VIEW, self::EDIT]),
                'expected' => 'OPTIONS, GET, HEAD, PATCH'
            ],
        ];
    }

    /**
     * @dataProvider provideApiViewOne
     */
    public function testApiViewOne(
        string $callCanMethods,
        string $canMethodsThatPass,
        int $authLevel,
        bool $recordExists,
        int $expectedStatusCode,
        ?array $expectedJson
    ): void {
        $this->setConfig(self::CALL_CAN_METHODS, $callCanMethods);
        TestCanMethodStatic::setCanMethodsThatPass($canMethodsThatPass);
        $this->login($authLevel);
        if ($recordExists) {
            $task = TestTask::get()->first();
            $id = $task->ID;
        } else {
            $task = null;
            $id = TestTask::get()->max('ID') + 1;
        }
        $response = $this->req('GET', $id);
        $this->assertSame($expectedStatusCode, $response->getStatusCode());
        if (!$this->isFlushing()) {
            $enabled = $expectedStatusCode === 200;
            $this->assertSame($this->cacheControl($enabled), $response->getHeader('Cache-Control'));
        }
        if ($expectedJson) {
            $json = json_decode($response->getBody(), true);
            $json = $this->jsonBody($response);
            $this->assertSame($expectedJson, $json);
        }
    }

    public function provideApiViewOne(): array
    {
        return [
            // Matrix - callCanMethods [NONE,VIEW] / pass [NONE,VIEW]
            'Matrix - callCanMethods NONE / canMethodsThatPass NONE' => [
                'callCanMethods' => self::NONE,
                'canMethodsThatPass' => self::NONE,
                'authLevel' => self::AUTH_LEVEL_NONE,
                'recordExists' => true,
                'expectedStatusCode' => 200,
                'expectedJson' => $this->expectedTaskJson(null, self::AUTH_LEVEL_NONE),
            ],
            'Matrix - callCanMethods NONE / canMethodsThatPass VIEW' => [
                'callCanMethods' => self::NONE,
                'canMethodsThatPass' => self::VIEW,
                'authLevel' => self::AUTH_LEVEL_NONE,
                'recordExists' => true,
                'expectedStatusCode' => 200,
                'expectedJson' => $this->expectedTaskJson(null, self::AUTH_LEVEL_NONE),
            ],
            'Matrix - callCanMethods VIEW / canMethodsThatPass NONE' => [
                'callCanMethods' => self::VIEW,
                'canMethodsThatPass' => self::NONE,
                'authLevel' => self::AUTH_LEVEL_NONE,
                'recordExists' => true,
                'expectedStatusCode' => 403,
                'expectedJson' => null,
            ],
            'Matrix - callCanMethods VIEW / canMethodsThatPass VIEW' => [
                'callCanMethods' => self::VIEW,
                'canMethodsThatPass' => self::VIEW,
                'authLevel' => self::AUTH_LEVEL_NONE,
                'recordExists' => true,
                'expectedStatusCode' => 200,
                'expectedJson' => $this->expectedTaskJson(null, self::AUTH_LEVEL_NONE),
            ],
            // Matrix - authLevel [NONE,LOGGED_IN,PERM_CODE]
            'Matrix - authLevel NONE' => [
                'callCanMethods' => self::NONE,
                'canMethodsThatPass' => self::NONE,
                'authLevel' => self::AUTH_LEVEL_NONE,
                'recordExists' => true,
                'expectedStatusCode' => 200,
                'expectedJson' => $this->expectedTaskJson(null, self::AUTH_LEVEL_NONE),
            ],
            'Matrix - authLevel LOGGED_IN' => [
                'callCanMethods' => self::NONE,
                'canMethodsThatPass' => self::NONE,
                'authLevel' => self::AUTH_LEVEL_LOGGED_IN,
                'recordExists' => true,
                'expectedStatusCode' => 200,
                'expectedJson' => $this->expectedTaskJson(null, self::AUTH_LEVEL_LOGGED_IN),
            ],
            'Matrix - authLevel PERM_CODE' => [
                'callCanMethods' => self::NONE,
                'canMethodsThatPass' => self::NONE,
                'authLevel' => self::AUTH_LEVEL_PERM_CODE,
                'recordExists' => true,
                'expectedStatusCode' => 200,
                'expectedJson' => $this->expectedTaskJson(null, self::AUTH_LEVEL_PERM_CODE),
            ],
            // Other tests
            'Composite callCanMethod' => [
                'callCanMethods' => self::VIEW_CREATE_EDIT_DELETE_ACTION,
                'canMethodsThatPass' => self::NONE,
                'authLevel' => self::AUTH_LEVEL_PERM_CODE,
                'recordExists' => true,
                'expectedStatusCode' => 403,
                'expectedJson' => null,
            ],
        ];
    }

    /**
     * Only testing for canView() here as canCreate(), canEdit() and canDelete() are nonsensical for child relations
     * because POST, PATCH and DELETE only have an effect on the root portions of the endpoint, not child relations
     */
    public function testCanViewCalledForChildRelations(): void
    {
        TestCanMethodStatic::setCanMethodsThatPass(self::NONE);
        // Add a canView() check to the testProject relation, but not the root portion of the endpoint
        $config = Config::inst()->get(TestApiEndpoint::class, 'api_config');
        $config[self::CALL_CAN_METHODS] = self::NONE;
        $config[self::FIELDS]['testProject'][self::CALL_CAN_METHODS] = self::VIEW;
        Config::modify()->set(TestApiEndpoint::class, 'api_config', $config);
        // Remove testProject from the expected json
        $task = TestTask::get()->first();
        $expectedJson = $this->expectedTaskJson();
        unset($expectedJson['testProject']);
        // Make request and assert result
        $response = $this->req('GET', $task->ID);
        $this->assertSame(200, $response->getStatusCode());
        $json = $this->jsonBody($response);
        $this->assertSame($expectedJson, $json);
    }

    /**
     * It does not make sense for there to check canView() at the field level, as the canView()
     * check can only happens at the DataObject level, not the DataObject field level
     * An exception is thrown here if this is attempted to inform developers that this is not supported
     * otherwise they may get a false sense of security by trying to add a canView() check to a field
     */
    public function testCallCanMethodsOnFieldThrowsException(): void
    {
        TestCanMethodStatic::setCanMethodsThatPass(self::NONE);
        // Add a canView() check to the description field, but not the root portion of the endpoint
        $config = Config::inst()->get(TestApiEndpoint::class, 'api_config');
        $config[self::CALL_CAN_METHODS] = self::NONE;
        $config[self::FIELDS]['description'] = [
            self::CALL_CAN_METHODS => self::VIEW,
            self::DATA_OBJECT_FIELD => 'Description',
        ];
        Config::modify()->set(TestApiEndpoint::class, 'api_config', $config);
        // Make request
        $this->expectException(RestApiEndpointConfigException::class);
        $task = TestTask::get()->first();
        $this->req('GET', $task->ID);
    }

    /**
     * Note: testing access is called for root level relatios is already done passively in other tests with
     * 'testReporter' on TestApiEndpoint. Testing access is called for root level fields is already passively
     * done in other tests with 'accessPermissionCode' on TestApiEndpoint
     */
    public function testAccessCalledForChildRelationFields(): void
    {
        // Add ACCESS => LOGGED_IN to the 'title' field on the 'testProject' relation
        $config = Config::inst()->get(TestApiEndpoint::class, 'api_config');
        $config[self::ACCESS] = self::PUBLIC;
        $config[self::FIELDS]['testProject'][self::FIELDS]['title'] = [
            self::ACCESS => self::LOGGED_IN,
            self::DATA_OBJECT_FIELD => 'Title'
        ];
        Config::modify()->set(TestApiEndpoint::class, 'api_config', $config);
        // Remove testProject from the expected json
        $task = TestTask::get()->first();
        $expectedJson = $this->expectedTaskJson(null, self::AUTH_LEVEL_NONE);
        unset($expectedJson['testProject']['title']);
        // Make request and assert result
        $response = $this->req('GET', $task->ID);
        $json = $this->jsonBody($response);
        $this->assertSame($expectedJson, $json);
    }

    // note: there is no test for ALLOWED_OPERATIONS on child relations/fields because it doesn't make any sense
    // to add ALLOWED_OPERATIONS on children. This is because only VIEW operations can be performed on children
    // and if you want to restrict VIEW operations on children then you simply wouldn't include the endpoint config

    /**
     * @dataProvider provideApiViewManyCheckCanMethodsAndAuthLevel
     */
    public function testApiViewManyCheckCanMethodsAndAuthLevel(
        string $callCanMethods,
        string $canMethodsThatPass,
        int $authLevel,
        ?array $expectedJson
    ): void {
        $this->setConfig(self::CALL_CAN_METHODS, $callCanMethods);
        TestCanMethodStatic::setCanMethodsThatPass($canMethodsThatPass);
        $this->login($authLevel);
        $response = $this->req('GET');
        $this->assertSame(200, $response->getStatusCode());
        if (!$this->isFlushing()) {
            $this->assertSame($this->cacheControl(true), $response->getHeader('Cache-Control'));
        }
        $json = $this->jsonBody($response);
        $this->assertSame($expectedJson, $json);
    }

    public function provideApiViewManyCheckCanMethodsAndAuthLevel(): array
    {
        $expectedJson = function(string $permCode) {
            return [
                $this->expectedTaskJson('01', $permCode),
                $this->expectedTaskJson('02', $permCode),
                $this->expectedTaskJson('03', $permCode),
                $this->expectedTaskJson('04', $permCode),
            ];
        };
        return [
            // Matrix - callCanMethods [NONE,VIEW] / pass [NONE,VIEW]
            'Matrix - callCanMethods NONE / canMethodsThatPass NONE' => [
                'callCanMethods' => self::NONE,
                'canMethodsThatPass' => self::NONE,
                'authLevel' => self::AUTH_LEVEL_NONE,
                'expectedJson' => $expectedJson(self::AUTH_LEVEL_NONE),
            ],
            'Matrix - callCanMethods NONE / canMethodsThatPass VIEW' => [
                'callCanMethods' => self::NONE,
                'canMethodsThatPass' => self::VIEW,
                'authLevel' => self::AUTH_LEVEL_NONE,
                'expectedJson' => $expectedJson(self::AUTH_LEVEL_NONE),
            ],
            'Matrix - callCanMethods VIEW / canMethodsThatPass NONE' => [
                'callCanMethods' => self::VIEW,
                'canMethodsThatPass' => self::NONE,
                'authLevel' => self::AUTH_LEVEL_NONE,
                'expectedJson' => [],
            ],
            'Matrix - callCanMethods VIEW / canMethodsThatPass VIEW' => [
                'callCanMethods' => self::VIEW,
                'canMethodsThatPass' => self::VIEW,
                'authLevel' => self::AUTH_LEVEL_NONE,
                'expectedJson' => $expectedJson(self::AUTH_LEVEL_NONE),
            ],
            // Matrix - authLevel [NONE,LOGGED_IN,PERM_CODE]
            'Matrix - authLevel NONE' => [
                'callCanMethods' => self::NONE,
                'canMethodsThatPass' => self::NONE,
                'authLevel' => self::AUTH_LEVEL_NONE,
                'expectedJson' => $expectedJson(self::AUTH_LEVEL_NONE),
            ],
            'Matrix - authLevel LOGGED_IN' => [
                'callCanMethods' => self::NONE,
                'canMethodsThatPass' => self::NONE,
                'authLevel' => self::AUTH_LEVEL_LOGGED_IN,
                'expectedJson' => $expectedJson(self::AUTH_LEVEL_LOGGED_IN),
            ],
            'Matrix - authLevel PERM_CODE' => [
                'callCanMethods' => self::NONE,
                'canMethodsThatPass' => self::NONE,
                'authLevel' => self::AUTH_LEVEL_PERM_CODE,
                'expectedJson' => $expectedJson(self::AUTH_LEVEL_PERM_CODE),
            ],
            // Other tests
            'Composite callCanMethod' => [
                'callCanMethods' => self::VIEW_CREATE_EDIT_DELETE_ACTION,
                'canMethodsThatPass' => self::NONE,
                'authLevel' => self::AUTH_LEVEL_NONE,
                'expectedJson' => []
            ],
        ];
    }

    /**
     * @dataProvider provideApiViewManyFilter
     */
    public function testApiViewManyFilter(array $filter, int $expectedStatusCode, ?array $expectedJson): void
    {
        $qs = '';
        if (!empty($filter)) {
            $arr = [];
            foreach ($filter as $k => $v) {
                if ($v === '<TestProject.First.ID>') {
                    $v = TestProject::get()->first()->ID;
                } elseif ($v === '<TestProject.NonExistant.ID>') {
                    $v = TestProject::get()->max('ID') + 1;
                }
                $arr[] = "filter[$k]=$v";
            }
            $qs = implode('&', $arr);
        }
        $response = $this->req('GET', null, null, $qs);
        $this->assertSame($expectedStatusCode, $response->getStatusCode());
        if ($expectedJson) {
            $json = $this->jsonBody($response);
            $this->assertSame($expectedJson, $json);
        }
    }

    public function provideApiViewManyFilter(): array
    {
        return [
            'no-filter' => [
                'filter' => [],
                'expectedStatusCode' => 200,
                'expectedJson' => [
                    $this->expectedTaskJson('01'),
                    $this->expectedTaskJson('02'),
                    $this->expectedTaskJson('03'),
                    $this->expectedTaskJson('04'),
                ],
            ],
            'single' => [
                'filter' => [
                    'title' => 'TestTask+01+Title'
                ],
                'expectedStatusCode' => 200,
                'expectedJson' => [
                    $this->expectedTaskJson('01'),
                ],
            ],
            'single with search filter' => [
                'filter' => [
                    'description:EndsWith' => 'ak',
                ],
                'expectedStatusCode' => 200,
                'expectedJson' => [
                    $this->expectedTaskJson('02'),
                    $this->expectedTaskJson('03'),
                ],
            ],
            'single with search filter including space' => [
                'filter' => [
                    'title:StartsWith' => 'TestTask+01'
                ],
                'expectedStatusCode' => 200,
                'expectedJson' => [
                    $this->expectedTaskJson('01'),
                ],
            ],
            'single with search filter and a nocase modifier' => [
                'filter' => [
                    'description:StartsWith:nocase' => 'xy',
                ],
                'expectedStatusCode' => 200,
                'expectedJson' => [
                    $this->expectedTaskJson('04'),
                ],
            ],
            'single with search filter and a case modifier' => [
                'filter' => [
                    'description:StartsWith:case' => 'xy',
                ],
                'expectedStatusCode' => 200,
                'expectedJson' => [],
            ],
            'single with numeric search filter on datetime field' => [
                'filter' => [
                    'someDateTime:GreaterThanOrEqual' => '1992-10-20+12:34:56',
                ],
                'expectedStatusCode' => 200,
                'expectedJson' => [
                    $this->expectedTaskJson('03'),
                    $this->expectedTaskJson('04')
                ]
            ],
            'single with relation ID' => [
                'filter' => [
                    'testProject__ID' => '<TestProject.First.ID>', // sboyd
                ],
                'expectedStatusCode' => 200,
                'expectedJson' => [
                    $this->expectedTaskJson('01'),
                    $this->expectedTaskJson('02'),
                    $this->expectedTaskJson('03'),
                    $this->expectedTaskJson('04'),
                ],
            ],
            'single with relation ID that does not exist' => [
                'filter' => [
                    'testProject__ID' => '<TestProject.NonExistant.ID>',
                ],
                'expectedStatusCode' => 200,
                'expectedJson' => [],
            ],
            'multi' => [
                'filter' => [
                    'title:EndsWith' => '02 Title',
                    'description:EndsWith' => 'ak',
                ],
                'expectedStatusCode' => 200,
                'expectedJson' => [
                    $this->expectedTaskJson('02'),
                ],
            ],
            'key that is a dataobject method' => [
                'filter' => [
                    'dataObjectMethod' => 'foo'
                ],
                'expectedStatusCode' => 400,
                'expectedJson' => null,
            ],
            'key that is not in api' => [
                'filter' => [
                    'not-in-api' => 'lorem'
                ],
                'expectedStatusCode' => 400,
                'expectedJson' => null,
            ],
        ];
    }

    /**
     * @dataProvider provideApiViewManySort
     */
    public function testApiViewManySort(
        ?string $sort,
        int $expectedStatusCode,
        ?array $expectedJson
    ): void
    {
        $qs = '';
        if (!is_null($sort)) {
            $qs = "sort=$sort";
        }
        $response = $this->req('GET', null, null, $qs);
        $json = $this->jsonBody($response);
        $this->assertSame($expectedStatusCode, $response->getStatusCode());
        if ($expectedJson) {
            $this->assertSame($expectedJson, $json);
        }
    }

    public function provideApiViewManySort(): array
    {
        return [
            'no sort' => [
                'sort' => null,
                'expectedStatusCode' => 200,
                'expectedJson' => [
                    $this->expectedTaskJson('01'),
                    $this->expectedTaskJson('02'),
                    $this->expectedTaskJson('03'),
                    $this->expectedTaskJson('04'),
                ],
            ],
            'sort single' => [
                'sort' => 'title',
                'expectedStatusCode' => 200,
                'expectedJson' => [
                    $this->expectedTaskJson('01'),
                    $this->expectedTaskJson('02'),
                    $this->expectedTaskJson('03'),
                    $this->expectedTaskJson('04'),
                ],
            ],
            'sort single desc' => [
                'sort' => '-title',
                'expectedStatusCode' => 200,
                'expectedJson' => [
                    $this->expectedTaskJson('04'),
                    $this->expectedTaskJson('03'),
                    $this->expectedTaskJson('02'),
                    $this->expectedTaskJson('01'),
                ],
            ],
            'sort multi' => [
                'sort' => 'description,title',
                'expectedStatusCode' => 200,
                'expectedJson' => [
                    $this->expectedTaskJson('04'),
                    $this->expectedTaskJson('02'),
                    $this->expectedTaskJson('03'),
                    $this->expectedTaskJson('01'),
                ],
            ],
            'sort non-existant field' => [
                'sort' => 'non-existant',
                'expectedStatusCode' => 400,
                'expectedJson' => null,
            ],
            'sort dataobject method field' => [
                'sort' => 'dataObjectField',
                'expectedStatusCode' => 400,
                'expectedJson' => null,
            ],
        ];
    }

    /**
     * @dataProvider provideApiViewManyLimit
     */
    public function testApiViewManyLimit(
        ?string $limit,
        int $expectedStatusCode,
        ?array $expectedJson
    ): void {
        $qs = '';
        if (!is_null($limit)) {
            $qs = "limit=$limit";
        }
        $response = $this->req('GET', null, null, $qs);
        $json = $this->jsonBody($response);
        $this->assertSame($expectedStatusCode, $response->getStatusCode());
        if ($expectedJson) {
            $this->assertSame($expectedJson, $json);
        }
    }

    public function provideApiViewManyLimit(): array
    {
        return [
            'no limit' => [
                'limit' => null,
                'expectedStatusCode' => 200,
                'expectedJson' => [
                    $this->expectedTaskJson('01'),
                    $this->expectedTaskJson('02'),
                    $this->expectedTaskJson('03'),
                    $this->expectedTaskJson('04'),
                ],
            ],
            'limit' => [
                'limit' => '2',
                'expectedStatusCode' => 200,
                'expectedJson' => [
                    $this->expectedTaskJson('01'),
                    $this->expectedTaskJson('02'),
                ],
            ],
            'limit zero' => [
                'limit' => '0',
                'expectedStatusCode' => 400,
                'expectedJson' => null,
            ],
            'limit negative' => [
                'limit' => '-1',
                'expectedStatusCode' => 400,
                'expectedJson' => null,
            ],
            'limit non-integer' => [
                'limit' => 'banana',
                'expectedStatusCode' => 400,
                'expectedJson' => null,
            ],
        ];
    }

    /**
     * @dataProvider provideLimitDefaultMax
     */
    public function testLimitDefaultMax(
        int $limitDefault,
        ?int $limitMax,
        ?int $limit,
        int $expected
    ): void {
        if ($limitDefault) {
            $this->setConfig(self::LIMIT_DEFAULT, $limitDefault);
        }
        if ($limitMax) {
            $this->setConfig(self::LIMIT_MAX, $limitMax);
        }
        $response = $this->req('GET', null, null, $limit ? "limit=$limit" : null);
        $this->assertCount($expected, $this->jsonBody($response));
    }

    public function provideLimitDefaultMax(): array
    {
        return [
            'fallback to default' => [
                'limitDefault' => 2,
                'limitMax' => null,
                'limit' => null,
                'expected' => 2,
            ],
            'limit above default' => [
                'limitDefault' => 2,
                'limitMax' => null,
                'limit' => 4,
                'expected' => 4,
            ],
            'limit below default' => [
                'limitDefault' => 2,
                'limitMax' => null,
                'limit' => 1,
                'expected' => 1,
            ],
            'max below default' => [
                'limitDefault' => 2,
                'limitMax' => 1,
                'limit' => null,
                'expected' => 1,
            ],
            'limit above max' => [
                'limitDefault' => 2,
                'limitMax' => 3,
                'limit' => 4,
                'expected' => 3,
            ],
        ];
    }

    /**
     * @dataProvider provideApiViewManyOffset
     */
    public function testApiViewManyOffset(
        ?string $limit,
        ?string $offset,
        int $expectedStatusCode,
        ?array $expectedJson
    ): void {
        $q = [];
        if (!is_null($limit)) {
            $q[] ="limit=$limit";
        }
        if (!is_null($offset)) {
            $q[] ="offset=$offset";
        }
        $qs = implode('&', $q);
        $response = $this->req('GET', null, null, $qs);
        $json = $this->jsonBody($response);
        $this->assertSame($expectedStatusCode, $response->getStatusCode());
        if ($expectedJson) {
            $this->assertSame($expectedJson, $json);
        }
    }

    public function provideApiViewManyOffset(): array
    {
        return [
            'no limit 1 offset' => [
                'limit' => null,
                'offset' => '1',
                'expectedStatusCode' => 200,
                'expectedJson' => [
                    $this->expectedTaskJson('02'),
                    $this->expectedTaskJson('03'),
                    $this->expectedTaskJson('04'),
                ],
            ],
            'no limit 3 offset' => [
                'limit' => null,
                'offset' => '3',
                'expectedStatusCode' => 200,
                'expectedJson' => [
                    $this->expectedTaskJson('04'),
                ],
            ],
            'no limit 4 offset' => [
                'limit' => null,
                'offset' => '4',
                'expectedStatusCode' => 200,
                'expectedJson' => [],
            ],
            'limit 2 1 offset' => [
                'limit' => '2',
                'offset' => '1',
                'expectedStatusCode' => 200,
                'expectedJson' => [
                    $this->expectedTaskJson('02'),
                    $this->expectedTaskJson('03'),
                ],
            ],
            'negative offset' => [
                'limit' => null,
                'offset' => '-1',
                'expectedStatusCode' => 400,
                'expectedJson' => null,
            ],
            'non-numeric offset' => [
                'limit' => null,
                'offset' => 'chicken',
                'expectedStatusCode' => 400,
                'expectedJson' => null,
            ],
        ];
    }

    public function testHead(): void
    {
        $task = TestTask::get()->first();
        $expectedHeadOneHeaders = $this->req('GET', $task->ID)->getHeaders();
        $expectedHeadManyHeaders = $this->req('GET')->getHeaders();
        $headOneResponse = $this->req('HEAD', $task->ID);
        $headManyResponse = $this->req('HEAD');
        $headOneHeaders = $headOneResponse->getHeaders();
        $headManyHeaders = $headManyResponse->getHeaders();
        if ($this->isFlushing()) {
            // if flushing then the initial GET requests won't return etag headers
            // so omit them from the comparison
            $fn = function ($key) {
                return strtolower($key) !== 'etag';
            };
            $headOneHeaders = array_filter($headOneHeaders, $fn, ARRAY_FILTER_USE_KEY);
            $headManyHeaders = array_filter($headManyHeaders, $fn, ARRAY_FILTER_USE_KEY);
            $expectedHeadOneHeaders = array_filter($expectedHeadOneHeaders, $fn, ARRAY_FILTER_USE_KEY);
            $expectedHeadManyHeaders = array_filter($expectedHeadManyHeaders, $fn, ARRAY_FILTER_USE_KEY);
        }
        // - remove the time portion from the expires header as there is sporadically a one second difference
        //   when running in CI on github actions
        // - sort headers alphabetically so they be asserted against each other
        $updateArray = function (&$arr) {
            $arr['expires'] = preg_replace('# [0-9]{2}:[0-9]{2}:[0-9]{2}#', '', $arr['expires'] ?? '');
            ksort($arr);
        };
        // ensure headers are in the same order
        $updateArray($expectedHeadOneHeaders);
        $updateArray($headOneHeaders);
        $updateArray($expectedHeadManyHeaders);
        $updateArray($headManyHeaders);
        $this->assertSame(204, $headOneResponse->getStatusCode());
        $this->assertSame($expectedHeadOneHeaders, $headOneHeaders);
        $this->assertSame(204, $headManyResponse->getStatusCode());
        $this->assertSame($expectedHeadManyHeaders, $headManyHeaders);
    }

    /**
     * @dataProvider provideApiCreate
     */
    public function testApiCreate(
        string $callCanMethods,
        string $canMethodsThatPass,
        int $authLevel,
        bool $addIdToFieldsConfig,
        $data,
        int $expectedStatusCode,
        ?array $expectedTaskJson
    ): void {
        $this->setConfig(self::CALL_CAN_METHODS, $callCanMethods);
        TestCanMethodStatic::setCanMethodsThatPass($canMethodsThatPass);
        if ($addIdToFieldsConfig) {
            $fields = $this->getConfig(self::FIELDS);
            $fields['id'] = 'ID';
            $this->setConfig(self::FIELDS, $fields);
        }
        $this->login($authLevel);
        $count = TestTask::get()->count();
        $maxID = TestTask::get()->max('ID');
        $newID = $maxID + 1;
        $expectedLocationHeader = null;
        if ($expectedStatusCode === 201) {
            $expectedTaskJson['dataObjectMethod'] = "TestTask 00 DataObjectMethod"; // @todo
            $expectedTaskJson = array_merge($expectedTaskJson, $data ?? []);
            $str = '<TestProject.First.ID>';
            if ($data['testProject__ID'] ?? '' === $str) {
                $data['testProject__ID'] = str_replace($str, TestProject::get()->first()->ID, $data['testProject__ID']);
                unset($expectedTaskJson['testProject__ID']);
            };
            if (array_key_exists('allowedOperationsCreate', $expectedTaskJson)) {
                unset($expectedTaskJson['allowedOperationsCreate']);
            };
            $expectedJson = [
                'data' => $expectedTaskJson,
                'success' => true,
            ];
            if ($this->configContains($callCanMethods, self::VIEW)
                && !$this->configContains($canMethodsThatPass, self::VIEW)) {
                $expectedJson['data'] = [];
            }
            $expectedCount = $count + 1;
            $expectedLocationHeader = Controller::join_links(
                Director::absoluteBaseURL(),
                "/{$this->endpointPath}/$newID"
            );
        } else {
            $expectedJson = [
                'message' => $this->errorMessage($expectedStatusCode),
                'success' => false,
            ];
            $expectedCount = $count;
        }
        $dataForBody = is_array($data) ? $data : null;
        $rawBody = !is_array($data) ? $data : null;
        $response = $this->req('POST', null, null, null, $dataForBody, $rawBody);
        $this->assertSame($expectedStatusCode, $response->getStatusCode());
        $json = $this->jsonBody($response);
        // Testing AllowedOperationsCreate on the DataObject separately rather then in $expectedJson
        // because it's not passed by in the json response as it fails the ALLOWED_OPERATIONS VIEW check
        if (is_array($data) && array_key_exists('allowedOperationsCreate', $data)) {
            $this->assertSame($data['allowedOperationsCreate'], TestTask::get()->last()->AllowedOperationsCreate);
        }
        // Allow for non-generic error messages
        if (!$expectedJson['success'] && !$json['success']) {
            $expectedJson['message'] = $json['message'];
        }
        $this->assertSame($expectedJson, $json);
        $this->assertSame($expectedCount, TestTask::get()->count());
        $this->assertSame($expectedLocationHeader, $response->getHeader('Location'));
        if (!$this->isFlushing()) {
            $this->assertSame($this->cacheControl(false), $response->getHeader('Cache-Control'));
        }
    }

    public function provideApiCreate(): array
    {
        return [
            // Passing in different types of data
            'Passing in data' => [
                'callCanMethods' => self::NONE,
                'canMethodsThatPass' => self::NONE,
                'authLevel' => self::AUTH_LEVEL_NONE,
                'addIdToFieldsConfig' => false,
                'data' => [
                    'title' => 'Task created',
                    'description' => 'rabbit',
                ],
                'expectedStatusCode' => 201,
                'expectedTaskJson' => $this->expectedTaskJson([
                    'title' => 'Task created',
                    'description' => 'rabbit',
                ], self::AUTH_LEVEL_NONE, null),
            ],
            'Passing in no data' => [
                'callCanMethods' => self::CREATE,
                'canMethodsThatPass' => self::CREATE,
                'authLevel' => self::AUTH_LEVEL_NONE,
                'addIdToFieldsConfig' => false,
                'data' => null,
                'expectedStatusCode' => 201,
                'expectedTaskJson' => $this->expectedTaskJson([], self::AUTH_LEVEL_NONE, null),
            ],
            'Passing in garbage data' => [
                'callCanMethods' => self::CREATE,
                'canMethodsThatPass' => self::CREATE,
                'authLevel' => self::AUTH_LEVEL_NONE,
                'addIdToFieldsConfig' => false,
                'data' => 'garbage',
                'expectedStatusCode' => 400,
                'expectedTaskJson' => null,
            ],
            'Passing in primary key field not in api' => [
                'callCanMethods' => self::CREATE,
                'canMethodsThatPass' => self::CREATE,
                'authLevel' => self::AUTH_LEVEL_NONE,
                'addIdToFieldsConfig' => false,
                'data' => [
                    'id' => '1',
                    'title' => 'Task created',
                ],
                'expectedStatusCode' => 400,
                'expectedTaskJson' => null,
            ],
            'Passing in primary key field in api' => [
                'callCanMethods' => self::CREATE,
                'canMethodsThatPass' => self::CREATE,
                'authLevel' => self::AUTH_LEVEL_NONE,
                'addIdToFieldsConfig' => true,
                'data' => [
                    'id' => '1',
                    'title' => 'Task created',
                ],
                'expectedStatusCode' => 400,
                'expectedTaskJson' => null,
            ],
            'Passing in data with non-existant field' => [
                'callCanMethods' => self::CREATE,
                'canMethodsThatPass' => self::CREATE,
                'authLevel' => self::AUTH_LEVEL_NONE,
                'addIdToFieldsConfig' => false,
                'data' => [
                    'title' => 'Task created',
                    'nonExistantField' => 'foo',
                ],
                'expectedStatusCode' => 400,
                'expectedTaskJson' => null,
            ],
            'Passing in data with dataobject method field' => [
                'callCanMethods' => self::CREATE,
                'canMethodsThatPass' => self::CREATE,
                'authLevel' => self::AUTH_LEVEL_NONE,
                'addIdToFieldsConfig' => false,
                'data' => [
                    'title' => 'Task created',
                    'dataObjectMethod' => 'foo',
                ],
                'expectedStatusCode' => 400,
                'expectedTaskJson' => null,
            ],
            'Passing in data with relation field' => [
                'callCanMethods' => self::CREATE,
                'canMethodsThatPass' => self::CREATE,
                'authLevel' => self::AUTH_LEVEL_NONE,
                'addIdToFieldsConfig' => false,
                'data' => [
                    'title' => 'Task created',
                    'testProject' => 'foo',
                ],
                'expectedStatusCode' => 400,
                'expectedTaskJson' => null,
            ],
            'Passing in data with field on a relation' => [
                'callCanMethods' => self::CREATE,
                'canMethodsThatPass' => self::CREATE,
                'authLevel' => self::AUTH_LEVEL_NONE,
                'addIdToFieldsConfig' => false,
                'data' => [
                    'title' => 'Task created',
                    'testProject' => [
                        'title' => 'bar'
                    ],
                ],
                'expectedStatusCode' => 400,
                'expectedTaskJson' => null,
            ],
            'Passing in data with relation ID' => [
                'callCanMethods' => self::CREATE,
                'canMethodsThatPass' => self::CREATE,
                'authLevel' => self::AUTH_LEVEL_NONE,
                'addIdToFieldsConfig' => false,
                'data' => [
                    'title' => 'Task created',
                    'testProject__ID' => '<TestProject.First.ID>',
                ],
                'expectedStatusCode' => 201,
                'expectedTaskJson' => $this->expectedTaskJson([
                    'title' => 'Task created',
                ], self::AUTH_LEVEL_NONE, '01'),
            ],
            // Matrix - Passing in data with individual field ACCESS [NONE,LOGGED_IN,PERM_CODE]
            'Matrix - Passing in data with individual field ACCESS NONE' => [
                'callCanMethods' => self::NONE,
                'canMethodsThatPass' => self::NONE,
                'authLevel' => self::AUTH_LEVEL_NONE,
                'addIdToFieldsConfig' => false,
                'data' => [
                    'title' => 'Task created',
                    'accessPrivate' => 'not-allowed',
                    'accessPermissionCode' => 'not-allowed',
                ],
                'expectedStatusCode' => 401,
                'expectedTaskJson' => null,
            ],
            'Matrix - Passing in data with individual field ACCESS LOGGED_IN' => [
                'callCanMethods' => self::NONE,
                'canMethodsThatPass' => self::NONE,
                'authLevel' => self::AUTH_LEVEL_LOGGED_IN,
                'addIdToFieldsConfig' => false,
                'data' => [
                    'title' => 'Task created',
                    'accessPrivate' => 'allowed',
                    'accessPermissionCode' => 'not-allowed',
                ],
                'expectedStatusCode' => 403,
                'expectedTaskJson' => null,
            ],
            'Matrix - Passing in data with individual field ACCESS PERM_CODE' => [
                'callCanMethods' => self::NONE,
                'canMethodsThatPass' => self::NONE,
                'authLevel' => self::AUTH_LEVEL_PERM_CODE,
                'addIdToFieldsConfig' => false,
                'data' => [
                    'title' => 'Task created',
                    'accessPrivate' => 'allowed',
                    'accessPermissionCode' => 'allowed',
                ],
                'expectedStatusCode' => 201,
                'expectedTaskJson' => $this->expectedTaskJson([
                    'title' => 'Task created',
                    'accessPrivate' => 'allowed',
                    'accessPermissionCode' => 'allowed',
                ], self::AUTH_LEVEL_PERM_CODE, null),
            ],
            // Matrix - Passing in data with individual field ALLOWED_OPERATIONS [VIEW,CREATE,EDIT]
            'Matrix - Passing in data with individual field ALLOWED_OPERATIONS VIEW' => [
                'callCanMethods' => self::CREATE,
                'canMethodsThatPass' => self::CREATE,
                'authLevel' => self::AUTH_LEVEL_NONE,
                'addIdToFieldsConfig' => false,
                'data' => [
                    'title' => 'Task created',
                    'allowedOperationsView' => 'not-allowed',
                ],
                'expectedStatusCode' => 400,
                'expectedTaskJson' => null,
            ],
            'Matrix - Passing in data with individual field ALLOWED_OPERATIONS CREATE' => [
                'callCanMethods' => self::CREATE,
                'canMethodsThatPass' => self::CREATE,
                'authLevel' => self::AUTH_LEVEL_NONE,
                'addIdToFieldsConfig' => false,
                'data' => [
                    'title' => 'Task created',
                    'allowedOperationsCreate' => 'allowed',
                ],
                'expectedStatusCode' => 201,
                'expectedTaskJson' => $this->expectedTaskJson([
                    'title' => 'Task created',
                    // allowedOperationsCreate is tested in testApiCreate() rather than defining here because
                    // it is not passed back in the json response as it fails the the ALLOWED_OPERATIONS VIEW check
                ], self::AUTH_LEVEL_NONE, null),
            ],
            'Matrix - Passing in data with individual field ALLOWED_OPERATIONS EDIT' => [
                'callCanMethods' => self::CREATE,
                'canMethodsThatPass' => self::CREATE,
                'authLevel' => self::AUTH_LEVEL_NONE,
                'addIdToFieldsConfig' => false,
                'data' => [
                    'title' => 'Task created',
                    'allowedOperationsEdit' => 'not-allowed',
                ],
                'expectedStatusCode' => 400,
                'expectedTaskJson' => null,
            ],
            // Matrix - callCanMethods [NONE,CREATE,CREATE_VIEW] / canMethodsThatPass [NONE,CREATE,CREATE_VIEW]
            'Matrix - callCanMethods NONE / canMethodsThatPass NONE' => [
                'callCanMethods' => self::NONE,
                'canMethodsThatPass' => self::NONE,
                'authLevel' => self::AUTH_LEVEL_NONE,
                'addIdToFieldsConfig' => false,
                'data' => null,
                'expectedStatusCode' => 201,
                'expectedTaskJson' => $this->expectedTaskJson([], self::AUTH_LEVEL_NONE, null),
            ],
            'Matrix - callCanMethods NONE / canMethodsThatPass CREATE' => [
                'callCanMethods' => self::NONE,
                'canMethodsThatPass' => self::CREATE,
                'authLevel' => self::AUTH_LEVEL_NONE,
                'addIdToFieldsConfig' => false,
                'data' => null,
                'expectedStatusCode' => 201,
                'expectedTaskJson' => $this->expectedTaskJson([], self::AUTH_LEVEL_NONE, null),
            ],
            'Matrix - callCanMethods NONE / canMethodsThatPass CREATE_VIEW' => [
                'callCanMethods' => self::NONE,
                'canMethodsThatPass' => implode(self::DELIMITER, [self::CREATE, self::VIEW]),
                'authLevel' => self::AUTH_LEVEL_NONE,
                'addIdToFieldsConfig' => false,
                'data' => null,
                'expectedStatusCode' => 201,
                'expectedTaskJson' => $this->expectedTaskJson([], self::AUTH_LEVEL_NONE, null),
            ],
            'Matrix - callCanMethods CREATE / canMethodsThatPass NONE' => [
                'callCanMethods' => self::CREATE,
                'canMethodsThatPass' => self::NONE,
                'authLevel' => self::AUTH_LEVEL_NONE,
                'addIdToFieldsConfig' => false,
                'data' => null,
                'expectedStatusCode' => 403,
                'expectedTaskJson' => null,
            ],
            'Matrix - callCanMethods CREATE / canMethodsThatPass CREATE' => [
                'callCanMethods' => self::CREATE,
                'canMethodsThatPass' => self::CREATE,
                'authLevel' => self::AUTH_LEVEL_NONE,
                'addIdToFieldsConfig' => false,
                'data' => null,
                'expectedStatusCode' => 201,
                'expectedTaskJson' => $this->expectedTaskJson([], self::AUTH_LEVEL_NONE, null),
            ],
            'Matrix - callCanMethods CREATE / canMethodsThatPass CREATE_VIEW' => [
                'callCanMethods' => self::CREATE,
                'canMethodsThatPass' => implode(self::DELIMITER, [self::CREATE, self::VIEW]),
                'authLevel' => self::AUTH_LEVEL_NONE,
                'addIdToFieldsConfig' => false,
                'data' => null,
                'expectedStatusCode' => 201,
                'expectedTaskJson' => $this->expectedTaskJson([], self::AUTH_LEVEL_NONE, null),
            ],
            'Matrix - callCanMethods CREATE_VIEW / canMethodsThatPass NONE' => [
                'callCanMethods' => implode(self::DELIMITER, [self::CREATE, self::VIEW]),
                'canMethodsThatPass' => self::NONE,
                'authLevel' => self::AUTH_LEVEL_NONE,
                'addIdToFieldsConfig' => false,
                'data' => null,
                'expectedStatusCode' => 403,
                'expectedTaskJson' => null,
            ],
            'Matrix - callCanMethods CREATE_VIEW / canMethodsThatPass CREATE' => [
                'callCanMethods' => implode(self::DELIMITER, [self::CREATE, self::VIEW]),
                'canMethodsThatPass' => self::CREATE,
                'authLevel' => self::AUTH_LEVEL_NONE,
                'addIdToFieldsConfig' => false,
                'data' => null,
                'expectedStatusCode' => 201,
                'expectedTaskJson' => null,
            ],
            'Matrix - callCanMethods CREATE_VIEW / canMethodsThatPass CREATE_VIEW' => [
                'callCanMethods' => implode(self::DELIMITER, [self::CREATE, self::VIEW]),
                'canMethodsThatPass' => implode(self::DELIMITER, [self::CREATE, self::VIEW]),
                'authLevel' => self::AUTH_LEVEL_NONE,
                'addIdToFieldsConfig' => false,
                'data' => null,
                'expectedStatusCode' => 201,
                'expectedTaskJson' => $this->expectedTaskJson([], self::AUTH_LEVEL_NONE, null),
            ],
            // Matrix - authLevel [NONE,LOGGED_IN,PERM_CODE]
            'Matrix - authLevel NONE' => [
                'callCanMethods' => self::NONE,
                'canMethodsThatPass' => self::NONE,
                'authLevel' => self::AUTH_LEVEL_NONE,
                'addIdToFieldsConfig' => false,
                'data' => null,
                'expectedStatusCode' => 201,
                'expectedTaskJson' => $this->expectedTaskJson([], self::AUTH_LEVEL_NONE, null),
            ],
            'Matrix - authLevel LOGGED_IN' => [
                'callCanMethods' => self::NONE,
                'canMethodsThatPass' => self::NONE,
                'authLevel' => self::AUTH_LEVEL_LOGGED_IN,
                'addIdToFieldsConfig' => false,
                'data' => null,
                'expectedStatusCode' => 201,
                'expectedTaskJson' => $this->expectedTaskJson([], self::AUTH_LEVEL_LOGGED_IN, null),
            ],
            'Matrix - authLevel PERM_CODE' => [
                'callCanMethods' => self::NONE,
                'canMethodsThatPass' => self::NONE,
                'authLevel' => self::AUTH_LEVEL_PERM_CODE,
                'addIdToFieldsConfig' => false,
                'data' => null,
                'expectedStatusCode' => 201,
                'expectedTaskJson' => $this->expectedTaskJson([], self::AUTH_LEVEL_PERM_CODE, null),
            ],
            // Other tests
            'Composite callCanMethod' => [
                'callCanMethods' => self::VIEW_CREATE_EDIT_DELETE_ACTION,
                'canMethodsThatPass' => self::NONE,
                'authLevel' => self::AUTH_LEVEL_NONE,
                'addIdToFieldsConfig' => false,
                'data' => null,
                'expectedStatusCode' => 403,
                'expectedTaskJson' => null,
            ],
            'Validation failure' => [
                'callCanMethods' => self::NONE,
                'canMethodsThatPass' => self::NONE,
                'authLevel' => self::AUTH_LEVEL_NONE,
                'addIdToFieldsConfig' => false,
                'data' => [
                    'title' => '__INVALID__',
                ],
                'expectedStatusCode' => 422,
                'expectedTaskJson' => null,
            ],
        ];
    }

    /**
     * @dataProvider provideApiEdit
     */
    public function testApiEdit(
        string $callCanMethods,
        string $canMethodsThatPass,
        int $authLevel,
        bool $addIdToFieldsConfig,
        bool $recordExists,
        $data,
        int $expectedStatusCode
    ): void {
        $this->setConfig(self::CALL_CAN_METHODS, $callCanMethods);
        TestCanMethodStatic::setCanMethodsThatPass($canMethodsThatPass);
        if ($addIdToFieldsConfig) {
            $fields = $this->getConfig(self::FIELDS);
            $fields['id'] = 'ID';
            $this->setConfig(self::FIELDS, $fields);
        }
        $this->login($authLevel);
        if ($recordExists) {
            $task = TestTask::get()->first();
            $reporter = $task->testReporter();
            $id = $task->ID;
        } else {
            $task = null;
            $reporter = null;
            $id = TestTask::get()->max('ID') + 1;
        }
        $expectedCount = TestTask::get()->count();
        if ($expectedStatusCode === 200) {
            $taskData = [
                'accessPermissionCode' => $task->AccessPermissionCode,
                'accessPrivate' => $task->AccessPrivate,
                'allowedOperationsView' => $task->AllowedOperationsView,
                'dataObjectMethod' => $task->DataObjectMethod(),
                'description' => $task->Description,
                'someDateTime' => $task->SomeDateTime,
                'testReporter' => !$reporter ? null : [
                    'title' => $reporter->title
                ],
                'title' => $task->Title,
            ];
            $str = '<TestProject.Last.ID>';
            $projectIden = $data['testProject__ID'] ?? '' === $str ? '02' : '01';
            $expectedJson = [
                'data' => $this->expectedTaskJson(
                    array_merge($taskData, $data),
                    $authLevel,
                    $projectIden
                ),
                'success' => true,
            ];
            if ($data['testProject__ID'] ?? '' === $str) {
                $data['testProject__ID'] = str_replace($str, TestProject::get()->last()->ID, $data['testProject__ID']);
                unset($expectedJson['data']['testProject__ID']);
            };
            if ($this->configContains($callCanMethods, self::VIEW)
                && !$this->configContains($canMethodsThatPass, self::VIEW)) {
                $expectedJson['data'] = [];
            }
        } else {
            $expectedJson = [
                'message' => $this->errorMessage($expectedStatusCode),
                'success' => false,
            ];
        }
        $dataForBody = is_array($data) ? $data : null;
        $rawBody = !is_array($data) ? $data : null;
        $response = $this->req('PATCH', $id, null, null, $dataForBody, $rawBody);
        $json = $this->jsonBody($response);
        // Allow for non-generic error messages
        if (!$expectedJson['success'] && !$json['success']) {
            $expectedJson['message'] = $json['message'];
        }
        $this->assertSame($expectedStatusCode, $response->getStatusCode());
        $this->assertSame($expectedJson, $json);
        $this->assertSame($expectedCount, TestTask::get()->count());
        if (!$this->isFlushing()) {
            $this->assertSame($this->cacheControl(false), $response->getHeader('Cache-Control'));
        }
    }

    public function provideApiEdit(): array
    {
        return [
            // Passing in data tests
            'Passing in data' => [
                'callCanMethods' => self::EDIT,
                'canMethodsThatPass' => self::EDIT,
                'authLevel' => self::AUTH_LEVEL_NONE,
                'addIdToFieldsConfig' => false,
                'recordExists' => true,
                'data' => [
                    'title' => 'Task updated',
                ],
                'expectedStatusCode' => 200,
            ],
            'Passing in data changing foreign id' => [
                'callCanMethods' => self::EDIT,
                'canMethodsThatPass' => self::EDIT,
                'authLevel' => self::AUTH_LEVEL_NONE,
                'addIdToFieldsConfig' => false,
                'recordExists' => true,
                'data' => [
                    'testProject__ID' => '<TestProject.Last.ID>',
                ],
                'expectedStatusCode' => 200,
            ],
            'Passing in data with primary key not in api' => [
                'callCanMethods' => self::EDIT,
                'canMethodsThatPass' => self::EDIT,
                'authLevel' => self::AUTH_LEVEL_NONE,
                'addIdToFieldsConfig' => false,
                'recordExists' => true,
                'data' => [
                    'title' => 'Task updated',
                    'id' => 99999
                ],
                'expectedStatusCode' => 400,
            ],
            'Passing in data with primary key in api' => [
                'callCanMethods' => self::EDIT,
                'canMethodsThatPass' => self::EDIT,
                'authLevel' => self::AUTH_LEVEL_NONE,
                'addIdToFieldsConfig' => true,
                'recordExists' => true,
                'data' => [
                    'title' => 'Task updated',
                    'id' => 99999
                ],
                'expectedStatusCode' => 400,
            ],
            'Passing in data with non-existant field' => [
                'callCanMethods' => self::EDIT,
                'canMethodsThatPass' => self::EDIT,
                'authLevel' => self::AUTH_LEVEL_NONE,
                'addIdToFieldsConfig' => false,
                'recordExists' => true,
                'data' => [
                    'nonExistant' => 'foo'
                ],
                'expectedStatusCode' => 400,
            ],
            'Passing in data with dataobject method field' => [
                'callCanMethods' => self::EDIT,
                'canMethodsThatPass' => self::EDIT,
                'authLevel' => self::AUTH_LEVEL_NONE,
                'addIdToFieldsConfig' => false,
                'recordExists' => true,
                'data' => [
                    'dataObjectField' => 'foo'
                ],
                'expectedStatusCode' => 400,
            ],
            'Passing in no data' => [
                'callCanMethods' => self::EDIT,
                'canMethodsThatPass' => self::EDIT,
                'authLevel' => self::AUTH_LEVEL_NONE,
                'addIdToFieldsConfig' => false,
                'recordExists' => true,
                'data' => null,
                'expectedStatusCode' => 400,
            ],
            'Passing in garbage data' => [
                'callCanMethods' => self::EDIT,
                'canMethodsThatPass' => self::EDIT,
                'authLevel' => self::AUTH_LEVEL_NONE,
                'addIdToFieldsConfig' => false,
                'recordExists' => true,
                'data' => 'garbage',
                'expectedStatusCode' => 400,
            ],
            'Passing in data with relation field' => [
                'callCanMethods' => self::EDIT,
                'canMethodsThatPass' => self::EDIT,
                'authLevel' => self::AUTH_LEVEL_NONE,
                'addIdToFieldsConfig' => false,
                'recordExists' => true,
                'data' => [
                    'title' => 'Task updated',
                    'testProject' => 'foo',
                ],
                'expectedStatusCode' => 400,
            ],
            'Passing in data with field on a relation' => [
                'callCanMethods' => self::EDIT,
                'canMethodsThatPass' => self::EDIT,
                'authLevel' => self::AUTH_LEVEL_NONE,
                'addIdToFieldsConfig' => false,
                'recordExists' => true,
                'data' => [
                    'title' => 'Task updated',
                    'testProject' => [
                        'title' => 'bar'
                    ],
                ],
                'expectedStatusCode' => 400,
            ],
            // Matrix - Passing in data with individual field ACCESS [NONE,LOGGED_IN,PERM_CODE]
            'Matrix - Passing in data with individual field ACCESS NONE' => [
                'callCanMethods' => self::NONE,
                'canMethodsThatPass' => self::NONE,
                'authLevel' => self::AUTH_LEVEL_NONE,
                'addIdToFieldsConfig' => false,
                'recordExists' => true,
                'data' => [
                    'title' => 'Task updated',
                    'accessPrivate' => 'not-allowed',
                    'accessPermissionCode' => 'not-allowed',
                ],
                'expectedStatusCode' => 401,
            ],
            'Matrix - Passing in data with individual field ACCESS LOGGED_IN' => [
                'callCanMethods' => self::NONE,
                'canMethodsThatPass' => self::NONE,
                'authLevel' => self::AUTH_LEVEL_LOGGED_IN,
                'addIdToFieldsConfig' => false,
                'recordExists' => true,
                'data' => [
                    'title' => 'Task updated',
                    'accessPrivate' => 'allowed',
                    'accessPermissionCode' => 'not-allowed',
                ],
                'expectedStatusCode' => 403,
            ],
            'Matrix - Passing in data with individual field ACCESS PERM_CODE' => [
                'callCanMethods' => self::NONE,
                'canMethodsThatPass' => self::NONE,
                'authLevel' => self::AUTH_LEVEL_PERM_CODE,
                'addIdToFieldsConfig' => false,
                'recordExists' => true,
                'data' => [
                    'title' => 'Task updated',
                    'accessPrivate' => 'allowed',
                    'accessPermissionCode' => 'allowed',
                ],
                'expectedStatusCode' => 200,
            ],
            // Matrix - Passing in data with individual field ALLOWED_OPERATIONS [VIEW,CREATE,EDIT]
            'Matrix - Passing in data with individual field ALLOWED_OPERATIONS VIEW' => [
                'callCanMethods' => self::CREATE,
                'canMethodsThatPass' => self::CREATE,
                'authLevel' => self::AUTH_LEVEL_NONE,
                'addIdToFieldsConfig' => false,
                'recordExists' => true,
                'data' => [
                    'title' => 'Task updated',
                    'allowedOperationsView' => 'not-allowed',
                ],
                'expectedStatusCode' => 400,
            ],
            'Matrix - Passing in data with individual field ALLOWED_OPERATIONS CREATE' => [
                'callCanMethods' => self::CREATE,
                'canMethodsThatPass' => self::CREATE,
                'authLevel' => self::AUTH_LEVEL_NONE,
                'addIdToFieldsConfig' => false,
                'recordExists' => true,
                'data' => [
                    'title' => 'Task updated',
                    'allowedOperationsCreate' => 'not-allowed',
                ],
                'expectedStatusCode' => 400,
            ],
            'Matrix - Passing in data with individual field ALLOWED_OPERATIONS EDIT' => [
                'callCanMethods' => self::CREATE,
                'canMethodsThatPass' => self::CREATE,
                'authLevel' => self::AUTH_LEVEL_NONE,
                'addIdToFieldsConfig' => false,
                'recordExists' => true,
                'data' => [
                    'title' => 'Task updated',
                    'allowedOperationsEdit' => 'allowed',
                ],
                'expectedStatusCode' => 200,
            ],
            // Matrix - callCanMethods [NONE,EDIT,EDIT_VIEW] / pass [NONE,EDIT,EDIT_VIEW]
            'Matrix - callCanMethods NONE / canMethodsThatPass NONE' => [
                'callCanMethods' => self::NONE,
                'canMethodsThatPass' => self::NONE,
                'authLevel' => self::AUTH_LEVEL_NONE,
                'addIdToFieldsConfig' => false,
                'recordExists' => true,
                'data' => [
                    'title' => 'Task updated',
                ],
                'expectedStatusCode' => 200,
            ],
            'Matrix - callCanMethods NONE / canMethodsThatPass EDIT' => [
                'callCanMethods' => self::NONE,
                'canMethodsThatPass' => self::EDIT,
                'authLevel' => self::AUTH_LEVEL_NONE,
                'addIdToFieldsConfig' => false,
                'recordExists' => true,
                'data' => [
                    'title' => 'Task updated',
                ],
                'expectedStatusCode' => 200,
            ],
            'Matrix - callCanMethods NONE / canMethodsThatPass EDIT_VIEW' => [
                'callCanMethods' => self::NONE,
                'canMethodsThatPass' => implode(self::DELIMITER, [self::EDIT, self::VIEW]),
                'authLevel' => self::AUTH_LEVEL_NONE,
                'addIdToFieldsConfig' => false,
                'recordExists' => true,
                'data' => [
                    'title' => 'Task updated',
                ],
                'expectedStatusCode' => 200,
            ],
            'Matrix - callCanMethods EDIT / canMethodsThatPass NONE' => [
                'callCanMethods' => self::EDIT,
                'canMethodsThatPass' => self::NONE,
                'authLevel' => self::AUTH_LEVEL_NONE,
                'addIdToFieldsConfig' => false,
                'recordExists' => true,
                'data' => [
                    'title' => 'Task updated',
                ],
                'expectedStatusCode' => 403,
            ],
            'Matrix - callCanMethods EDIT / canMethodsThatPass EDIT' => [
                'callCanMethods' => self::EDIT,
                'canMethodsThatPass' => self::EDIT,
                'authLevel' => self::AUTH_LEVEL_NONE,
                'addIdToFieldsConfig' => false,
                'recordExists' => true,
                'data' => [
                    'title' => 'Task updated',
                ],
                'expectedStatusCode' => 200,
            ],
            'Matrix - callCanMethods EDIT / canMethodsThatPass EDIT_VIEW' => [
                'callCanMethods' => self::EDIT,
                'canMethodsThatPass' => implode(self::DELIMITER, [self::EDIT, self::VIEW]),
                'authLevel' => self::AUTH_LEVEL_NONE,
                'addIdToFieldsConfig' => false,
                'recordExists' => true,
                'data' => [
                    'title' => 'Task updated',
                ],
                'expectedStatusCode' => 200,
            ],
            'Matrix - callCanMethods EDIT_VIEW / canMethodsThatPass NONE' => [
                'callCanMethods' => implode(self::DELIMITER, [self::EDIT, self::VIEW]),
                'canMethodsThatPass' => self::NONE,
                'authLevel' => self::AUTH_LEVEL_NONE,
                'addIdToFieldsConfig' => false,
                'recordExists' => true,
                'data' => [
                    'title' => 'Task updated',
                ],
                'expectedStatusCode' => 403,
            ],
            'Matrix - callCanMethods EDIT_VIEW / canMethodsThatPass EDIT' => [
                'callCanMethods' => implode(self::DELIMITER, [self::EDIT, self::VIEW]),
                'canMethodsThatPass' => self::EDIT,
                'authLevel' => self::AUTH_LEVEL_NONE,
                'addIdToFieldsConfig' => false,
                'recordExists' => true,
                'data' => [
                    'title' => 'Task updated',
                ],
                'expectedStatusCode' => 200,
            ],
            'Matrix - callCanMethods EDIT_VIEW / canMethodsThatPass EDIT_VIEW' => [
                'callCanMethods' => implode(self::DELIMITER, [self::EDIT, self::VIEW]),
                'canMethodsThatPass' => implode(self::DELIMITER, [self::EDIT, self::VIEW]),
                'authLevel' => self::AUTH_LEVEL_NONE,
                'addIdToFieldsConfig' => false,
                'recordExists' => true,
                'data' => [
                    'title' => 'Task updated',
                ],
                'expectedStatusCode' => 200,
            ],
            // Matrix - authLevel [NONE,LOGGED_IN,PERM_CODE]
            'Matrix - authLevel AUTH_LEVEL_NONE' => [
                'callCanMethods' => self::NONE,
                'canMethodsThatPass' => self::NONE,
                'authLevel' => self::AUTH_LEVEL_NONE,
                'addIdToFieldsConfig' => false,
                'recordExists' => true,
                'data' => [
                    'title' => 'Task updated',
                ],
                'expectedStatusCode' => 200,
            ],
            'Matrix - authLevel AUTH_LEVEL_LOGGED_IN' => [
                'callCanMethods' => self::NONE,
                'canMethodsThatPass' => self::NONE,
                'authLevel' => self::AUTH_LEVEL_LOGGED_IN,
                'addIdToFieldsConfig' => false,
                'recordExists' => true,
                'data' => [
                    'title' => 'Task updated',
                ],
                'expectedStatusCode' => 200,
            ],
            'Matrix - authLevel AUTH_LEVEL_PERM_CODE' => [
                'callCanMethods' => self::NONE,
                'canMethodsThatPass' => self::NONE,
                'authLevel' => self::AUTH_LEVEL_PERM_CODE,
                'addIdToFieldsConfig' => false,
                'recordExists' => true,
                'data' => [
                    'title' => 'Task updated'
                ],
                'expectedStatusCode' => 200,
            ],
            // Other tests
            'Composite callCanMethod' => [
                'callCanMethods' => self::VIEW_CREATE_EDIT_DELETE_ACTION,
                'canMethodsThatPass' => self::NONE,
                'authLevel' => self::AUTH_LEVEL_NONE,
                'addIdToFieldsConfig' => false,
                'recordExists' => true,
                'data' => null,
                'expectedStatusCode' => 403,
            ],
            'Record does not exist' => [
                'callCanMethods' => self::EDIT,
                'canMethodsThatPass' => self::EDIT,
                'authLevel' => self::AUTH_LEVEL_PERM_CODE,
                'addIdToFieldsConfig' => false,
                'recordExists' => false,
                'data' => [
                    'title' => 'Task updated',
                ],
                'expectedStatusCode' => 404,
            ],

            'Validation failure' => [
                'callCanMethods' => self::NONE,
                'canMethodsThatPass' => self::NONE,
                'authLevel' => self::AUTH_LEVEL_NONE,
                'addIdToFieldsConfig' => false,
                'recordExists' => true,
                'data' => [
                    'title' => '__INVALID__',
                ],
                'expectedStatusCode' => 422,
                'expectedTaskJson' => null,
            ],
        ];
    }

    /**
     * @dataProvider provideApiDelete
     */
    public function testApiDelete(
        string $callCanMethods,
        string $canMethodsThatPass,
        int $authLevel,
        bool $recordExists,
        int $expectedStatusCode
    ): void {
        $this->setConfig(self::CALL_CAN_METHODS, $callCanMethods);
        TestCanMethodStatic::setCanMethodsThatPass($canMethodsThatPass);
        $this->login($authLevel);
        $initialCount = TestTask::get()->count();
        if ($recordExists) {
            $task = TestTask::get()->first();
            $id = $task->ID;
        } else {
            $id = TestTask::get()->max('ID') + 1;
        }
        if ($expectedStatusCode === 200) {
            $expectedJson = [
                'success' => true,
            ];
            $expectedCount = $initialCount - 1;
        } else {
            $expectedJson = [
                'message' => $this->errorMessage($expectedStatusCode),
                'success' => false,
            ];
            $expectedCount = $initialCount;
        }
        $response = $this->req('DELETE', $id);
        $json = $this->jsonBody($response);
        $this->assertSame($expectedStatusCode, $response->getStatusCode());
        $this->assertSame($expectedJson, $json);
        $this->assertSame($expectedCount, TestTask::get()->count());
        if (!$this->isFlushing()) {
            $this->assertSame($this->cacheControl(false), $response->getHeader('Cache-Control'));
        }
    }

    public function provideApiDelete(): array
    {
        return [
            // Matrix - recordExists [true,false]
            'Matrix - recordExists true' => [
                'callCanMethods' => self::DELETE,
                'canMethodsThatPass' => self::DELETE,
                'authLevel' => self::AUTH_LEVEL_NONE,
                'recordExists' => true,
                'expectedStatusCode' => 200,
            ],
            'Matrix - recordExists false' => [
                'callCanMethods' => self::DELETE,
                'canMethodsThatPass' => self::DELETE,
                'authLevel' => self::AUTH_LEVEL_NONE,
                'recordExists' => false,
                'expectedStatusCode' => 404,
            ],
            // Matrix - callCanMethods [NONE,DELETE] / pass [NONE,DELETE]
            'Matrix - callCanMethods NONE / canMethodsThatPass NONE' => [
                'callCanMethods' => self::NONE,
                'canMethodsThatPass' => self::NONE,
                'authLevel' => self::AUTH_LEVEL_NONE,
                'recordExists' => true,
                'expectedStatusCode' => 200,
            ],
            'Matrix - callCanMethods NONE / canMethodsThatPass DELETE' => [
                'callCanMethods' => self::NONE,
                'canMethodsThatPass' => self::DELETE,
                'authLevel' => self::AUTH_LEVEL_NONE,
                'recordExists' => true,
                'expectedStatusCode' => 200,
            ],
            'Matrix - callCanMethods DELETE / canMethodsThatPass NONE' => [
                'callCanMethods' => self::DELETE,
                'canMethodsThatPass' => self::NONE,
                'authLevel' => self::AUTH_LEVEL_NONE,
                'recordExists' => true,
                'expectedStatusCode' => 403,
            ],
            'Matrix - callCanMethods DELETE / canMethodsThatPass DELETE' => [
                'callCanMethods' => self::DELETE,
                'canMethodsThatPass' => self::DELETE,
                'authLevel' => self::AUTH_LEVEL_NONE,
                'recordExists' => true,
                'expectedStatusCode' => 200,
            ],
            // Matrix - authLevel [NONE,LOGGED_IN,PERM_CODE]
            'Matrix - authLevel AUTH_LEVEL_NONE' => [
                'callCanMethods' => self::DELETE,
                'canMethodsThatPass' => self::DELETE,
                'authLevel' => self::AUTH_LEVEL_NONE,
                'recordExists' => true,
                'expectedStatusCode' => 200,
            ],
            'Matrix - authLevel AUTH_LEVEL_LOGGED_IN' => [
                'callCanMethods' => self::DELETE,
                'canMethodsThatPass' => self::DELETE,
                'authLevel' => self::AUTH_LEVEL_LOGGED_IN,
                'recordExists' => true,
                'expectedStatusCode' => 200,
            ],
            'Matrix - authLevel AUTH_LEVEL_PERM_CODE' => [
                'callCanMethods' => self::DELETE,
                'canMethodsThatPass' => self::DELETE,
                'authLevel' => self::AUTH_LEVEL_PERM_CODE,
                'recordExists' => true,
                'expectedStatusCode' => 200,
            ],
            // Other tests
            'Composite callCanMethod' => [
                'callCanMethods' => self::VIEW_CREATE_EDIT_DELETE_ACTION,
                'canMethodsThatPass' => self::NONE,
                'authLevel' => self::AUTH_LEVEL_NONE,
                'recordExists' => true,
                'expectedStatusCode' => 403,
            ],
        ];
    }

    /**
     * @dataProvider provideUnicodeInJsonResponse
     */
    public function testUnicodeInJsonResponse(string $title, string $contentLength): void
    {
        $config = Config::inst()->get(TestApiEndpoint::class, 'api_config');
        $config[self::FIELDS] = ['title' => 'Title'];
        Config::modify()->set(TestApiEndpoint::class, 'api_config', $config);
        $task = TestTask::get()->first();
        $task->Title = $title;
        $task->write();
        $response = $this->req('GET', $task->ID);
        // assert that Content-length header correctly counts bytes, not just number of characters
        $this->assertSame($contentLength, $response->getHeader('Content-length'));
        // assert that unicode is unescaped with JSON_UNESCAPED_UNICODE e.g. "ō" renders as "ō", not "\u014d"
        $this->assertStringContainsString($title, $response->getBody());
    }

    public function provideUnicodeInJsonResponse(): array
    {
        return [
            [
                'title' => 'aaa',
                'contentLength' => '15'
            ],
            [
                'title' => 'ōōō',
                'contentLength' => '18'
            ],
            [
                'title' => '℅℅℅',
                'contentLength' => '21'
            ],
            [
                'title' => '👍👍👍',
                'contentLength' => '24'
            ],
        ];
    }

    public function testETag()
    {
        $this->setConfig(self::CALL_CAN_METHODS, self::NONE);
        // double quotes inside single quotes are intentional
        $expectedViewOperation = '"6cd52dbfaf406fcece186c5a9004e677"';
        $expectedBlankBody = '"d41d8cd98f00b204e9800998ecf8427e"';
        $taskID = TestTask::get()->first()->ID;
        $this->assertSame($expectedViewOperation, $this->req('GET', $taskID)->getHeader('ETag'));
        $this->assertSame($expectedViewOperation, $this->req('HEAD', $taskID)->getHeader('ETag'));
        $this->assertSame(null, $this->req('POST')->getHeader('ETag'));
        $this->assertSame(null, $this->req('PATCH', $taskID, null, null, ['title' => 'changed'])->getHeader('ETag'));
        $this->assertSame(null, $this->req('DELETE', $taskID)->getHeader('ETag'));
        $this->assertSame(null, $this->req('PUT')->getHeader('ETag'));
        // OPTIONS gets an etag added by ChangeDetectionMiddleware
        // commenting out as this as $actual was null on a different local environment, not sure why
        // possibly a different version of framework. It's OK not to test this here.
        // $this->assertSame($expectedBlankBody, $this->req('OPTIONS')->getHeader('ETag'));
    }

    public function testExtensionHooks(): void
    {
        $task = TestTask::get()->first();
        $taskID = $task->ID;
        // ViewOne
        $this->req('GET', $taskID);
        $this->assertTrue(TestApiEndpoint::$hooksCalled['onViewOne']);
        // ViewMany
        $this->req('GET');
        $this->assertTrue(TestApiEndpoint::$hooksCalled['onViewMany']);
        // Create
        $this->req('POST', null, null, null, ['title' => 'test']);
        $this->assertTrue(TestApiEndpoint::$hooksCalled['onCreateBeforeWrite']);
        $this->assertTrue(TestApiEndpoint::$hooksCalled['onCreateAfterWrite']);
        // Edit
        $this->req('PATCH', $taskID, null, null, ['title' => 'test']);
        $this->assertTrue(TestApiEndpoint::$hooksCalled['onEditBeforeWrite']);
        $this->assertTrue(TestApiEndpoint::$hooksCalled['onEditAfterWrite']);
        // Action
        $this->req('PUT', $taskID, 'publish');
        $this->assertTrue(TestApiEndpoint::$hooksCalled['onBeforeAction']);
        $this->assertTrue(TestApiEndpoint::$hooksCalled['onAfterAction']);
        // Delete - need to call this after all the others
        $this->req('DELETE', $taskID);
        $this->assertTrue(TestApiEndpoint::$hooksCalled['onDeleteBeforeDelete']);
        $this->assertTrue(TestApiEndpoint::$hooksCalled['onDeleteAfterDelete']);
        // BeforeSendResponse
        $this->assertTrue(TestApiEndpoint::$hooksCalled['onBeforeSendResponse']);
        $this->assertTrue(TestApiEndpoint::$hooksCalled['updateApiConfig']);
    }

    public function testVersionedActions(): void
    {
        // Set ACCESS to LOGGED_IN to set versioned mode to DRAFT in rest-api
        $this->setConfig(self::ACCESS, self::LOGGED_IN);
        $this->login(self::AUTH_LEVEL_LOGGED_IN);
        TestVersionedExtension::disableAutoPublish();
        $task = TestTask::get()->first();
        $taskID = $task->ID;
        // create a draft change
        $this->req('PATCH', $taskID, null, null, ['title' => 'Updated'])->getStatusCode();
        // assert versioning actions
        $task = TestTask::get()->byID($taskID);
        $this->assertTrue($task->stagesDiffer());
        $this->req('PUT', $taskID, 'publish');
        $task = TestTask::get()->byID($taskID);
        $this->assertFalse($task->stagesDiffer());
        $this->req('PUT', $taskID, 'unpublish');
        $task = TestTask::get()->byID($taskID);
        $this->assertTrue($task->stagesDiffer());
        $this->req('PUT', $taskID, 'archive');
        $task = TestTask::get()->byID($taskID);
        $this->assertNull($task);
    }

    private function login(int $authLevel)
    {
        if ($authLevel === self::AUTH_LEVEL_NONE) {
            return;
        }
        if ($authLevel === self::AUTH_LEVEL_LOGGED_IN) {
            $this->logInWithPermission('REGULAR');
        }
        if ($authLevel === self::AUTH_LEVEL_PERM_CODE) {
            $this->logInWithPermission('ADMIN');
        }
    }

    private function getConfig(string $key)
    {
        return Config::inst()->get(TestApiEndpoint::class, 'api_config')[$key];
    }

    private function setConfig(string $key, $value): void
    {
        Config::modify()->merge(TestApiEndpoint::class, 'api_config', [$key => $value]);
    }

    private function req(
        string $method,
        int $id = null,
        string $action = null,
        string $qs = null,
        ?array $dataForBody = null,
        ?string $rawBody = '',
        string $csrfTokenType = 'valid'
    ): HTTPResponse {
        $url = $this->endpointPath;
        if ($id) {
            $url .= "/$id";
        }
        if ($action) {
            $url .= "/$action";
        }
        if ($qs) {
            $url .= "?$qs";
        }
        if ($rawBody) {
            $body = $rawBody;
        } else {
            $body = json_encode($dataForBody ?: [], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
        }
        $headers = [];
        if ($csrfTokenType === 'valid') {
            $headers['x-csrf-token'] = SecurityToken::getSecurityID();
        } elseif ($csrfTokenType === 'invalid') {
            $headers['x-csrf-token'] = 'nonsense';
        }
        return $this->mainSession->sendRequest($method, $url, [], $headers, null, $body);
    }

    private function errorMessage(int $code)
    {
        switch ($code) {
            case 400:
                return 'Bad request';
            case 401:
                return 'Unauthorised';
            case 403:
                return 'Forbidden';
            case 404:
                return 'Not found';
            case 405:
                return 'HTTP request method not allowed';
            default:
                return 'Error';
        }
    }

    /**
     * Passing in $taskIdenOrData as null will default to using TestTask 01
     */
    private function expectedTaskJson(
        $taskIdenOrData = null,
        int $authLevel = self::AUTH_LEVEL_NONE,
        ?string $projectIden = '01'
    ): array {
        $testMilestones = $projectIden === '02' ? [] : [
            ['title' => 'TestMilestone 01 Title'],
            ['title' => 'TestMilestone 02 Title']
        ];
        $testProject = [
            'testMilestones' => $testMilestones,
            'testTeam' => $projectIden === '02' ? null : [
                // Field type testing
                'myBigInt' => 1234567890,
                'myBoolean' => true,
                'myCurrency' => 999.12,
                'myDate' => '2020-11-22',
                'myDateTime' => '2020-11-22 12:34:56',
                'myDecimal' => 999.12,
                'myDouble' => 999.123456789,
                'myEnum' => 'Option2',
                'myFloat' => 999.123,
                'myHTMLFragment' => '<strong>The quick brown fox</strong>',
                'myHTMLVarchar' => '<strong>The quick brown fox</strong>',
                'myInt' => 1234567890,
                'myLocale' => 'en_NZ',
                'myMoney' => '999.1235 NZD',
                'myMutliEnum' => 'Option2,Option3',
                'myPercentage' => 0.1234568,
                'myText' => 'Lorem ipsum',
                'myTime' => '12:34:56',
                'myVarchar' => 'Lorem ipsum',
                'myYear' => 1989,
                // standard title field
                'title' => 'TestTeam 01 Title', // @todo is this right?
            ],
            'title' => "TestProject $projectIden Title",
        ];
        $testReporter = [
            'title' => 'TestReporter 01 Title',
        ];
        if (is_null($projectIden)) {
            $testProject = null;
        }
        if (is_array($taskIdenOrData)) {
            $data = $taskIdenOrData;
            $a = [
                'allowedOperationsView' => $data['allowedOperationsView'] ?? '',
                'dataObjectMethod' => $data['dataObjectMethod'] ?? '',
                'description' => $data['description'] ?? '',
                'someDateTime' => $data['someDateTime'] ?? '',
                'testProject' => $testProject,
                'title' => $data['title'] ?? '',
            ];
            if ($authLevel !== self::AUTH_LEVEL_NONE) {
                $a['accessPrivate'] = $data['accessPrivate'] ?? '';
                if ($authLevel === self::AUTH_LEVEL_PERM_CODE) {
                    $a['accessPermissionCode'] = $data['accessPermissionCode'] ?? '';
                    $a['testReporter'] = $data['testReporter'] ?? null;
                }
            }
            ksort($a);
            return $a;
        } else {
            $taskIden = $taskIdenOrData;
            if (is_null($taskIden)) {
                $taskIden = '01';
            }
            $descriptions = [
                '01' => 'Zoo',
                '02' => 'Yak',
                '03' => 'Yak',
                '04' => 'Xylophone',
            ];
            $someDateTimes = [
                '01' => '1990-10-20 12:34:56',
                '02' => '1991-10-20 12:34:56',
                '03' => '1992-10-20 12:34:56',
                '04' => '1993-10-20 12:34:56',
            ];
            $a = [
                'allowedOperationsView' => "TestTask $taskIden AllowedOperationsView",
                'dataObjectMethod' => "TestTask $taskIden DataObjectMethod",
                'description' => $descriptions[$taskIden],
                'someDateTime' => $someDateTimes[$taskIden],
                'testProject' => $testProject,
                'title' => "TestTask $taskIden Title",
            ];
            if ($authLevel !== self::AUTH_LEVEL_NONE) {
                $a['accessPrivate'] = "TestTask $taskIden AccessPrivate";
                if ($authLevel === self::AUTH_LEVEL_PERM_CODE) {
                    $a['accessPermissionCode'] = "TestTask $taskIden AccessPermissionCode";
                    $a['testReporter'] = $testReporter;
                }
            }
            ksort($a);
            return $a;
        }
    }

    private function jsonBody(HTTPResponse $response): array
    {
        $json = json_decode($response->getBody(), true);
        $this->alphaSortJsonKeys($json);
        return $json;
    }

    private function alphaSortJsonKeys(array &$json): void
    {
        ksort($json);
        foreach ($json as &$v) {
            if (is_array($v)) {
                $this->alphaSortJsonKeys($v);
            }
        }
    }

    private function cacheControl(bool $enabled, int $maxAge = 55): string
    {
        if ($enabled) {
            return "must-revalidate, max-age=$maxAge";
        }
        return 'no-cache, no-store, must-revalidate';
    }

    /**
     * Used to skip skip cache control header check when running unit tests with flush=1 because
     * flushing will always disable caching.
     */
    private function isFlushing(): bool
    {
        global $argv;
        foreach ($argv as $arg) {
            if (substr($arg, 0, 6) === 'flush=') {
                return true;
            }
        }
        if (!is_null(Controller::curr()->getRequest()->getVar('flush'))) {
            return true;
        }
        return false;
    }

    private function configContains(string $configValue, string $value)
    {
        $values = explode(self::DELIMITER, $configValue);
        return in_array($value, $values);
    }
}
