<?php

namespace emteknetnz\RestApi\Tests\Controllers\RestApiTest;

use SilverStripe\Dev\TestOnly;
use emteknetnz\RestApi\Tests\Controllers\RestApiTest\TestProject;
use emteknetnz\RestApi\Tests\Controllers\RestApiTest\TestCanMethodsTrait;
use SilverStripe\ORM\DataObject;

class TestTeam extends DataObject implements TestOnly
{
    use TestCanMethodsTrait;

    private static $db = [
        // Fields for testing datatypes:
        // https://docs.silverstripe.org/en/5/developer_guides/model/data_types_and_casting/
        // Note the following fields from those listed in the link are not tested:
        // - DBClassName
        // - ForeignKey
        // - PolymorphicForeignKey
        // - PrimaryKey
        'MyBigInt' => 'BigInt',
        'MyBoolean' => 'Boolean',
        'MyCurrency' => 'Currency',
        'MyDate' => 'Date',
        'MyDateTime' => 'Datetime',
        'MyDecimal' => 'Decimal',
        'MyDouble' => 'Double',
        'MyEnum' => 'Enum("Option1,Option2,Option3")',
        'MyFloat' => 'Float',
        'MyHTMLFragment' => 'HTMLFragment',
        'MyHTMLVarchar' => 'HTMLVarchar',
        'MyInt' => 'Int',
        'MyLocale' => 'Locale',
        'MyMoney' => 'Money',
        'MyMutliEnum' => 'MultiEnum("Option1,Option2,Option3")',
        'MyPercentage' => 'Percentage(7)',
        'MyText' => 'Text',
        'MyTime' => 'Time',
        'MyVarchar' => 'Varchar(255)',
        'MyYear' => 'Year',
        // Standard field used in tests not specifically for testing datatypes
        'Title' => 'Varchar',
    ];

    private static $has_many = [
        'TestProjects' => TestProject::class,
    ];

    private static $table_name = 'TestTeam';
}
