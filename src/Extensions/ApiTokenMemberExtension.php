<?php

namespace emteknetnz\RestApi\Extensions;

use emteknetnz\RestApi\PermissionProviders\ApiTokenPermissionProvider;
use SilverStripe\Core\Extension;
use SilverStripe\Forms\CheckboxField;
use SilverStripe\Forms\FieldList;
use SilverStripe\Forms\TextField;
use SilverStripe\ORM\ValidationResult;
use SilverStripe\Security\Permission;

class ApiTokenMemberExtension extends Extension
{
    private static $db = [
        'ApiToken' => 'Varchar'
    ];

    private string $unencryptedApiToken = '';

    /**
     * Sets the ApiToken field to a new randomly generated API token
     *
     * @return string The unencrypted API token
     */
    public function refreshApiToken(): string
    {
        /** @var Member $member */
        $member = $this->getOwner();
        $this->unencryptedApiToken = $this->generateRandomApiToken();
        $member->ApiToken = $member->encryptWithUserSettings($this->unencryptedApiToken);
        return $this->unencryptedApiToken;
    }

    public function updateCMSFields(FieldList $fields): void
    {
        /** @var Member $member */
        $member = $this->getOwner();
        // Never show the encrypted API token database field
        $fields->removeByName('ApiToken');
        // Check the user is allowed to use API tokens
        $code = ApiTokenPermissionProvider::API_TOKEN_AUTHENTICATION;
        if (!Permission::checkMember($member, $code)) {
            return;
        }
        // Create a checkbox to generate a new API token
        $checkboxField = CheckboxField::create('GenerateApiToken', 'Generate new API token', false);
        $checkboxField->setDescription('This will generate a new API token for this user when saved');
        if ($fields->dataFieldByName('RequiresPasswordChangeOnNextLogin')) {
            // Regular user
            $fields->insertAfter('RequiresPasswordChangeOnNextLogin', $checkboxField);
        } else {
            // Admin
            $fields->insertAfter('Password', $checkboxField);
        }
        if ($this->unencryptedApiToken !== '') {
            // Create a readonly text field to display the new API token
            $readonlyField = TextField::create('ReadonlyApiToken', 'API token', $this->unencryptedApiToken);
            $message = 'This is your new API token. Please copy it now as it will not be shown again.';
            $readonlyField->setMessage($message, ValidationResult::TYPE_GOOD);
            $readonlyField->setReadonly(true);
            $tab = $fields->findTab('Root.Main');
            $tab->unshift($readonlyField);
            $this->unencryptedApiToken = '';
        }
    }

    public function onBeforeWrite(): void
    {
        /** @var Member $member */
        $member = $this->getOwner();
        if ($member->GenerateApiToken) {
            $member->refreshApiToken();
        }
        // Ensure checkbox is unticked on page reload
        $member->GenerateApiToken = false;
    }

    private function generateRandomApiToken(): string
    {
        $len = 32;
        $charsets = [
            'abcdefghijklmnopqrstuvwyxz',
            'ABCDEFGHIJKLMNOPQRSTUVWYXZ',
            '0123456789',
            '!@#$%^&*()_+-=[]{};:,./<>?',
        ];
        $apiToken = '';
        for ($i = 0; $i < $len; $i++) {
            $charset = $charsets[$i % 4];
            $randomInt = random_int(0, strlen($charset) - 1);
            $apiToken .= $charset[$randomInt];
        }
        $passwordArr = [];
        $len = strlen($apiToken);
        foreach (str_split($apiToken) as $char) {
            $r = random_int(0, $len + 10000);
            while (array_key_exists($r, $passwordArr)) {
                $r++;
            }
            $passwordArr[$r] = $char;
        }
        ksort($passwordArr);
        $apiToken = implode('', $passwordArr);
        return $apiToken;
    }
}
