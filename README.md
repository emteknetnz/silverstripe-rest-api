# Silverstripe REST API

**NOTE: This module is currently a pre-release. The API and/or behaviour may change as newer pre-release versions are tagged.**

This module allows you to quickly and easily create secure REST API endpoints that can be used for both providing database records as JSON as well as optionally allow data to be updated through the API.

Simply subclass the `RestApiEndpoint` class and define your endpoint with `private static array` configuration.

An endpoint provides data for one DataObject type, for instance `SiteTree`. To provide data for more DataObject types simply add more endpoints.

This module is not intended to replace regular Silverstripe controller endpoints if you endpoint provides non-DataObject data.

These instructions assume you have created a project that have `silverstripe/recipe-cms` in the composer.json as some of the code instructions include the `SiteTree` class. You can still use this module without `silverstripe/recipe-cms` as `silverstripe/framework` is the only requirement, though `silverstripe/versioned` is required for the `publish`, `unpublish` and `archive` actions.

Also a common gotcha, if your dataobject isn't showing in the JSON response then you probably need to add a `canView()` to your dataobject that returns `true`. Alternatively you can simply disable the `canView()` check by setting `CALL_CAN_METHODS` to `CREATE_EDIT_DELETE_ACTION` (which lacks `VIEW`) in your endpoint config.

### Contents:

- [Installation](#readme-quickstart)
- [Quickstart](#readme-quickstart)
- [Querying data](#readme-querying-data)
  - [Filtering](#readme-filtering)
  - [Sorting](#readme-sorting)
  - [Limiting and offsetting](#readme-limiting-and-offsetting)
- [HTTP requests and status codes](#readme-http-requests)
  - [Generic failure status codes](#readme-http-generic)
  - [OPTIONS](#readme-http-options)
  - [GET](#readme-http-get)
  - [HEAD](#readme-http-head)
  - [POST](#readme-http-post)
  - [PATCH](#readme-http-patch)
  - [DELETE](#readme-http-delete)
  - [PUT](#readme-http-put)
- [Endpoint configuration options](#readme-config)
- [Relations](#readme-relations)
- [Individual fields](#readme-individual-fields)
- [CSRF token](#readme-csrf-token)
- [API token](#readme-api-token)
- [Extension hooks](#readme-extension-hooks)

## Installation<a name="readme-installation"></a>

`composer require emteknetnz/silverstripe-rest-api`

Works on both Silverstripe CMS 4 and 5.

## Quickstart<a name="readme-quickstart"></a>

Copy paste the following code snippets to quickly setup a public readonly endpoint the provides `SiteTree` data.

This assumes that you have an existing project created with `silverstripe/cms` installed so that you have the `SiteTree` class available.

**src/MySiteTreeEndpoint.php**

```php
<?php

use emteknetnz\RestApi\Controllers\RestApiEndpoint;
use SilverStripe\CMS\Model\SiteTree;

class MySiteTreeEndpoint extends RestApiEndpoint
{
    private static array $api_config = [
        RestApiEndpoint::PATH => 'api/pages',
        RestApiEndpoint::DATA_CLASS => SiteTree::class,
        RestApiEndpoint::ACCESS => RestApiEndpoint::PUBLIC,
        RestApiEndpoint::FIELDS => [
            'title' => 'Title',
            'absoluteLink' => 'AbsoluteLink',
            'content' => 'Content',
            'lastEdited' => 'LastEdited',
        ],
    ];
}
```

Run `https://mysite.test/dev/build?flush=1`

Visit `https://mysite.test/api/pages` to see endpoint data.

Visit `https://mysite.test/api/pages/1` to see endpoint data for page with an `ID` of `1`

## Querying data<a name="readme-querying-data"></a>

Filter data by adding querystring parameters to a `GET` request made to the endpoint

### Filtering<a name="readme-filtering"></a>

To filter on an exact value:

`?filter=[<field>]=<value>`

The use a [search filter](https://docs.silverstripe.org/en/5/developer_guides/model/searchfilters/) such as `PartialMatchFilter` use:

`?filter=[<field>:<SearchFilter>]=<value>`

When using a search filter in the querystring omit the 'Filter' suffix from its name. For example to use the `StartsWithFilter` to search for titles starting with "Hello" use `StartsWith` in the querystring:

`?filter=[<title>:StartsWith]=Hello`

To use a [search filter modifier](https://docs.silverstripe.org/en/5/developer_guides/model/searchfilters/#modifiers) such as "case" use:

`?filter=[<field>:<SearchFilter>:<Modifier>]=<value>`

For example to return all pages with the word "About" in them matched case-sensitive. Note that Silverstripe ORM uses the `nocase` search modifier by default if it is not specified.

`?filter[title:PartialMatch:case]=About`

To use multiple filters, for example to filter on the `title` and `lastEdited` fields:

`?filter[title:PartialMatch]=rockets&filter[lastEdited:GreaterThan]=2022-01-01`

The following search filters are available:

- `ExactMatch`
- `StartsWith`
- `EndsWith`
- `PartialMatch`
- `GreaterThan`
- `GreaterThanOrEqual`
- `LessThan`
- `LessThanOrEqual`

The following search filter modifiers are available:

- `case`
- `no-case`
- `not`

### Sorting<a name="readme-sorting"></a>

To sort by a field in ascending order:

`?sort=<field>`

To sort by a field in descending order:

`?sort=-<field>`

To sort by multiple fields use a comma to separate them:

`?sort=-<field1>,<field2>`

For example, to sort all pages by publishedYear descending first and title ascending second:

`?sort=-publishedYear,title`

### Limiting and offsetting<a name="readme-limiting-and-offsetting"></a>

To limit the number of records:

`?limit=<number>`

To offset records:

`?offset=<number>`

For example to get the second page of 10 records:

`?limit=10&offset=10`

The default limit is `30`, and the max limit that can be specified via the querystring is `100`. Both these limits can be changed in the endpoint config.

## HTTP requests and status codes<a name="readme-http-requests"></a>

### Failure codes<a name="readme-http-generic"></a>

The following failure codes are used in a variety of requests

| Status code | Description |
| - | - |
| `400` | Bad request, for example a missing `x-csrf-token` header |
| `401` | The current user cannot access the endpoint because they failed an access check configured with `ACCESS`|
| `403` | HTTP method is forbidden for the current user because they failed a `can*()` check configured with `CALL_CAN_METHODS` |
| `405` | HTTP method not allowed on this endpoint configured with `ALLOWED_OPERATIONS` |
| `500` | Server error, usually as a result project endpoint misconfiguration |

Response body will be JSON with a `"success":false` node and a `"message"` node that describes the error.

### OPTIONS<a name="readme-http-options"></a>

The `OPTIONS` HTTP request is always allowed and will return a list of allowed operations for the endpoint in the `allow` response header

| Status code | Description | Response body |
| - | - | - |
| `204` | Success | Empty |

### GET<a name="readme-http-get"></a>

The `GET` HTTP request is used to read data from the endpoint. You can view a list of nodes by visiting the endpoint URL, or view a single node by visiting the endpoint URL with the ID of the node. e.g.

Examples:
- `curl -X GET https://mysite.test/api/pages` 
- `curl -X GET https://mysite.test/api/pages/<id>`

| Status code | Description | Response body |
| - | - | - |
| `200` | Successfully read data | JSON matching endpoint config |

### HEAD<a name="readme-http-head"></a>

The same as `GET` though only returns the headers that would be be returned by `GET` with an empty body

Examples:
- `curl --head https://mysite.test/api/pages` 
- `curl --head https://mysite.test/api/pages/123`

| Status code | Description | Response body |
| - | - | - |
| `204` | Successfully read data | None |

### POST<a name="readme-http-post"></a>

The `POST` HTTP request is used to create a new record. The body of the request should be a JSON object with the data to create the record that matches the endpoint configuration i.e. specify the `jsonKey` to update on the DataObject, not the `dataObjectKey`.

Specifying field values is optional, though may be required depending on DataObject validation.

Example:
- `curl -X POST https://mysite.test/api/pages -d '{"title":"My title"}'`

| Status code | Description | Response body |
| - | - | - |
| `201` | Record created | JSON with a `"success": true` node and a `"data"` node with JSON matching the endpoint config for the newly created record |
| `400` | Invalid request body JSON | JSON with a `"success":false` node and a `"message"` node |
| `422` | Validation error | JSON with a `"success":false` node and a `"message"` node |

### PATCH<a name="readme-http-patch"></a>

The `PATCH` HTTP request is used to update an existing record where ID is specified in the URL. The body of the request should be a JSON object with the data to update the record that matches the endpoint configuration i.e. specify the `jsonKey` to update on the DataObject, not the `dataObjectKey`.

Specifying field values is optional, though may be required depending on DataObject validation.

Example:
- `curl -X PATCH https://mysite.test/api/pages/123 -d '{"title":"My updated title"}'`

| Status code | Description | Response body |
| - | - | - |
| `200` | Record updated | JSON with a `"success": true` node and a `"data"` node with JSON matching the endpoint config for the updated record |
| `400` | Invalid request body JSON | JSON with a `"success":false` node and a `"message"` node |
| `422` | Validation error | JSON with a `"success":false` node and a `"message"` node |

### DELETE<a name="readme-http-delete"></a>

The `DELETE` HTTP request is used to delete an existing record where ID is specified in the URL. If the `Versioned` extension from the `silverstripe/versioned` module has been applied to the DataObject then the `doArchive()` method is called on the DataObject which deletes it from other the draft and live versions of the site. If the `Versioned` extension has not bee applied then the `delete()` method will be called on DataObject instead.

Example:
- `curl -X DELETE https://mysite.test/api/pages/123`

| Status code | Description | Response body |
| - | - | - |
| `200` | Record deleted | JSON with a `"success":true` node |

### PUT<a name="readme-http-put"></a>

The `PUT` HTTP request is only used to run a predefined list of actions. It is NOT used to create or update data which `PUT` is commonly used for in other REST API implementations. Instead use `POST` or `PATCH` respectively for create or update operations.

Actions can only be run on existing records. The action parameter is added to the URL after the ID of the existing record.

The following actions are available:
| Action | Description |
| - | - |
| `publish` | Publish a record. Requires the `Versioned` extension from `silverstripe/versioned` module to be applied to the `DataObject`. |
| `unpublish` | Unpublish a record. Requires the `Versioned` extension from `silverstripe/versioned` module to be applied to the `DataObject`. |
| `archive` | Archive a record. Requires the `Versioned` extension from `silverstripe/versioned` module to be applied to the `DataObject`. Note this similar to using the `DELETE` HTTP method. |

Example:
- `curl -X PUT https://mysite.test/api/pages/123/publish`

| Status code | Description | Response body |
| - | - | - |
| `200` | Action succeeded | JSON with a `"success":true` node |

## Endpoint configuration options<a name="readme-config"></a>

Endpoint configuration is done using the `private array static $api_config` field on your subclass of `RestApiEndpoint`. Remember to `?flush=1` to apply the new configuration. The following table includes a list of configuration constants available on the `RestApiEndpoint` class.

| Key | Description |
| - | - |
| `PATH` | The path to your API<br><br>A leading forward slash is optional.<br><br>Warning: starting the path with `/admin` will NOT require the user to log into the admin section before accessing the API which is probably not what you would expect |
| `DATA_CLASS` | The FQCN of DataObject for the API endpoint |
| `FIELDS` | An associative array of fields to show where `'jsonKey'` => `'dataObjectKey'`<br><br>DataObject methods can be also be used along with regular fields, though you cannot perform queries on DataObject methods.<br><br>Nested relations on DataObjects can also be used. |
| `ACCESS` | The level of access required for the endpoint or for an individual field or relation. Options are:<ul><li>`PUBLIC` - Can be accessed by anyone including not-logged-in users</li><li>`LOGGED_IN` - Must be logged in to access</li><li>`<PERMISSION_CODE>` - User must be in a Group with this permission code</li><br><br>If this is not set to `PUBLIC` the an `x-csrf-token` header must be past in unless it has been disabled - see the [CSRF token](#readme-csrf-token) section below.<br><br>If set to `PUBLIC` it is strongly recommended that `ALLOWED_OPERATIONS` is set to `VIEW` (which is the default) so that write operations are not permitted.<br><br>If the `silverstripe/versioned` module is installed then the reading mode will be set to `Versioned::DRAFT` so that draft content is read and written. |
| `ALLOWED_OPERATIONS` | The operations that are allowed on the endpoint which can be any combination of:<ul><li>`VIEW` - Can view the data. Used for `GET` and `HEAD` HTTP requests.</li><li>`CREATE` - Can create new data using `POST` HTTP requests.</li><li>`EDIT` - Can update existing data using `PATCH` HTTP requests.</li><li>`DELETE` - Can delete existing data using `DELETE` HTTP requests.</li><li>`ACTION` - Can call actions e.g. the `/publish` action using `PUT` HTTP requests.</li></ul>Multiple operations can be joined together with `DELIMITER` which by default is `_` for instance `CREATE_EDIT_DELETE_ACTION`<br><br>Default is `VIEW`<br><br>Note that the `OPTIONS` HTTP request is always allowed |
| `CALL_CAN_METHODS` | The `can*()` methods that are called on every DataObject, i.e.<ul><li>`VIEW` - Call `canView()` when making a `GET` or `HEAD` request</li><li>`CREATE` - Call `canCreate()` when making a `POST` request</li><li>`EDIT` - Call `canEdit()` when making a `PATCH` request</li><li>`DELETE` - Call `canDelete()` when making a `DELETE` request</li><li>`ACTION` - Call relevant method when running an action e.g. `canPublish()` when calling the `/publish` action</li></ul>Join together with `DELIMITER` which by default is `_` for instance `EDIT_DELETE`<br><br>Default is `VIEW_CREATE_EDIT_DELETE_ACTION`<br><br>To only disable `canView()` to increase performance, set to `CREATE_EDIT_DELETE_ACTION` - note be careful doing this if the endpoint allows write operations that allow updating a `has_one` relation because that may be set to a relation record that would normally fail a `canView()` check for the user and the user can then view the updated relation JSON in the response body.<br><br>To disable all `can*()` checks set to `NONE` |
| `CACHE_MAX_AGE_VIEW` | The `max-age` set in the HTTP `Cache-control` header for `GET` requests<br><br>Valid values are positive ints.<br><br>Default is `0` which will will result as `no-cache` being used instead of `max-age` |
| `CACHE_MAX_AGE_OPTIONS` | The `max-age` set in the HTTP `Cache-control` header for the `OPTIONS` request<br><br>Valid values are positive ints.<br><br>Default is `604800` |
| `LIMIT_DEFAULT` | The default limit applied to ORM queries when a `limit` querystring parameter is not provided<br><br>Valid values are positive ints.<br><br>Default is `30`.<br><br>Note this has no effect on `has_many` relations which will always return all records as they cannot have querystring parameters set for them |
| `LIMIT_MAX` | The max limit that can be applied to ORM queries via the `limit` querystring<br><br>Valid values are positive ints.<br><br>Default is `100`.<br><br>Note this has no effect on `has_many` relations which will always return all records |
| `ALLOW_API_TOKEN` | Whether an API token can be used to authenticate with the API via the `x-api-token` HTTP header<br><br>Valid values are bools.<br><br>Default is `false` |
| `RELATION` | Include data from relations on data objects. This is detailed further below in its own section |
| `DATA_OBJECT_FIELD` | Special key used to define the DataObject field used when defining configuration on an individual field. This is detailed further below in its own section |

## Relations<a name="readme-relations"></a>

Your endpoint can contain data from relations on the dataobject, i.e. `has_one`, `has_many` or `many_many` relations. Configuration for relations follows the same rules and the top-level configuration.

For each if there is a `Team` class with a `db` field `Title` and a `has_many` relation `Players`, and the `Player` class has a `db` field `LastName`, you can use the following endpoint configuration to show all the of the `Players` on every `Team`.

Note that when including relations, as there is no ability to paginate the relation data ALL relations will be included in the response, instead of the default limit which is `30`.

```php
private static array $api_config = [
    RestApiEndpoint::PATH = 'api/teams';
    RestApiEndpoint::DATA_CLASS => Team::class,
    RestApiEndpoint::FIELDS => [
        // db fields
        'title' => 'Title',
        'yearFounded' => 'YearFounded',
        // has_one relation
        'city' => [
            RestApiEndpoint::RELATION => 'City',
                RestApiEndpoint::FIELDS => [
                    'name' => 'Name',
                ],
            ],
        ],
        // has_many relation
        'players' => [
            RestApiEndpoint::RELATION => 'Players',
            RestApiEndpoint::FIELDS => [
                'lastName' => 'LastName,
            ],
        ],
    ],
];
```

`has_one` Relations that are defined in the endpoint configuration can be set via `POST` or `PATCH` requests using a magic field `<jsonField>__ID`.

For the example above, to update the `CityID` from `14` to `15` on an existing `Team` DataObject with an `ID` of `77`:

`curl -X PATCH https://mysite.test/api/teams/77 -d '{"city__ID":"15"}'`

## Individual fields<a name="readme-individual-fields"></a>

The normal notation for including a field is `<jsonField>` => `<dataObjectField>`. You can configure individual fields to have their own `ACCESS` and `ALLOWED_OPERATIONS` if you wish to restrict those fields. When doing this the notation changes to an array notation where `DATA_OBJECT_FIELD` is what `<dataObjectField>` is with the regular notation.

For example, to set the `PrivateField` on the `Team` class to only be accessible to logged in members who pass a permission check on a custom `CAN_ACCESS_PRIVATE_FIELD` permission:

```php
private static array $api_config = [
    RestApiEndpoint::PATH = 'api/teams';
    RestApiEndpoint::DATA_CLASS => Team::class,
    RestApiEndpoint::FIELDS => [
        'title' => 'Title',
        'privateField' => [
            RestApiEndPoint::DATA_OBJECT_FIELD => 'PrivateField',
            RestApiEndpoint::ACCESS => 'CAN_ACCESS_PRIVATE_FIELD',
        ],
    ],
];
```

## CSRF token<a name="readme-csrf-token"></a>

If the endpoint `ACCESS` is set to anything except `PUBLIC` then an `x-csrf-token` header needs to be sent with the request, unless an `x-api-token` is sent instead. A valid token is generated by `SecurityToken::getSecurityID()`. Within the CMS it is available to javascript from `window.ss.config.SecurityID;`.

For instance the following javascript code will make a `GET` request that includes the `x-csrf-token` header when logged into Silverstripe CMS:

```js
fetch(
    '/api/pages',
    { headers: { 'x-csrf-token': window.ss.config.SecurityID } }
)
    .then(response => response.json())
    .then(responseJson => console.log(responseJson));
```

When working with non-public API endpoints you may wish to disable the csrf token check so that you can quickly test `GET` queries in your browsers location bar. You can do this by calling `SecurityToken::disable()` in `app/_config.php`, though if you do this be very careful this isn't then disabled in production too. To be safe, wrap this in a check to an environment variable of your choosing that you set in your local .env file, for example:

```php
use SilverStripe\Core\Environment;
use SilverStripe\Security\SecurityToken;

// ...

if (Environment::getEnv('DISABLE_API_CSRF_TOKEN_CHECK')) {
    SecurityToken::disable();
}
```

The `x-csrf-token` header is available as a constant on `RestApiEndpoint::CSRF_TOKEN_HEADER`.

## API token<a name="readme-api-token"></a>

Non-public API's can be configured to allow members to authenticate using an HTTP header instead of having to log in to the CMS.

If API authentication is used, the user will be logged in only for the duration of the request i.e. they will be logged out before the JSON response is returned.

This module provides a permission "Use an API token" which is `API_TOKEN_AUTHENTICATION` which must be assigned to a group that users using API tokens must belong to. The endpoints `ALLOW_API_ACCESS` config must be set to `true`.

When a user and endpoint is set up to allow using an API token, pass an `x-api-token` header with the value of the API Token to authenticate. Note that API token authentication will bypass MFA if it was set up for that user.

### Setting up an API user and group using the CMS

#### Creating the API user and group

1. Log in to the CMS as an administrator
1. Go to the Security section
1. Create a new group called "API Users"
1. Click on the Permissions tab (top right)
1. Tick "Use an API token" - this is the label for the permission code `API_TOKEN_AUTHENTICATION`
1. Save the Group
1. Click "Add Member"
1. Create a new user with a "First name" of "api-user", an Email of "api-user@example.com", and a long random password
1. Assign them to the "Api Users" group
1. Tick the "Generate new API token" checkbox and click "Save"
1. Copy the API token that is generated - you will only be shown this once

#### Additional group permissions

The "api-user" still needs to pass all necessary permissions checks for the API to work i.e. so that `canView()` checks still pass. You can either:
- Update the "API Users" group to have the necessary permissions, or
- Set the endpoints `CHECK_CAN_METHODS` to `NONE` though you *MUST* ensure that the API `ACCESS` is set to a permission code that is only assigned to dedicated api users.

### Programmatically updating a users API token

Programmatically update a users API token with `$member->refreshApiToken();` followed by `$member->write();`. The returned value is the unencrypted API token. The members `ApiToken` field will be the encrypted API token.

Note that for newly created users, `$member->write()` must be called at least once before calling `$member->refreshApiToken();` to ensure that the API token is properly encrypted.

## Extension hooks<a name="readme-extension-hooks"></a>

You may need to add custom logic to your API which can do with using the following extension hooks available in the table below. Implement a hook by adding one of these methods directly to your subclass of `RestApiEndpoint` using the `protected` visibility. You can also implement them on extension classes with a `public` visibility.

For example the following implementation of the `onEditBeforeWrite()` hook will update the `Content` field of a DataObject updated via a `PATCH` request before saving, even though the `Content` field is not exposed in the API.

Note to run this code example you need to be logged in to the CMS to use and pass an `x-csrf-token` header when making requests.

**src/MySiteTreeEndpoint.php**

```php
<?php

use emteknetnz\RestApi\Controllers\RestApiEndpoint;
use SilverStripe\CMS\Model\SiteTree;
use SilverStripe\ORM\DataObject;

class MySiteTreeEndpoint extends RestApiEndpoint
{
    private static array $api_config = [
        RestApiEndpoint::PATH => 'api/pages',
        RestApiEndpoint::DATA_CLASS => SiteTree::class,
        RestApiEndpoint::ACCESS => RestApiEndpoint::LOGGED_IN,
        RestApiEndpoint::ALLOWED_OPERATIONS => RestApiEndpoint::VIEW_CREATE_EDIT_DELETE_ACTION,
        RestApiEndpoint::FIELDS => [
            'title' => 'Title',
        ],
    ];

    protected function onEditBeforeWrite(SiteTree $page)
    {
        // You wouldn't normally do this, this is only for demo purposes
        $page->Content .= '<p>This was updated using the API</p>';
    }
}
```

Notes:

- If your extension hook updates the DataObject or another DataObject then it is likely you should use a different extension hook such as `onAfterWrite()` on the Dataobject itself rather than on the endpoint. This is because it usually shouldn't matter whether the object was created/updated/deleted via the API or a different way. These hooks are intended to facilitate the implementation of API specific code such as logging operations done via the API.
- For the `onView*()` hooks if you are adding extra data to the JSON for the response, remember to call `canView()` for any DataObjects being added as required.
- For both of the `onEdit*Write()` hooks the `$changedFields` param is return value of `$obj->getChangedFields()` before the object was written to.

| Extension hook | Description |
| - | - |
| `onBeforeApi()` | Called during all requests before any processing |
| `onAfterApi()` | Called during all requests after any processing |
| `onViewOne(DataObject $obj)` | Called during `GET` requests to view a single record before rendering JSON for response |
| `onViewMany(array $objs)` | Called during `GET` requests to view many records before rendering JSON for response |
| `onCreateBeforeWrite(DataObject $obj)` | Called during `POST` requests before calling `$obj->write()` |
| `onCreateAfterWrite(DataObject $obj)` | Called during `POST` requests after calling `$obj->write()` |
| `onEditBeforeWrite(DataObject $obj, array $changedFields)` | Called during `PATCH` requests before calling `$obj->write()` |
| `onEditAfterWrite(DataObject $obj, array $changedFields)` | Called during `PATCH` requests after calling `$obj->write()` |
| `onDeleteBeforeDelete(DataObject $obj)` | Called during `DELETE` requests before calling `$obj->write()` |
| `onDeleteAfterDelete(DataObject $obj)` | Called during `DELETE` requests after calling `$obj->write()` |
| `onBeforeAction(DataObject $obj, string $action)` | Called during `ACTION` requests before running the action |
| `onAfterAction(DataObject $obj, string $action)` | Called during `ACTION` requests after running the action |
| `onBeforeSendResponse(HTTPResponse $response)` | Called during all requests before sending HTTP response |
| `updateApiConfig(array &$apiConfig)` | Called during all requests before any processing. Allows late updates to `private static array $api_config`. Note that modifying the `RestApiEndpoint::PATH` key will have no effect at this stage |
