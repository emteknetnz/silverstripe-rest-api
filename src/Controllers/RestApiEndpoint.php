<?php

namespace emteknetnz\RestApi\Controllers;

use emteknetnz\RestApi\Exceptions\RestApiEndpointException;
use SilverStripe\Control\Controller;
use SilverStripe\Control\HTTPResponse;
use Exception;
use SilverStripe\ORM\DataObject;
use SilverStripe\Control\Middleware\HTTPCacheControlMiddleware;
use SilverStripe\Security\Security;
use SilverStripe\ORM\DataList;
use SilverStripe\Control\Director;
use SilverStripe\Security\Permission;
use stdClass;
use emteknetnz\RestApi\Exceptions\RestApiEndpointConfigException;
use SilverStripe\ORM\DataObjectSchema;
use SilverStripe\ORM\ValidationException;
use SilverStripe\Security\SecurityToken;
use SilverStripe\Versioned\Versioned;

abstract class RestApiEndpoint extends Controller
{
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
    // other constants
    public const CSRF_TOKEN_HEADER = 'x-csrf-token';

    private static array $url_handlers = [
        '$@' => 'api',
    ];

    private static array $allowed_actions = [
        'api'
    ];

    private static array $api_config = [];

    /**
     * Main entry point for all Rest API's
     */
    public function api(): HTTPResponse
    {
        try {
            $this->invokeWithExtensions('onBeforeApi');
            // Allow extensions or subclasses to update $api_config
            $apiConfig = $this->config()->get('api_config');
            $this->invokeWithExtensions('updateApiConfig', $apiConfig);
            $this->config()->set('api_config', $apiConfig);
            // Check access
            if (!$this->canAccess()) {
                $code = Security::getCurrentUser() ? 403 : 401;
                throw new RestApiEndpointException('', $code);
            }
            // If the endpoint is non-public i.e. an admin only endpoint, set it to read and write draft content
            // Not doing this will result is strange behaviour e.g. calling DataObject::write() will update
            // both the draft and live tables
            if (class_exists(Versioned::class)) {
                $access = $this->endpointConfig(self::ACCESS, true);
                if ($access !== self::PUBLIC) {
                    Versioned::set_stage(Versioned::DRAFT);
                }
            }
            $requestHttpMethod = $this->requestHttpMethod();
            $this->checkHttpRequestMethodAllowed($requestHttpMethod);
            $this->configureHttpCache($requestHttpMethod);
            switch ($requestHttpMethod) {
                case 'OPTIONS':
                    return $this->apiOptions();
                case 'GET':
                    return $this->apiView();
                case 'HEAD';
                    return $this->apiHead();
                case 'PATCH':
                    return $this->apiEdit();
                case 'POST':
                    return $this->apiCreate();
                case 'DELETE':
                    return $this->apiDelete();
                case 'PUT':
                    return $this->apiAction();
            }
        } catch (RestApiEndpointException $e) {
            return $this->error($e->getMessage(), $e->getCode());
        } catch (Exception $e) {
            // 500 Internal Server Error - don't wrap it in JSON.
            // In dev mode this gives feedback to the developer
            // In prod mode it doesn't give any feedback though it will show in error logs
            throw $e;
        } finally {
            $this->invokeWithExtensions('onAfterApi');
        }
    }

    /**
     * Get a value for a key from the endpoint config
     */
    private function endpointConfig(string $key, bool $uppercase)
    {
        $value = $this->config()->get('api_config')[$key] ?? null;
        if ($value === null) {
            // default values
            switch($key) {
                case self::ACCESS:
                    $value = self::LOGGED_IN;
                    break;
                case self::ALLOWED_OPERATIONS:
                    $value = self::VIEW;
                    break;
                case self::CALL_CAN_METHODS:
                    $value = self::VIEW_CREATE_EDIT_DELETE_ACTION;
                    break;
                case self::CACHE_MAX_AGE_VIEW:
                    $value = 0;
                    break;
                case self::CACHE_MAX_AGE_OPTIONS:
                    // one week
                    $value = 604800;
                    break;
                case self::LIMIT_DEFAULT:
                    $value = 30;
                    break;
                case self::LIMIT_MAX:
                    $value = 100;
                    break;
            }
        }
        if (is_string($value) && $uppercase) {
            return strtoupper($value);
        }
        return $value;
    }

    /**
     * Check if the user is authenticated (a.k.a logged in) which is required to view a private API
     * 
     * If ACCESS is not PUBLIC then the x-csrf-token must be present and match
     * 
     * Will throw a 400 error if missing x-csrf-token header or failed csrf token check
     * 
     * The following status error codes may need to be raised if false is returned
     * 401 logged-out when need to be logged-in
     * 403 logged-in but not enough permissions - this is done later with canView() style permissions
     */
    private function canAccess(string $subSchemaAccess = ''): bool
    {
        $access = $subSchemaAccess ?: $this->endpointConfig(self::ACCESS, true);
        if ($access === self::PUBLIC) {
            return true;
        }
        // ACCESS = LOGGED_IN or PERMISSION_CODE 
        $member = Security::getCurrentUser();
        if (is_null($member)) {
            return false;
        }
        // Permission check for PERMISSION_CODE
        if ($access !== self::LOGGED_IN && !Permission::checkMember($member, $access)) {
            return false;
        }
        // CSRF-Token check only on non-subSchemaAccess aka root level
        if (SecurityToken::is_enabled() && $subSchemaAccess === '') {
            $token = $this->getRequest()->getHeader(self::CSRF_TOKEN_HEADER);
            if (!$token) {
                throw new RestApiEndpointException('Missing x-csrf-token header', 400);
            }
            if (!SecurityToken::inst()->check($token)) {
                throw new RestApiEndpointException('Invalid csrf token', 400);
            }
        }
        return true;
    }

    /**
     * Check if an HTTP request method is allowed
     */
    private function checkHttpRequestMethodAllowed(string $requestHttpMethod): void
    {
        if ($requestHttpMethod === 'OPTIONS') {
            return;
        }
        $id = $this->requestIdParam();
        if (!$id) {
            if (in_array($requestHttpMethod, ['PATCH', 'DELETE', 'PUT'])) {
                throw new RestApiEndpointException('', 405);
            }
        } else {
            if (in_array($requestHttpMethod, ['POST'])) {
                throw new RestApiEndpointException('', 405);
            }
        }
        $allowedOperations = $this->endpointConfig(self::ALLOWED_OPERATIONS, true);
        $operations = explode(self::DELIMITER, $allowedOperations);
        foreach ($operations as $operation) {
            switch ($requestHttpMethod) {
                case 'GET':
                case 'HEAD':
                    if ($operation === self::VIEW) {
                        return;
                    }
                    break;
                case 'PATCH':
                    if ($operation === self::EDIT) {
                        return;
                    }
                    break;
                case 'POST':
                    if ($operation === self::CREATE) {
                        return;
                    }
                    break;
                case 'DELETE':
                    if ($operation === self::DELETE) {
                        return;
                    }
                    break;
                case 'PUT':
                    if ($operation === self::ACTION) {
                        return;
                    }
                    break;
            }
        }
        throw new RestApiEndpointException('', 405);
    }

    /**
     * Get the HTTP request method
     */
    private function requestHttpMethod(): string
    {
        $request = $this->getRequest();
        $requestHttpMethod = strtoupper($request->httpMethod());
        if (!in_array($requestHttpMethod, ['OPTIONS', 'GET', 'HEAD', 'PATCH', 'POST', 'DELETE', 'PUT'])) {
            return '';
        }
        return $requestHttpMethod;
    }

    /**
     * OPTIONS request
     * https://developer.mozilla.org/en-US/docs/Web/HTTP/Methods/OPTIONS
     */
    private function apiOptions(): HTTPResponse
    {
        $response = $this->getResponse();
        $response->setStatusCode(204);
        $response->addHeader('Allow', $this->allowedOptions());
        $response->setBody('');
        return $response;
    }

    private function allowedOptions(): string
    {
        $allowedOptions = ['OPTIONS'];
        $allowedOperations = $this->endpointConfig(self::ALLOWED_OPERATIONS, true);
        $operations = explode(self::DELIMITER, $allowedOperations);
        foreach ($operations as $operation) {
            switch ($operation) {
                case self::VIEW:
                    $allowedOptions[] = 'GET';
                    $allowedOptions[] = 'HEAD';
                    break;
                case self::EDIT:
                    $allowedOptions[] = 'PATCH';
                    break;
                case self::CREATE:
                    $allowedOptions[] = 'POST';
                    break;
                case self::DELETE:
                    $allowedOptions[] = 'DELETE';
                    break;
                case self::ACTION:
                    $allowedOptions[] = 'PUT';
                    break;
            }
        }
        return implode(', ', $allowedOptions);
    }

    /**
     * View one or many values from the API - used for GET requests
     */
    private function apiView(): HTTPResponse
    {
        $request = $this->getRequest();
        if ($this->requestIdParam()) {
            return $this->apiViewOne($request);
        }
        return $this->apiViewMany($request);
    }

    /**
     * View one value from the API - used for GET requests
     */
    private function apiViewOne(): HTTPResponse
    {
        $obj = $this->dataObjectFromRequest();
        if (!$obj) {
            throw new RestApiEndpointException('', 404);
        }
        $this->invokeWithExtensions('onViewOne', $obj);
        $callCanMethods = $this->endpointConfig(self::CALL_CAN_METHODS, true);
        if ($this->configContains($callCanMethods, self::VIEW)) {
            $member = Security::getCurrentUser();
            if (!$obj->canView($member)) {
                throw new RestApiEndpointException('', 403);
            }
        }
        $json = $this->jsonData($obj);
        return $this->jsonResponse($json);
    }

    /**
     * View many values from the API - used for GET requests
     * unlike apiViewOne this will not return a 403 when it fails a canView check
     * instead it simply won't include dataobjects that fail canView() in the response
     */
    private function apiViewMany(): HTTPResponse
    {
        $member = null;
        $callCanMethods = $this->endpointConfig(self::CALL_CAN_METHODS, true);
        if ($this->configContains($callCanMethods, self::VIEW)) {
            $member = Security::getCurrentUser();
        }
        $json = [];
        /** @var DataList $objs */
        $dataClass = $this->endpointConfig(self::DATA_CLASS, false);
        $objs = $dataClass::get();
        $filter = $this->filterFromRequest();
        if ($filter) {
            $objs = $objs->filter($this->filterFromRequest());
        }
        $sort = $this->sortFromRequest();
        if ($sort) {
            $objs = $objs->sort($this->sortFromRequest());
        }
        $objs = $objs->limit($this->limitFromRequest(), $this->offsetFromRequest());
        $this->invokeWithExtensions('onViewMany', $objs);
        foreach ($objs as $obj) {
            if ($this->configContains($callCanMethods, self::VIEW)) {
                if (!$obj->canView($member)) {
                    continue;
                }
            }
            $json[] = $this->jsonData($obj);
        }
        return $this->jsonResponse($json);
    }

    /**
     * Allows filtering of apiViewMany() requests using standard ORM filtering
     * /api/<endpoint>?filter[<jsonKey>:<SearchFilter>]=<value>
     * e.g. /api/teams?filter[name:StartsWith]=Ste
     * Is whitelisted against fields in $this->config()->get('end')
     */
    private function filterFromRequest(): array
    {
        $request = $this->getRequest();
        $fields = $this->endpointConfig(self::FIELDS, false);
        $filter = [];
        foreach ($request->getVar('filter') ?? [] as $jsonKey => $value) {
            $searchFilter = '';
            $arr = explode(':', $jsonKey);
            $jsonKey = $arr[0];
            // support for has_one __ID relations
            $isIDField = false;
            $rx = '/__ID$/';
            if (preg_match($rx, $jsonKey)) {
                $isIDField = true;
                $jsonKey = preg_replace($rx, '', $jsonKey);
            }
            $searchFilter = $arr[1] ?? '';
            $modifier = $arr[2] ?? '';
            if (!array_key_exists($jsonKey, $fields)) {
                throw new RestApiEndpointException("Field $jsonKey does not exist", 400);
            }
            if ($this->jsonKeyIsDataObjectMethod($jsonKey)) {
                throw new RestApiEndpointException("Cannot filter on field $jsonKey", 400);
            }
            $dataObjectKey = $fields[$jsonKey];
            $key = $dataObjectKey;
            if ($isIDField) {
                $key = $dataObjectKey[RestApiEndpoint::RELATION] . 'ID';
            }
            if ($searchFilter) {
                $key .= ":$searchFilter";
            }
            if ($modifier) {
                $key .= ":$modifier";
            }
            $filter[$key] = $value;
        }
        return $filter;
    }

    /**
     * Allows sorting of apiViewMany() requests using standard ORM sorting
     * Prefix key with `-` to sort DESC
     * /api/<endpoint>?sort=<keyOne>,<keyTwo>
     * e.g. /api/teams?sort=title,-id
     * Only allowed to sort fields included in $api_config
     */
    private function sortFromRequest(): array
    {
        $fields = $this->endpointConfig(self::FIELDS, false);
        $sort = [];
        $jsonKeys = array_filter(explode(',', $this->getRequest()->getVar('sort') ?? ''));
        if (empty($jsonKeys)) {
            return $sort;
        }
        foreach ($jsonKeys as $jsonKey) {
            $sortDirection = 'ASC';
            if (substr($jsonKey, 0, 1) === '-') {
                $sortDirection = 'DESC';
                $jsonKey = substr($jsonKey, 1);
            }
            if (!array_key_exists($jsonKey, $fields)) {
                throw new RestApiEndpointException("Field $jsonKey does not exist", 400);
            }
            if ($this->jsonKeyIsDataObjectMethod($jsonKey)) {
                throw new RestApiEndpointException("Cannot sort on field $jsonKey", 400);
            }
            $dataObjectKey = $fields[$jsonKey];
            $sort[$dataObjectKey] = "$sortDirection";
        }
        return $sort;
    }

    /**
     * Extract limit=<int> from querystring
     */
    private function limitFromRequest(): ?int
    {
        $limit = $this->getRequest()->getVar('limit') ?? $this->endpointConfig(self::LIMIT_DEFAULT, false);
        if (!ctype_digit((string) $limit) || $limit != (int) $limit || $limit < 1) {
            throw new RestApiEndpointException('Limit must be a positive integer', 400);
        }
        $limitMax = $this->endpointConfig(self::LIMIT_MAX, false);
        if ($limit > $limitMax) {
            $limit = $limitMax;
        }
        return $limit;
    }

    /**
     * Extract offset=<int> from querystring
     */
    private function offsetFromRequest(): int
    {
        $offset = $this->getRequest()->getVar('offset') ?: 0;
        if (!ctype_digit((string) $offset) || $offset != (int) $offset || $offset < 0) {
            throw new RestApiEndpointException('Offset must be a positive integer or zero', 400);
        }
        return (int) $offset;
    }

    /**
     * This is a simple implementation of HEAD that simply takes the result GET request
     * and then sets the body to empty and sets the status code to 204 (No content)
     * This ensures that the Content-length and eTag headers are correctly calculated
     * Note the Content-length header may be removed later on by the webserver e.g. Apache
     */
    private function apiHead(): HTTPResponse
    {
        $response = $this->apiView();
        $response->setStatusCode(204);
        $response->setBody('');
        return $response;
    }

    /**
     * Create new records via the API - used by POST requests
     *
     * Only used for creating new objects, data is never passed in
     */
    private function apiCreate(): HTTPResponse
    {
        $dataClass = $this->endpointConfig(self::DATA_CLASS, false);
        // check can methods
        $callCanMethods = $this->endpointConfig(self::CALL_CAN_METHODS, true);
        if ($this->configContains($callCanMethods, self::CREATE)) {
            $member = Security::getCurrentUser();
            if (!$dataClass::singleton()->canCreate($member)) {
                throw new RestApiEndpointException('', 403);
            }
        }
        // decode body json data
        $body = $this->getRequest()->getBody();
        if ($body) {
            $data = json_decode($this->getRequest()->getBody(), true);
            if (is_null($data)) {
                throw new RestApiEndpointException('Cannot parse JSON', 400);
            }
        }
        // create new dataObject and update it with data
        $obj = $dataClass::create();
        $this->updateDataObjectWithData($obj, $data, self::CREATE);
        $this->invokeWithExtensions('onCreateBeforeWrite', $obj);
        try {
            $obj->write();
        } catch (ValidationException $e) {
            return $this->error($e->getMessage(), 422);
        }
        $this->invokeWithExtensions('onCreateAfterWrite', $obj);
        // Return 201 status code + Location header + json body
        // https://developer.mozilla.org/en-US/docs/Web/HTTP/Status/201
        $location = Controller::join_links(
            Director::absoluteBaseUrl(),
            $this->getRequest()->getURL() . '/' . $obj->ID
        );
        return $this->success($this->jsonData($obj), 201, ['Location' => $location]);
    }

    /**
     * Edit values via the API - used by PATCH requests
     */
    private function apiEdit(): HTTPResponse
    {
        $dataClass = $this->endpointConfig(self::DATA_CLASS, false);
        // check can methods
        $callCanMethods = $this->endpointConfig(self::CALL_CAN_METHODS, true);
        if ($this->configContains($callCanMethods, self::EDIT)) {
            $member = Security::getCurrentUser();
            if (!$dataClass::singleton()->canEdit($member)) {
                throw new RestApiEndpointException('', 403);
            }
        }
        // decode body json data
        $body = $this->getRequest()->getBody();
        if (!$body) {
            throw new RestApiEndpointException('No request body', 400);
        }
        $data = json_decode($body, true);
        if (is_null($data) || empty($data)) {
            throw new RestApiEndpointException('Cannot parse JSON', 400);
        }
        // update dataObject
        $obj = $this->dataObjectFromRequest($dataClass);
        $this->updateDataObjectWithData($obj, $data, self::EDIT);
        $changedFields = $obj->getChangedFields();
        $this->invokeWithExtensions('onEditBeforeWrite', $obj, $changedFields);
        try {
            $obj->write();
        } catch (ValidationException $e) {
            return $this->error($e->getMessage(), 422);
        }
        $this->invokeWithExtensions('onEditAfterWrite', $obj, $changedFields);
        return $this->success($this->jsonData($obj), 200);
    }

    /**
     * Delete records via the API - used by DELETE requests
     */
    private function apiDelete(): HTTPResponse
    {
        $dataClass = $this->endpointConfig(self::DATA_CLASS, false);
        $callCanMethods = $this->endpointConfig(self::CALL_CAN_METHODS, true);
        if ($this->configContains($callCanMethods, self::DELETE)) {
            $member = Security::getCurrentUser();
            if (!$dataClass::singleton()->canDelete($member)) {
                throw new RestApiEndpointException('', 403);
            }
        }
        $obj = $this->dataObjectFromRequest($dataClass);
        $this->invokeWithExtensions('onDeleteBeforeDelete', $obj);
        if ($obj->hasExtension(Versioned::class)) {
            $obj->doArchive();
        } else {
            $obj->delete();
        }
        $this->invokeWithExtensions('onDeleteAfterDelete', $obj);
        // Will default to a 200 status code
        // A 204 status code is not used because there is stil JSON content returned in the body
        return $this->success(null);
    }

    /**
     * Perform a range of actions via the API - used by PUT requests
     */
    private function apiAction(): HTTPResponse
    {
        $action = $this->requestActionParam();
        if (!$action) {
            throw new RestApiEndpointException('No action specified', 400);
        }
        $dataClass = $this->endpointConfig(self::DATA_CLASS, false);
        $obj = $this->dataObjectFromRequest($dataClass);
        $this->invokeWithExtensions('onBeforeAction', $obj, $action);
        if (in_array($action, ['publish', 'unpublish', 'archive'])) {
            $response = $this->apiVersioning($obj, $action);
        } else {
            throw new RestApiEndpointException('Invalid action', 400);
        }
        $this->invokeWithExtensions('onAfterAction', $obj, $action);
        return $response;
    }

    /**
     * Run versioning actions e.g. publish, unpublish, archive
     */
    private function apiVersioning(DataObject $obj, string $action): HTTPResponse
    {
        $callCanMethods = $this->endpointConfig(self::CALL_CAN_METHODS, true);
        $doCheck = $this->configContains($callCanMethods, self::ACTION);
        if (!$obj->hasExtension(Versioned::class)) {
            $message = !Director::isDev() ? '' : get_class($obj) . ' does not support Versioning';
            throw new RestApiEndpointException($message, 404);
        }
        if ($action === 'publish') {
            if ($doCheck && !$obj->canPublish()) {
                throw new RestApiEndpointException('', 403);
            }
            $obj->publishRecursive();
        } elseif ($action === 'unpublish') {
            if ($doCheck && !$obj->canUnpublish()) {
                throw new RestApiEndpointException('', 403);
            }
            $obj->doUnpublish();
        } elseif ($action === 'archive') {
            if ($doCheck && !$obj->canArchive()) {
                throw new RestApiEndpointException('', 403);
            }
            $obj->doArchive();
        } else {
            throw new RestApiEndpointException('Invalid action', 400);
        }
        // Will default to a 200 status code
        // A 204 status code is not used because there is stil JSON content returned in the body
        return $this->success(null);
    }

    private function requestIdParam(): int
    {
        // use $1 rather than $ID to make project configuration slightly more robust i.e they don't need to
        // exactly have 'api//$Action/$ID' in their yml file, instead simply 'api' is fine
        return (int) $this->getRequest()->param('$1');
    }

    private function requestActionParam(): string
    {
        // use $2 rather than $ID to make project configuration slightly more robust i.e they don't need to
        // exactly have 'api//$Action/$ID'
        return (string) $this->getRequest()->param('$2');
    }

    /**
     * Update the DataObject
     */
    private function updateDataObjectWithData(DataObject $obj, array $data, string $operation)
    {
        $fields = $this->endpointConfig(self::FIELDS, false);
        // allow setting relation field ID via special *__ID field
        foreach ($fields as $jsonKey => $dataObjectKey) {
            if (isset($dataObjectKey[RestApiEndpoint::RELATION])) {
                $fields["{$jsonKey}__ID"] = $dataObjectKey[RestApiEndpoint::RELATION] . 'ID';
            }
        }
        $dataClass = get_class($obj);
        $fieldSpecs = $obj->getSchema()->fieldSpecs($dataClass);
        $primaryKeys = array_filter($fieldSpecs, fn($v) => $v === 'PrimaryKey');
        foreach ($data as $jsonKey => $value) {
            // non-existant field
            if (!array_key_exists($jsonKey, $fields)) {
                throw new RestApiEndpointException("Field $jsonKey does not exist", 400);
            }
            $dataObjectKey = $fields[$jsonKey];
            if (is_array($dataObjectKey)) {
                // unsettable field
                if (!array_key_exists(self::DATA_OBJECT_FIELD, $dataObjectKey)) {
                    throw new RestApiEndpointException("Field $jsonKey does not exist", 400);
                }
                // operation not allowed on field
                if (array_key_exists(self::ALLOWED_OPERATIONS, $fields[$jsonKey])) {
                    $allowedOperations = strtoupper($fields[$jsonKey][self::ALLOWED_OPERATIONS]);
                    if (!$this->configContains($allowedOperations, $operation)) {
                        // note using 400 rather than 405 because 405 is if the entire endpoint
                        // cannot have operation run on it, whereas this is just a single field
                        // which is a pretty niche use case so using the generic 400 code
                        throw new RestApiEndpointException("Field $jsonKey cannot be set in this request", 400);
                    }
                }
                // access not allowed on field
                if (array_key_exists(self::ACCESS, $fields[$jsonKey])) {
                    $access = strtoupper($fields[$jsonKey][self::ACCESS]);
                    if (!$this->canAccess($access)) {
                        $code = Security::getCurrentUser() ? 403 : 401;
                        throw new RestApiEndpointException("Do not have permission to set field $jsonKey", $code);
                    }
                }
                $dataObjectKey = $fields[$jsonKey][self::DATA_OBJECT_FIELD];
            }
            // un-settable field
            if (!is_string($dataObjectKey)
                || array_key_exists($dataObjectKey, $primaryKeys)
                || $this->jsonKeyIsDataObjectMethod($jsonKey)
            ) {
                throw new RestApiEndpointException("Field $jsonKey cannot be set", 400);
            }
            $obj->$dataObjectKey = $value;
        }
    }

    /**
     * Convert a DataObject to json for the API response
     */
    private function jsonData(DataObject $obj): array
    {
        $ret = [];
        $this->recursiveJsonData(
            $ret,
            $this->config()->get('api_config'),
            $obj,
        );
        $this->deleteStdClassesFromJsonData($ret);
        return $ret;
    }

    private function recursiveJsonData(&$ret, array $schema, DataObject $obj): void
    {
        $showValue = true;
        // access check
        if (array_key_exists(self::ACCESS, $schema)) {
            $access = strtoupper($schema[self::ACCESS]);
            if (!$this->canAccess($access)) {
                $showValue = false;
            }
        }
        // allowed operations check - view only
        if ($showValue && array_key_exists(self::ALLOWED_OPERATIONS, $schema)) {
            $allowedOperations = strtoupper($schema[self::ALLOWED_OPERATIONS]);
            if (!$this->configContains($allowedOperations, self::VIEW)) {
                $showValue = false;
            }
        }
        // check can methods - view only
        if ($showValue && array_key_exists(self::CALL_CAN_METHODS, $schema)) {
            $callCanMethods = strtoupper($schema[self::CALL_CAN_METHODS]);
            if (array_key_exists(self::DATA_OBJECT_FIELD, $schema)) {
                throw new RestApiEndpointConfigException('Cannot set CALL_CAN_METHODS on an individual field');
            }
            if ($this->configContains($callCanMethods, self::VIEW)) {
                $member = Security::getCurrentUser();
                if (!$obj->canView($member)) {
                    $showValue = false;
                }
            }
        }
        if (!$showValue) {
            // setting $ret to a stdClass so that it's easy to delete later
            $ret = new stdClass();
            return;
        }
        if (array_key_exists(self::DATA_OBJECT_FIELD, $schema)) {
            $dataObjectKey = $schema[self::DATA_OBJECT_FIELD];
            $ret = $this->dataObjectValue($obj, $dataObjectKey);
            return;
        }
        $relationObj = null;
        $relationList = null;
        if (array_key_exists(self::RELATION, $schema)) {
            $relation = $obj->{$schema[self::RELATION]}();
            if ($relation instanceof DataObject) {
                // has_one relation
                $relationObj = $relation;
                if ($relationObj->ID === 0) {
                    $ret = null;
                    return;
                }
            } else {
                // has_many / many_many relation
                $relationList = $relation;
            }
        }
        if (array_key_exists(self::FIELDS, $schema)) {
            if (!$relationList) {
                // Single object
                $paramObjOrRelationObj = $relationObj ?: $obj;
                $this->loopFields($ret, $schema, $paramObjOrRelationObj);
            } else {
                // RelationList
                foreach ($relationList as $objToUpdate) {
                    $values = [];
                    $this->loopFields($values, $schema, $objToUpdate);
                    $ret[] = $values;
                }
            }
        }
    }

    /**
     * Inner method used by recursiveJsonData()
     */
    private function loopFields(array &$ret, array $schema, DataObject $obj): void
    {
        foreach ($schema[self::FIELDS] as $jsonKey => $dataObjectKeyOrSubSchema) {
            if (!is_array($dataObjectKeyOrSubSchema)) {
                // regular field with no types of checks e.g. callCanMethods, access, allowedOperations
                $dataObjectKey = $dataObjectKeyOrSubSchema;
                $ret[$jsonKey] = $this->dataObjectValue($obj, $dataObjectKey);
            } else {
                // array field, either
                // - a regular field with RestApiEndpoint::DATA_OBJECT_FIELD, or
                // - a relation field with RestApiEndpoint::RELATION
                $subSchema = $dataObjectKeyOrSubSchema;
                $subRet = [];
                $this->recursiveJsonData($subRet, $subSchema, $obj);
                $ret[$jsonKey] = $subRet;
            }
        }
    }

    /**
     * Delete key/value where any value is a stdClass object with a delete property
     */
    private function deleteStdClassesFromJsonData(&$ret)
    {
        // This isn't a great way to do this, though it works
        // Reason for it is the ACCESS/ALLOWED_OPERATIONS/CALL_CAN_METHODS are done "one level deeper"
        // that the bit where the keys and values are set, there's an assumption that a key and value should
        // be set. What ideally would happen is if a check fails they a key should not have been set at all
        if (!is_array($ret)) {
            $ret = [$ret];
        }
        foreach ($ret as $key => $val) {
            if (is_array($val)) {
                $this->deleteStdClassesFromJsonData($ret[$key]);
            }
            if (is_a($val, 'stdClass')) {
                unset($ret[$key]);
            }
        }
    }

    private function dataObjectValue($obj, $key)
    {
        if (method_exists($obj, $key)) {
            return $obj->$key();
        }
        $fieldSpecs = DataObjectSchema::singleton()->fieldSpecs($obj->ClassName);
        $fieldType = $fieldSpecs[$key];
        $pos = strpos($fieldType, '(');
        if ($pos !== false) {
            $fieldType = substr($fieldType, 0, $pos);
        }
        // cast values to scalar type to handle any null values
        // also ensures that Boolean is not output as `1` or `0`
        // this is also just a handy reference for how different datatypes are represented in json
        $value = $obj->$key;
        if ($fieldType === 'Money') {
            $fieldType = 'Varchar';
            $value = $value->getValue();
        }
        switch ($fieldType) {
            case 'Boolean':
                return (bool) $value;
            case 'BigInt':
            case 'Int':
            case 'Year':
                return (int) $value;
            case 'Currency':
            case 'Decimal':
            case 'Double':
            case 'Float':
            case 'Percentage':
                return (float) $value;
            case 'Datetime':
            case 'Enum':
            case 'HTMLFragment':
            case 'HTMLVarchar':
            case 'HTMLText':
            case 'Locale':
            case 'MyMutliEnum':
            case 'Text':
            case 'Time':
            case 'Varchar':
                return (string) $value;
        }
        // Any custom fields
        $this->extend('updateDataObjectValue', $value, $key, $obj);
        return $value;
    }

    /**
     * Get a DataObject from the request
     */
    private function dataObjectFromRequest(): DataObject
    {
        $dataClass = $this->endpointConfig(self::DATA_CLASS, false);
        $id = $this->requestIdParam();
        $obj = $dataClass::get()->byID($id);
        if (is_null($obj)) {
            throw new RestApiEndpointException('', 404);
        }
        return $obj;
    }

    /**
     * Set a successful HTTP response
     */
    private function success(?array $data = [], int $code = 200, array $headers = []): HTTPResponse
    {
        $arr = [
            'success' => true
        ];
        if (!is_null($data)) {
            $arr['data'] = $data;
        }
        return $this->jsonResponse($arr, $code, $headers);
    }

    /**
     * Set an HTTP error response
     * 
     * @param string|int $messageOrCode
     */
    private function error(string $message, int $code, array $headers = []): HTTPResponse
    {
        $this->disableHttpCache();
        if ($message === '') {
            switch ($code) {
                case 400:
                    $message = 'Bad request';
                    break;
                case 401:
                    $message = 'Unauthorised';
                    break;
                case 403:
                    $message = 'Forbidden';
                    break;
                case 404:
                    $message = 'Not found';
                    break;
                case 405:
                    $message = 'HTTP request method not allowed';
                    break;
                case 422:
                    $message = 'Unprocessable entity';
                    break;
                default:
                    $message = 'Error';
            }
        }
        return $this->jsonResponse([
            'success' => false,
            'message' => $message
        ], $code, $headers);
    }

    /**
     * Set an HTTP response with array $data converted to json
     */
    private function jsonResponse(array $data, int $code = 200, array $headers = []): HTTPResponse
    {
        $response = $this->getResponse();
        $body = json_encode(
            $data,
            // Use JSON_UNESCAPED_UNICODE so that unicode characters are not escaped
            // e.g. "ō" renders as "ō", not "\u014d"
            JSON_UNESCAPED_SLASHES + JSON_UNESCAPED_UNICODE
            // not using JSON_PRETTY_PRINT to save on bandwidth
        );
        $httpRequestMethod = $this->requestHttpMethod();
        if (in_array($httpRequestMethod, ['GET', 'HEAD'])) {
            // etag implementation is the same as ChangeDetectionMiddleware::generateETag()
            // Surronding with double quotes is required by RFC 7232
            // https://www.rfc-editor.org/rfc/rfc7232#section-2.3
            $etag = $response->getHeader('ETag');
            if (!$etag) {
                $etag = sprintf('"%s"', md5($body));
                $response->addHeader('ETag', $etag);
            }
        }
        // "The Content-Length header indicates the size of the message body, in bytes, sent to the recipient."
        // https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Length
        // Using strlen() rather than mb_strlen() because mb_strlen() will count a multi-byte character as
        // one unit, whereas we want the total number of bytes which strlen() provides.
        $contentLength = strlen($body);
        $response
            ->addHeader('Content-type', 'application/json')
            // explicitly setting Content-length rather than relying on the webserver
            // note the webserver e.g. Apache may ignore this header and set it itself
            ->addHeader('Content-length', $contentLength)
            ->setStatusCode($code)
            ->setBody($body);
        foreach ($headers as $name => $value) {
            $response->addHeader($name, $value);
        }
        $this->invokeWithExtensions('onBeforeSendResponse', $response);
        return $response;
    }

    /**
     * Set HTTP cache headers depending on the request method and configuration
     */
    private function configureHttpCache(string $httpRequestMethod): void
    {
        if (in_array($httpRequestMethod, ['GET', 'HEAD'])) {
            $maxAge = $this->endpointConfig(self::CACHE_MAX_AGE_VIEW, false);
        } elseif ($httpRequestMethod === 'OPTIONS') {
            $maxAge = $this->endpointConfig(self::CACHE_MAX_AGE_OPTIONS, false);
        } else {
            // POST, PATCH, DELETE
            $maxAge = 0;
        }
        if (!ctype_digit((string) $maxAge)) {
            $maxAge = 0;
        }
        $maxAge = (int) $maxAge;
        if ($maxAge > 0) {
            // force = true is required to get this to work, not sure why
            // means that if an extension wants to disable it then they must have
            // ->disableHttpCache(true)
            // i.e. force it disabled, otherwise it will remain enabled
            $force = true;
            HTTPCacheControlMiddleware::singleton()->enableCache($force, $maxAge);
        } else {
            $this->disableHttpCache();
        }
    }

    /**
     * Disable HTTP cache
     */
    private function disableHttpCache(): void
    {
        // force disabling cache due to use of force enabling cache in configureHttpCache()
        // would prefer to not have to force this so that extensions are able to renable it if
        // they wanted for whatever reason
        $force = true;
        HTTPCacheControlMiddleware::singleton()->disableCache($force);
    }

    /**
     * Check if $jsonKey is a method on the Model
     */
    private function jsonKeyIsDataObjectMethod(string $jsonKey): bool
    {
        // __ID is a special relation ID field
        if (substr($jsonKey, -4) === '__ID') {
            return false;
        }
        $model = $this->endpointConfig(self::DATA_CLASS, false);
        $fields = $this->endpointConfig(self::FIELDS, false);
        $dataObjectKey = $fields[$jsonKey];
        if (!is_string($dataObjectKey)) {
            return false;
        }
        $obj = $model::singleton();
        return method_exists($obj, $dataObjectKey);
    }

    /**
     * Check if a config value contains a value, useful for config contains compositive values
     * e.g. configContains(<something that is VIEW_CREATE_EDIT_DELETE_ACTION), 'EDIT') => true
     */
    private function configContains(string $configValue, string $value)
    {
        $values = explode(self::DELIMITER, $configValue);
        return in_array($value, $values);
    }
}
