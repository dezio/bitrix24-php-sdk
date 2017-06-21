<?php
/*
 * This file is part of the bitrix24-php-sdk package.
 *
 * © Mesilov Maxim <mesilov.maxim@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */
namespace Bitrix24;

use Bitrix24\Contracts\iBitrix24;
use Bitrix24\Exceptions\Bitrix24ApiException;
use Bitrix24\Exceptions\Bitrix24BadGatewayException;
use Bitrix24\Exceptions\Bitrix24EmptyResponseException;
use Bitrix24\Exceptions\Bitrix24Exception;
use Bitrix24\Exceptions\Bitrix24IoException;
use Bitrix24\Exceptions\Bitrix24MethodNotFoundException;
use Bitrix24\Exceptions\Bitrix24PaymentRequiredException;
use Bitrix24\Exceptions\Bitrix24PortalDeletedException;
use Bitrix24\Exceptions\Bitrix24SecurityException;
use Bitrix24\Exceptions\Bitrix24TokenIsExpiredException;
use Bitrix24\Exceptions\Bitrix24TokenIsInvalidException;
use Bitrix24\Exceptions\Bitrix24WrongClientException;
use Psr\Log\LoggerInterface;
use Psr\Log\NullLogger;

/**
 * Class Bitrix24
 * @author Mesilov Maxim <mesilov.maxim@gmail.com>
 * @copyright 2013 - 2016 Mesilov Maxim
 */
class Bitrix24 implements iBitrix24
{
	const STATE_NEW = 1;
	const STATE_PENDING = 2;
	const STATE_IN_PROGRESS = 3;
	const STATE_SUPPOSEDLY_COMPLETED = 4;
	const STATE_COMPLETED = 5;
	const STATE_DEFERRED = 6;
	const STATE_DECLINED = 7;
	
	/**
     * @var string SDK version
     */
    const VERSION = '1.0';

    /**
     * @var string OAuth server
     */
    const OAUTH_SERVER = 'oauth.bitrix.info';

    /**
     * Max calls in one batch
     */
    const MAX_BATCH_CALLS = 50;

    /**
     * Default delay between batch calls (in msec)
     */
    const BATCH_DELAY = 500000;

    /**
     * @var string access token
     */
    protected $accessToken;

    /**
     * @var string refresh token
     */
    protected $refreshToken;

    /**
     * @var string domain
     */
    protected $domain;

    /**
     * @var array scope
     */
    protected $applicationScope = array();

    /**
     * @var string application id
     */
    protected $applicationId;

    /**
     * @var string application secret
     */
    protected $applicationSecret;

    /**
     * @var array raw request, contain all cURL options array and API query
     */
    protected $rawRequest;

    /**
     * @var array, contain all api-method parameters, vill be available after call method
     */
    protected $methodParameters;

    /**
     * @var array request info data structure акщь curl_getinfo function
     */
    protected $requestInfo;

    /**
     * @var bool if true raw response from bitrix24 will be available from method getRawResponse, this is debug mode
     */
    protected $isSaveRawResponse = false;

    /**
     * @var array raw response from bitrix24
     */
    protected $rawResponse;

    /**
     * @var string redirect URI from application settings
     */
    protected $redirectUri;

    /**
     * @var string portal GUID
     */
    protected $memberId;

    /**
     * @var array custom options for cURL
     */
    protected $customCurlOptions;

    /**
     * @see https://github.com/Seldaek/monolog
     * @var \Monolog\Logger PSR-3 compatible logger, use only from wrappers methods log*
     */
    protected $log;

    /**
     * @var integer CURL request count retries
     */
    protected $retriesToConnectCount;

    /**
     * @var integer retries to connect timeout in microseconds
     */
    protected $retriesToConnectTimeout;

    /**
     * @var array pending batch calls
     */
    protected $_batch = array();

    /**
     * @var callable callback for expired tokens
     */
    protected $_onExpiredToken;

    protected $_onPrepare = null;
    
    public function setPrepare($func) {
    	$this->_onPrepare = $func;
    }
    
    public function prepare() {
    	if($this->_onPrepare != null) {
		    return call_user_func($this->_onPrepare, $this);
	    }
	    return false;
    }
	
    public function me() {
	    $obB24User = new \Bitrix24\User\User($this);
	    return $arCurrentB24User = $obB24User->current()["result"];
    }
    
    /**
     * Set function called on token expiration. Callback receives instance as first parameter.
     * If callback returns true, API call will be retried.
     *
     * @param callable $callback
     */
    public function setOnExpiredToken(callable $callback)
    {
        $this->_onExpiredToken = $callback;
    }

    /**
     * Create a object to work with Bitrix24 REST API service
     *
     * @param bool $isSaveRawResponse - if true raw response from bitrix24 will be available from method getRawResponse, this is debug mode
     * @param null|LoggerInterface $obLogger - instance of \Monolog\Logger
     *
     * @throws Bitrix24Exception
     *
     * @return Bitrix24
     */
    public function __construct($isSaveRawResponse = false, LoggerInterface $obLogger = null)
    {
        if (!extension_loaded('curl')) {
            throw new Bitrix24Exception('cURL extension must be installed to use this library');
        }
        if (!is_bool($isSaveRawResponse)) {
            throw new Bitrix24Exception('isSaveRawResponse flag must be boolean');
        }
        $this->isSaveRawResponse = $isSaveRawResponse;
        if ($obLogger !== null) {
            /**
             * @var \Monolog\Logger
             */
            $this->log = clone $obLogger;
        } else {
            // dev/null logger
            /**
             * @var \Monolog\Logger
             */
            $this->log = new NullLogger();
        }
        $this->setRetriesToConnectCount(1);
        $this->setRetriesToConnectTimeout(1000000);
    }

    /**
     * Get a random string to sign protected api-call. Use salt for argument "state" in secure api-call
     * random string is a result of mt_rand function
     *
     * @return int
     */
    public function getSecuritySignSalt()
    {
        return mt_rand();
    }

    /**
     * Set member ID — portal GUID
     *
     * @param string $memberId
     *
     * @throws Bitrix24Exception
     *
     * @return true
     */
    public function setMemberId($memberId)
    {
        if ('' === $memberId) {
            throw new Bitrix24Exception('memberId is empty');
        } elseif (null === $memberId) {
            throw new Bitrix24Exception('memberId is null');
        }
        $this->memberId = $memberId;
        return true;
    }

    /**
     * Get memeber ID
     *
     * @return string | null
     */
    public function getMemberId()
    {
        return $this->memberId;
    }

    /**
     * Set redirect URI
     *
     * @param string $redirectUri
     *
     * @throws Bitrix24Exception
     *
     * @return true;
     */
    public function setRedirectUri($redirectUri)
    {
        if ('' === $redirectUri) {
            throw new Bitrix24Exception('redirect URI is empty');
        }
        $this->redirectUri = $redirectUri;
        return true;
    }

    /**
     * Get redirect URI
     *
     * @return string | null
     */
    public function getRedirectUri()
    {
        return $this->redirectUri;
    }

    /**
     * Set access token
     *
     * @param string $accessToken
     *
     * @throws Bitrix24Exception
     *
     * @return true
     */
    public function setAccessToken($accessToken)
    {
        if ('' === $accessToken) {
            throw new Bitrix24Exception('access token is empty');
        }
        $this->accessToken = $accessToken;
        return true;
    }

    /**
     * Get access token
     *
     * @return string | null
     */
    public function getAccessToken()
    {
        return $this->accessToken;
    }

    /**
     * Set refresh token
     *
     * @param $refreshToken
     *
     * @throws Bitrix24Exception
     *
     * @return true;
     */
    public function setRefreshToken($refreshToken)
    {
        if ('' === $refreshToken) {
            throw new Bitrix24Exception('refresh token is empty');
        }
        $this->refreshToken = $refreshToken;
        return true;
    }

    /**
     * Get refresh token
     *
     * @return string
     */
    public function getRefreshToken()
    {
        return $this->refreshToken;
    }

    /**
     * Set domain
     *
     * @param $domain
     *
     * @throws Bitrix24Exception
     *
     * @return true;
     */
    public function setDomain($domain)
    {
        if ('' === $domain) {
            throw new Bitrix24Exception('domain is empty');
        }
        $this->domain = $domain;
        return true;
    }

    /**
     * Get domain
     *
     * @return string | null
     */
    public function getDomain()
    {
        return $this->domain;
    }

    /**
     * Set application scope
     *
     * @param array $applicationScope
     *
     * @return boolean
     *
     * @throws Bitrix24Exception
     */
    public function setApplicationScope(array $applicationScope)
    {
        if (is_array($applicationScope) && count($applicationScope) > 0) {
            $this->applicationScope = $applicationScope;
            return true;
        } else {
            throw new Bitrix24Exception('application scope not set');
        }
    }

    /**
     * Get application scope
     *
     * @return string
     */
    public function getApplicationScope()
    {
        return $this->applicationScope;
    }

    /**
     * Set application id
     *
     * @param string $applicationId
     *
     * @throws Bitrix24Exception
     *
     * @return true;
     */
    public function setApplicationId($applicationId)
    {
        if ('' === $applicationId) {
            throw new Bitrix24Exception('application id is empty');
        }
        $this->applicationId = $applicationId;
        return true;
    }// end of SetApplicationId

    /**
     * Get application id
     *
     * @return string
     */
    public function getApplicationId()
    {
        return $this->applicationId;
    }

    /**
     * Set application secret
     *
     * @param string $applicationSecret
     *
     * @throws Bitrix24Exception
     *
     * @return true;
     */
    public function setApplicationSecret($applicationSecret)
    {
        if ('' === $applicationSecret) {
            throw new Bitrix24Exception('application secret is empty');
        }
        $this->applicationSecret = $applicationSecret;
        return true;
    }

    /**
     * Get application secret
     *
     * @return string
     */
    public function getApplicationSecret()
    {
        return $this->applicationSecret;
    }

    /**
     * Set custom cURL options, overriding default ones
     *
     * @link http://php.net/manual/en/function.curl-setopt.php
     *
     * @param array $options - array(CURLOPT_XXX => value1, CURLOPT_XXX2 => value2,...)
     *
     * @return bool
     */
    public function setCustomCurlOptions($options)
    {
        $this->customCurlOptions = $options;

        return true;
    }

    /**
     * Return raw request, contain all cURL options array and API query. Data available after you try to call method call
     * numbers of array keys is const of cURL module. Example: CURLOPT_RETURNTRANSFER = 19913
     *
     * @return array | null
     */
    public function getRawRequest()
    {
        return $this->rawRequest;
    }

    /**
     * Return result from function curl_getinfo. Data available after you try to call method call
     *
     * @return array | null
     */
    public function getRequestInfo()
    {
        return $this->requestInfo;
    }

    /**
     * Return additional parameters of last api-call. Data available after you try to call method call
     *
     * @return array | null
     */
    public function getMethodParameters()
    {
        return $this->methodParameters;
    }

    /**
     * get error context
     *
     * @return array
     */
    protected function getErrorContext()
    {
        return array(
            // portal specific settings
            'B24_DOMAIN' => $this->getDomain(),
            'B24_MEMBER_ID' => $this->getMemberId(),
            'B24_ACCESS_TOKEN' => $this->getAccessToken(),
            'B24_REFRESH_TOKEN' => $this->getRefreshToken(),
            // application settings
            'APPLICATION_SCOPE' => $this->getApplicationScope(),
            'APPLICATION_ID' => $this->getApplicationId(),
            'APPLICATION_SECRET' => $this->getApplicationSecret(),
            'REDIRECT_URI' => $this->getRedirectUri(),
            // network
            'RAW_REQUEST' => $this->getRawRequest(),
            'CURL_REQUEST_INFO' => $this->getRequestInfo(),
            'RAW_RESPONSE' => $this->getRawResponse()
        );
    }

    /**
     * Execute a request API to Bitrix24 using cURL
     *
     * @param string $url
     * @param array  $additionalParameters
     *
     * @throws Bitrix24Exception
     * @throws Bitrix24PortalDeletedException
     * @throws Bitrix24IoException
     * @throws Bitrix24EmptyResponseException
     *
     * @return array
     * @throws \Bitrix24\Exceptions\Bitrix24BadGatewayException
     */
    protected function executeRequest($url, array $additionalParameters = array())
    {
        $retryableErrorCodes = array(
            CURLE_COULDNT_RESOLVE_HOST,
            CURLE_COULDNT_CONNECT,
            CURLE_HTTP_NOT_FOUND,
            CURLE_READ_ERROR,
            CURLE_OPERATION_TIMEOUTED,
            CURLE_HTTP_POST_ERROR,
            CURLE_SSL_CONNECT_ERROR
        );

        $curlOptions = array(
            CURLOPT_FOLLOWLOCATION => true,
            CURLOPT_RETURNTRANSFER => true,
            CURLINFO_HEADER_OUT => true,
            CURLOPT_VERBOSE => true,
            CURLOPT_CONNECTTIMEOUT => 65,
            CURLOPT_TIMEOUT => 70,
            CURLOPT_USERAGENT => strtolower(__CLASS__ . '-PHP-SDK/v' . self::VERSION),
            CURLOPT_POST => true,
            CURLOPT_POSTFIELDS => http_build_query($additionalParameters),
            CURLOPT_URL => $url
        );

        if (is_array($this->customCurlOptions)) {
            foreach ($this->customCurlOptions as $customCurlOptionKey => $customCurlOptionValue) {
                $curlOptions[$customCurlOptionKey] = $customCurlOptionValue;
            }
        }

        $this->rawRequest = $curlOptions;
        $curl = curl_init();
        curl_setopt_array($curl, $curlOptions);

        $curlResult = false;
        $retriesCnt = $this->retriesToConnectCount;
        while ($retriesCnt--) {
            $this->log->debug(sprintf('try [%s] to connect to host [%s]', $retriesCnt, $this->getDomain()));
            $curlResult = curl_exec($curl);
            // handling network I/O errors
            if (false === $curlResult) {
                $curlErrorNumber = curl_errno($curl);
                $errorMsg = sprintf('in try[%s] cURL error (code %s): %s' . PHP_EOL, $retriesCnt, $curlErrorNumber,
                    curl_error($curl));
                if (false === in_array($curlErrorNumber, $retryableErrorCodes, true) || !$retriesCnt) {
                    $this->log->error($errorMsg, $this->getErrorContext());
                    curl_close($curl);
                    throw new Bitrix24IoException($errorMsg);
                } else {
                    $this->log->warning($errorMsg, $this->getErrorContext());
                }
                usleep($this->getRetriesToConnectTimeout());
                continue;
            }
            $this->requestInfo = curl_getinfo($curl);
            $this->rawResponse = $curlResult;
            $this->log->debug('cURL request info', array($this->getRequestInfo()));
            curl_close($curl);
            break;
        }

        // handling URI level resource errors
        switch ($this->requestInfo['http_code']) {
            case 403:
                $errorMsg = sprintf('portal [%s] deleted, query aborted', $this->getDomain());
                $this->log->error($errorMsg, $this->getErrorContext());
                throw new Bitrix24PortalDeletedException($errorMsg);
                break;

            case 502:
                $errorMsg = sprintf('bad gateway to portal [%s]', $this->getDomain());
                $this->log->error($errorMsg, $this->getErrorContext());
                throw new Bitrix24BadGatewayException($errorMsg);
                break;
        }

        // handling server-side API errors: empty response from bitrix24 portal
        if ($curlResult === '') {
            $errorMsg = sprintf('empty response from portal [%s]', $this->getDomain());
            $this->log->error($errorMsg, $this->getErrorContext());
            throw new Bitrix24EmptyResponseException($errorMsg);
        }

        // handling json_decode errors
        $jsonResult = json_decode($curlResult, true);
        unset($curlResult);
        $jsonErrorCode = json_last_error();
        if (null === $jsonResult && (JSON_ERROR_NONE !== $jsonErrorCode)) {
            /**
             * @todo add function json_last_error_msg()
             */
            $errorMsg = 'fatal error in function json_decode.' . PHP_EOL . 'Error code: ' . $jsonErrorCode . PHP_EOL;
            $this->log->error($errorMsg, $this->getErrorContext());
            throw new Bitrix24Exception($errorMsg);
        }
        return $jsonResult;
    }


    /**
     * Execute Bitrix24 REST API method
     *
     * @param string $methodName
     * @param array  $additionalParameters
     *
     * @return mixed
     * @throws \Bitrix24\Exceptions\Bitrix24WrongClientException
     * @throws \Bitrix24\Exceptions\Bitrix24TokenIsInvalidException
     * @throws \Bitrix24\Exceptions\Bitrix24SecurityException
     * @throws \Bitrix24\Exceptions\Bitrix24PortalDeletedException
     * @throws \Bitrix24\Exceptions\Bitrix24PaymentRequiredException
     * @throws \Bitrix24\Exceptions\Bitrix24MethodNotFoundException
     * @throws \Bitrix24\Exceptions\Bitrix24IoException
     * @throws \Bitrix24\Exceptions\Bitrix24Exception
     * @throws \Bitrix24\Exceptions\Bitrix24EmptyResponseException
     * @throws \Bitrix24\Exceptions\Bitrix24ApiException
     * @throws Bitrix24TokenIsExpiredException
     */
    public function call($methodName, array $additionalParameters = array())
    {
        try {
            $result = $this->_call($methodName, $additionalParameters);
        } catch (Bitrix24TokenIsExpiredException $e) {
            if (!is_callable($this->_onExpiredToken)) {
                throw $e;
            }

            $retry = call_user_func($this->_onExpiredToken, $this);
            if (!$retry) {
                throw $e;
            }
            $result = $this->_call($methodName, $additionalParameters);
        }

        return $result;
    }

    /**
     * Execute Bitrix24 REST API method
     *
     * @param string $methodName
     * @param array $additionalParameters
     *
     * @throws Bitrix24Exception
     * @throws Bitrix24ApiException
     * @throws Bitrix24TokenIsInvalidException
     * @throws Bitrix24TokenIsExpiredException
     * @throws Bitrix24WrongClientException
     * @throws Bitrix24MethodNotFoundException
     * @throws Bitrix24PaymentRequiredException
     * @throws Bitrix24SecurityException
     * @throws Bitrix24PortalDeletedException
     * @throws Bitrix24IoException
     * @throws Bitrix24EmptyResponseException
     *
     * @return array
     */
    protected function _call($methodName, array $additionalParameters = array())
    {
        if (null === $this->getDomain()) {
            throw new Bitrix24Exception('domain not found, you must call setDomain method before');
        }
        if (null === $this->getAccessToken()) {
            throw new Bitrix24Exception('access token not found, you must call setAccessToken method before');
        }
        if ('' === $methodName) {
            throw new Bitrix24Exception('method name not found, you must set method name');
        }

        $url = 'https://' . $this->domain . '/rest/' . $methodName;
        $additionalParameters['auth'] = $this->accessToken;
        // save method parameters for debug
        $this->methodParameters = $additionalParameters;
        // is secure api-call?
        $isSecureCall = false;
        if (array_key_exists('state', $additionalParameters)) {
            $isSecureCall = true;
        }
        // execute request
        $this->log->info('call bitrix24 method', array(
            'BITRIX24_DOMAIN' => $this->domain,
            'METHOD_NAME' => $methodName,
            'METHOD_PARAMETERS' => $additionalParameters
        ));
        $requestResult = $this->executeRequest($url, $additionalParameters);
        // check errors and throw exception if errors exists
        $this->handleBitrix24APILevelErrors($requestResult, $methodName, $additionalParameters);
        // handling security sign for secure api-call
        if ($isSecureCall) {
            if (array_key_exists('signature', $requestResult)) {
                // check signature structure
                if (strpos($requestResult['signature'], '.') === false) {
                    throw new Bitrix24SecurityException('security signature is corrupted');
                }
                if (null === $this->getMemberId()) {
                    throw new Bitrix24Exception('member-id not found, you must call setMemberId method before');
                }
                if (null === $this->getApplicationSecret()) {
                    throw new Bitrix24Exception('application secret not found, you must call setApplicationSecret method before');
                }
                // prepare
                $key = md5($this->getMemberId() . $this->getApplicationSecret());
                $delimiterPosition = strrpos($requestResult['signature'], '.');
                $dataToDecode = substr($requestResult['signature'], 0, $delimiterPosition);
                $signature = base64_decode(substr($requestResult['signature'], $delimiterPosition + 1));
                // compare signatures
                $hash = hash_hmac('sha256', $dataToDecode, $key, true);
                if ($hash !== $signature) {
                    throw new Bitrix24SecurityException('security signatures not same, bad request');
                }
                // decode
                $arClearData = json_decode(base64_decode($dataToDecode), true);
                // handling json_decode errors
                $jsonErrorCode = json_last_error();
                if (null === $arClearData && (JSON_ERROR_NONE !== $jsonErrorCode)) {
                    /**
                     * @todo add function json_last_error_msg()
                     */
                    $errorMsg = 'fatal error in function json_decode.' . PHP_EOL . 'Error code: ' . $jsonErrorCode . PHP_EOL;
                    throw new Bitrix24Exception($errorMsg);
                }
                // merge dirty and clear data
                unset($arClearData['state']);
                $requestResult ['result'] = array_merge($requestResult ['result'], $arClearData);
            } else {
                throw new Bitrix24SecurityException('security signature in api-response not found');
            }
        }
        return $requestResult;
    }

    /**
     * Handling bitrix24 api-level errors
     *
     * @param $arRequestResult
     * @param $methodName
     * @param array $additionalParameters
     *
     * @return null
     *
     * @throws Bitrix24ApiException
     * @throws Bitrix24TokenIsInvalidException
     * @throws Bitrix24TokenIsExpiredException
     * @throws Bitrix24WrongClientException
     * @throws Bitrix24MethodNotFoundException
     * @throws Bitrix24PaymentRequiredException
     */
    protected function handleBitrix24APILevelErrors(
        $arRequestResult,
        $methodName,
        array $additionalParameters = array()
    ) {
        if (array_key_exists('error', $arRequestResult)) {
            $errorMsg = sprintf('%s - %s in call [%s] for domain [%s]',
                $arRequestResult['error'],
                (array_key_exists('error_description', $arRequestResult) ? $arRequestResult['error_description'] : ''),
                $methodName,
                $this->getDomain());
            $this->log->error($errorMsg, $this->getErrorContext());
            // throw specific API-level exceptions
            switch (strtoupper(trim($arRequestResult['error']))) {
                case 'WRONG_CLIENT':
                case 'ERROR_OAUTH':
                    throw new Bitrix24WrongClientException($errorMsg);
                case 'ERROR_METHOD_NOT_FOUND':
                    throw new Bitrix24MethodNotFoundException($errorMsg);
                case 'INVALID_TOKEN':
                case 'INVALID_GRANT':
                    throw new Bitrix24TokenIsInvalidException($errorMsg);
                case 'EXPIRED_TOKEN':
                    throw new Bitrix24TokenIsExpiredException($errorMsg);
                case 'PAYMENT_REQUIRED':
                    throw new Bitrix24PaymentRequiredException($errorMsg);
                default:
                    throw new Bitrix24ApiException($errorMsg);
            }
        }
        return null;
    }

    /**
     * Get raw response from Bitrix24 before json_decode call, method available only in debug mode.
     * To activate debug mode you must before set to true flag isSaveRawResponse in class construct
     *
     * @return string | null
     */
    public function getRawResponse()
    {
        return $this->rawResponse;
    }

    /**
     * Get new access token
     *
     * @return array
     *
     * @throws Bitrix24Exception
     * @throws Bitrix24ApiException
     * @throws Bitrix24PortalDeletedException
     * @throws Bitrix24IoException
     * @throws Bitrix24EmptyResponseException
     * @throws Bitrix24TokenIsInvalidException
     * @throws Bitrix24TokenIsExpiredException
     * @throws Bitrix24WrongClientException
     * @throws Bitrix24MethodNotFoundException
     * @throws Bitrix24PaymentRequiredException
     *
     */
    public function getNewAccessToken()
    {
        $applicationId = $this->getApplicationId();
        $applicationSecret = $this->getApplicationSecret();
        $refreshToken = $this->getRefreshToken();
        $applicationScope = $this->getApplicationScope();
        $redirectUri = $this->getRedirectUri();

        if (null === $applicationId) {
            throw new Bitrix24Exception('application id not found, you must call setApplicationId method before');
        } elseif (null === $applicationSecret) {
            throw new Bitrix24Exception('application id not found, you must call setApplicationSecret method before');
        } elseif (null === $refreshToken) {
            throw new Bitrix24Exception('application id not found, you must call setRefreshToken method before');
        } elseif (0 === count($applicationScope)) {
            throw new Bitrix24Exception('application scope not found, you must call setApplicationScope method before');
        } elseif (null === $redirectUri) {
            throw new Bitrix24Exception('application redirect URI not found, you must call setRedirectUri method before');
        }

//		$url = 'https://'.self::OAUTH_SERVER.'/oauth/token/'.
        $url = 'https://' . $this->getDomain() . '/oauth/token/' .
            '?client_id=' . urlencode($applicationId) .
            '&grant_type=refresh_token' .
            '&client_secret=' . $applicationSecret .
            '&refresh_token=' . $refreshToken .
            '&redirect_uri=' . urlencode($redirectUri);
        $requestResult = $this->executeRequest($url);
        // handling bitrix24 api-level errors
        $this->handleBitrix24APILevelErrors($requestResult, 'refresh access token');
        return $requestResult;
    }

    /**
     * Authorize and get first access token
     *
     * @param $code
     *
     * @return array
     *
     * @throws Bitrix24Exception
     * @throws Bitrix24ApiException
     * @throws Bitrix24PortalDeletedException
     * @throws Bitrix24IoException
     * @throws Bitrix24EmptyResponseException
     * @throws Bitrix24TokenIsInvalidException
     * @throws Bitrix24TokenIsExpiredException
     * @throws Bitrix24WrongClientException
     * @throws Bitrix24MethodNotFoundException
     * @throws Bitrix24PaymentRequiredException
     *
     */
    public function getFirstAccessToken($code)
    {
        $applicationId = $this->getApplicationId();
        $applicationSecret = $this->getApplicationSecret();
        $applicationScope = $this->getApplicationScope();
        $redirectUri = $this->getRedirectUri();

        if (null === $applicationId) {
            throw new Bitrix24Exception('application id not found, you must call setApplicationId method before');
        } elseif (null === $applicationSecret) {
            throw new Bitrix24Exception('application id not found, you must call setApplicationSecret method before');
        } elseif (0 === count($applicationScope)) {
            throw new Bitrix24Exception('application scope not found, you must call setApplicationScope method before');
        } elseif (null === $redirectUri) {
            throw new Bitrix24Exception('application redirect URI not found, you must call setRedirectUri method before');
        }
	    
//        $url = 'https://'.self::OAUTH_SERVER.'/oauth/token/'.
        $url = 'https://' . $this->getDomain() . '/oauth/token/' .
            '?client_id=' . urlencode($applicationId) .
            '&grant_type=authorization_code' .
            '&client_secret=' . $applicationSecret .
            '&redirect_uri=' . urlencode($redirectUri) .
            '&code=' . urlencode($code);

        $requestResult = $this->executeRequest($url);
        // handling bitrix24 api-level errors
        $this->handleBitrix24APILevelErrors($requestResult, 'get first access token');
        return $requestResult;
    }

    /**
     * Authorize and get first access token
     *
     * @param $code
     *
     * @return array
     *
     * @throws Bitrix24Exception
     * @throws Bitrix24ApiException
     * @throws Bitrix24PortalDeletedException
     * @throws Bitrix24IoException
     * @throws Bitrix24EmptyResponseException
     * @throws Bitrix24TokenIsInvalidException
     * @throws Bitrix24TokenIsExpiredException
     * @throws Bitrix24WrongClientException
     * @throws Bitrix24MethodNotFoundException
     * @throws Bitrix24PaymentRequiredException
     *
     */
    public function getCodeUrl()
    {
        $applicationId = $this->getApplicationId();
        $applicationSecret = $this->getApplicationSecret();
        $redirectUri = $this->getRedirectUri();

        if (null === $applicationId) {
            throw new Bitrix24Exception('application id not found, you must call setApplicationId method before');
        } elseif (null === $redirectUri) {
            throw new Bitrix24Exception('application redirect URI not found, you must call setRedirectUri method before');
        }
	
	    $url = "https://prepaidhoster.bitrix24.de/oauth/authorize/?response_type=code" .
		    "&client_id=" . $this->getApplicationId() . "" .
		    "&redirect_uri=" . urlencode($this->getRedirectUri());
	    
        return $url;
    }

    /**
     * Check is access token expire, call list of all available api-methods from B24 portal with current access token
     * if we have an error code expired_token then return true else return false
     *
     * @throws Bitrix24Exception
     * @throws Bitrix24ApiException
     * @throws Bitrix24PortalDeletedException
     * @throws Bitrix24IoException
     * @throws Bitrix24EmptyResponseException
     * @throws Bitrix24TokenIsInvalidException
     * @throws Bitrix24TokenIsExpiredException
     * @throws Bitrix24WrongClientException
     * @throws Bitrix24MethodNotFoundException
     * @throws Bitrix24PaymentRequiredException
     *
     * @return boolean
     */
    public function isAccessTokenExpire()
    {
        $isTokenExpire = false;
        $accessToken = $this->getAccessToken();
        $domain = $this->getDomain();

        if (null === $domain) {
            throw new Bitrix24Exception('domain not found, you must call setDomain method before');
        } elseif (null === $accessToken) {
            throw new Bitrix24Exception('application id not found, you must call setAccessToken method before');
        }
//		$url = 'https://'.self::OAUTH_SERVER.'/rest/app.info?auth='.$accessToken;
        $url = 'https://' . $domain . '/rest/app.info?auth=' . $accessToken;
        $requestResult = $this->executeRequest($url);
        if (isset($requestResult['error'])) {
            if (in_array($requestResult['error'], array('expired_token', 'invalid_token', 'WRONG_TOKEN'), false)) {
                $isTokenExpire = true;
            } else {
                // handle other errors
                $this->handleBitrix24APILevelErrors($requestResult, 'app.info');
            }
        }
        return $isTokenExpire;
    }// end of isTokenExpire

    /**
     * Get list of all methods available for current application
     *
     * @param array | null $applicationScope
     * @param bool $isFull
     *
     * @return array
     *
     * @throws Bitrix24Exception
     * @throws Bitrix24Exception
     * @throws Bitrix24PortalDeletedException
     * @throws Bitrix24IoException
     * @throws Bitrix24EmptyResponseException
     */
    public function getAvailableMethods(array $applicationScope = array(), $isFull = false)
    {
        $accessToken = $this->getAccessToken();
        $domain = $this->getDomain();

        if (null === $domain) {
            throw new Bitrix24Exception('domain not found, you must call setDomain method before');
        } elseif (null === $accessToken) {
            throw new Bitrix24Exception('application id not found, you must call setAccessToken method before');
        }

        $showAll = '';
        if (true === $isFull) {
            $showAll = '&full=true';
        }
        $scope = '';
        if (null === $applicationScope) {
            $scope = '&scope';
        } elseif (count(array_unique($applicationScope)) > 0) {
            $scope = '&scope=' . implode(',', array_map('urlencode', array_unique($applicationScope)));
        }
        $url = 'https://' . $domain . '/rest/methods.json?auth=' . $accessToken . $showAll . $scope;
        return $this->executeRequest($url);
    }

    /**
     * get list of scope for current application from bitrix24 api
     *
     * @param bool $isFull
     *
     * @throws Bitrix24Exception
     * @throws Bitrix24Exception
     * @throws Bitrix24PortalDeletedException
     * @throws Bitrix24IoException
     * @throws Bitrix24EmptyResponseException
     *
     * @return array
     */
    public function getScope($isFull = false)
    {
        $accessToken = $this->getAccessToken();
        $domain = $this->getDomain();

        if (null === $domain) {
            throw new Bitrix24Exception('domain not found, you must call setDomain method before');
        } elseif (null === $accessToken) {
            throw new Bitrix24Exception('application id not found, you must call setAccessToken method before');
        }
        $showAll = '';
        if (true === $isFull) {
            $showAll = '&full=true';
        }
        $url = 'https://' . $domain . '/rest/scope.json?auth=' . $accessToken . $showAll;
        return $this->executeRequest($url);
    }

    /**
     * set CURL request count retries
     * @param $retriesCnt
     *
     * @return boolean
     *
     * @throws  Bitrix24Exception
     */
    public function setRetriesToConnectCount($retriesCnt = 1)
    {
        $this->log->debug(sprintf('set retries to connect count %s', $retriesCnt));
        if (!is_int($retriesCnt)) {
            throw new Bitrix24Exception('retries to connect count must be an integer');
        }
        $this->retriesToConnectCount = (int)$retriesCnt;
        return true;
    }

    /**
     * set retries to connect timeout in microseconds
     * @param int $microseconds
     * @return bool
     * @throws Bitrix24Exception
     */
    public function setRetriesToConnectTimeout($microseconds = 1000000)
    {
        $this->log->debug(sprintf('set retries to connect count %s', $microseconds));
        if (!is_numeric($microseconds)) {
            throw new Bitrix24Exception('retries to connect count must be an integer');
        }
        $this->retriesToConnectTimeout = $microseconds;
        return true;
    }

    /**
     * get CURL request count retries
     *
     * @return int
     */
    public function getRetriesToConnectCount()
    {
        return $this->retriesToConnectCount;
    }

    /**
     * get retries to connect timeout in microseconds
     *
     * @return mixed
     */
    public function getRetriesToConnectTimeout()
    {
        return $this->retriesToConnectTimeout;
    }

    /**
     * Add call to batch. If [[$callback]] parameter is set, it will receive call result as first parameter.
     *
     * @param string $method
     * @param array $parameters
     * @param callable|null $callback
     *
     * @return string Unique call ID.
     */
    public function addBatchCall($method, array $parameters = array(), callable $callback = null)
    {
        $id = uniqid();
        $this->_batch[$id] = array(
            'method' => $method,
            'parameters' => $parameters,
            'callback' => $callback,
        );
        return $id;
    }

    /**
     * Return true, if we have unprocessed batch calls.
     *
     * @return bool
     */
    public function hasBatchCalls()
    {
        return (bool) count($this->_batch);
    }

    /**
     * Process batch calls.
     *
     * @param int $halt  Halt batch on error
     * @param int $delay Delay between batch calls (in msec)
     *
     * @throws Bitrix24Exception
     * @throws Bitrix24SecurityException
     * @throws \Bitrix24\Exceptions\Bitrix24ApiException
     * @throws \Bitrix24\Exceptions\Bitrix24TokenIsExpiredException
     */
    public function processBatchCalls($halt = 0, $delay = self::BATCH_DELAY)
    {
        while (count($this->_batch)) {
            $slice = array_splice($this->_batch, 0, self::MAX_BATCH_CALLS);
            $commands = array();
            foreach ($slice as $idx => $call) {
                $commands[$idx] = $call['method'] . '?' . http_build_query($call['parameters']);
            }
            $batchResult = $this->call('batch', array('halt' => $halt, 'cmd' => $commands));
            $results = $batchResult['result'];
            foreach ($slice as $idx => $call) {
                if (!isset($call['callback']) || !is_callable($call['callback'])) {
                    continue;
                }

                call_user_func($call['callback'], array(
                    'result' => isset($results['result'][$idx]) ? $results['result'][$idx] : null,
                    'error' => isset($results['result_error'][$idx]) ? $results['result_error'][$idx] : null,
                    'total' => isset($results['result_total'][$idx]) ? $results['result_total'][$idx] : null,
                    'next' => isset($results['result_next'][$idx]) ? $results['result_next'][$idx] : null,
                ));
            }
            if (count($this->_batch) && $delay) {
                usleep($delay);
            }
        }
    }
}

/**
 * @name
 *
 * @author Qexy
 *
 * @contact admin@qexy.org
 *
 * @version 1.0.0
 *
 * @copyright Qexy.org
 *
 * @example example.php
 *
 * @license https://github.com/qexyorg/BB-Code-Parser/blob/master/LICENSE
 *
 */
class MiniBitrixBBCode {
	// URL до папки со смайликами
	private $smiles_url = '/qx_upload/api/smiles/';
	// Шаблоны обычных ББ-кодов (рекурсивные)
	public $codes = array(
		'b' => array(
			'left_tag' => '<b>',
			'right_tag' => '</b>'
		),
		
		'i' => array(
			'left_tag' => '<i>',
			'right_tag' => '</i>'
		),
		
		'u' => array(
			'left_tag' => '<u>',
			'right_tag' => '</u>'
		),
		
		's' => array(
			'left_tag' => '<s>',
			'right_tag' => '</s>'
		),
		
		'code' => array(
			'left_tag' => '<div class="qxbb-code">',
			'right_tag' => '</div>'
		),
		
		'quote' => array(
			'left_tag' => '<div class="qxbb-quote">',
			'right_tag' => '</div>'
		),
		
		'offtop' => array(
			'left_tag' => '<span class="qxbb-offtop" title="Offtop">',
			'right_tag' => '</span>'
		),
		
		'spoiler' => array(
			'left_tag' => '<div class="qxbb-spoiler"><button type="button" class="qxbb-spoiler-btn">Спойлер</button><div class="qxbb-spoiler-body">',
			'right_tag' => '</div></div>'
		),
		
		'reverse' => array(
			'left_tag' => '<bdo class="qxbb-reverse" dir="rtl">',
			'right_tag' => '</bdo>'
		),
		
		'left' => array(
			'left_tag' => '<div class="qxbb-left">',
			'right_tag' => '</div>'
		),
		
		'center' => array(
			'left_tag' => '<div class="qxbb-center">',
			'right_tag' => '</div>'
		),
		
		'right' => array(
			'left_tag' => '<div class="qxbb-right">',
			'right_tag' => '</div>'
		),
	);
	// Шаблоны ББ-кодов с опциями и тонкими настройками регулярок (рекурсивные)
	private $codes_options = array(
		'quote' => array(
			'pattern' => '/\[(quote)\=\"(([\w]+) \| (\d{2}\.\d{2}\.\d{2} \- \d{2}\:\d{2}\:\d{2}))\"\]((?:[^[]|(?R))*)\[\/quote\]/Usi',
			'replace' => '<div class="qxbb-quote"><div class="qxbb-quote-info">{2}</div>{5}</div>',
			'values' => array(1,2,5),
			'escapes' => false,
		),
		'code' => array(
			'pattern' => '/\[(code)\=\"(php|html|css|javascript)\"\]((?:[^[]|(?R))*)\[\/code\]/Usi',
			'replace' => '<div class="qxbb-code"><div class="qxbb-code-info">Тип: {2}</div>{3}</div>',
			'values' => array(1,2,3),
			'escapes' => 3,
		),
		'color' => array(
			'pattern' => '/\[(color)\=\"(\#[0-9a-f]{6})\"\]((?:[^[]|\[(?!\/?(color)\])|(?R))+)\[\/color\]/Usi',
			'replace' => '<font color="{2}" class="qxbb-color">{3}</font>',
			'values' => array(1,2,3),
			'escapes' => false,
		),
		'background' => array(
			'pattern' => '/\[(background)\=\"(\#[0-9a-f]{6})\"\]((?:[^[]|(?R))*)\[\/background\]/Usi',
			'replace' => '<font style="background-color:{2};" class="qxbb-background">{3}</font>',
			'values' => array(1,2,3),
			'escapes' => false,
		),
		'size' => array(
			'pattern' => '/\[(size)\=\"([1-7])\"\]((?:[^[]|(?R))*)\[\/size\]/Usi',
			'replace' => '<font size="{2}" class="qxbb-size">{3}</font>',
			'values' => array(1,2,3),
			'escapes' => false,
		),
		'font' => array(
			'pattern' => '/\[(font)\=\"(Arial|Arial Black|Comic Sans MS|Courier New|Georgia|Impact|Tahoma|Times New Roman|Trebuchet MS|Verdana)\"\]((?:[^[]|(?R))*)\[\/font\]/Usi',
			'replace' => '<font face="{2}" class="qxbb-font">{3}</font>',
			'values' => array(1,2,3),
			'escapes' => false,
		),
		'url' => array(
			'pattern' => '/\[(URL)\=\"(http(s)?\:\/\/[\w\.\/\?\=\&\%\+\~\*\-]+)\"\]((?:[^[]|(?R))*)\[\/URL\]/Usi',
			'replace' => '<a href="{2}" class="qxbb-url">{4}</a>',
			'values' => array(1,2,4),
			'escapes' => false,
		),
		'spoiler' => array(
			'pattern' => '/\[(spoiler)\=\"([\w\s\-\.\:\;\+\|\,]{1,32})\"\]((?:[^[]|(?R))*)\[\/spoiler\]/Usui',
			'replace' => '<div class="qxbb-spoiler"><button type="button" class="qxbb-spoiler-btn">{2}</button><div class="qxbb-spoiler-body">{3}</div></div>',
			'values' => array(1,2,3),
			'escapes' => false,
		),
	);
	// Шаблоны ББ-кодов с опциями и тонкими настройками регулярок (не рекурсивные)
	private $codes_once = array(
		'img' => array(
			'pattern' => '/\[img\](http(s)?\:\/\/[\w\.\/\?\=\&\%\+\~\*\-]+)\[\/img\]/Usi',
			'replace' => '<img src="$1" class="qxbb-img" alt="IMG" />',
		),
		'line' => array(
			'pattern' => '/\[line\]/Usi',
			'replace' => '<hr class="qxbb-line">',
		),
		'url' => array(
			'pattern' => '/\[url\](http(s)?\:\/\/[\w\.\/\?\=\&\%\+\~\*\-]+)\[\/url\]/Usi',
			'replace' => '<a href="$1" class="qxbb-url">$1</a>',
		),
		'email' => array(
			'pattern' => '/\[email\]([\w\.\-]+\@[a-z0-9\.\-]+)\[\/email\]/Usi',
			'replace' => '<a href="mailto:$1" class="qxbb-email">$1</a>',
		),
	);
	// Шаблоны ББ-кодов для обработки тегов видео ([video]) с тонкими настройками регулярок (не рекурсивные)
	private $codes_video = array(
		'youtube' => array(
			'pattern' => '((youtube\.com\/watch\?v\=([\w\-]+))|(youtu\.be\/([\w\-]+))|(youtube.com\/embed\/([\w\-]+)))',
			'replace' => 'https://www.youtube.com/embed/$5',
		),
		'vk' => array(
			'pattern' => 'vk.com\/video_ext.php\?oid=(\d+)\&amp;id\=(\d+)\&amp;hash\=(\w+)',
			'replace' => 'http://vk.com/video_ext.php?oid=$3&id=$4&hash=$5',
		),
		'vimeo' => array(
			'pattern' => 'vimeo\.com\/(\d+)',
			'replace' => 'https://player.vimeo.com/video/$3',
		),
		'coub' => array(
			'pattern' => 'coub.com\/view\/(\w+)',
			'replace' => 'http://coub.com/embed/$3',
		),
		'twitch' => array(
			'pattern' => 'twitch\.tv\/(\w+)',
			'replace' => 'http://www.twitch.tv/$3/embed',
		),
		'vine' => array(
			'pattern' => 'vine\.co\/v\/(\w+)',
			'replace' => 'https://vine.co/v/$3/embed/simple',
		),
	);
	// Обработчик смайликов
	private function parse_smiles($text){
		$smile_list = array(
			'[:)]',
			'[:(]',
			'[;)]',
			'[:beer:]',
			'[:good:]',
			'[:wall:]',
			'[:D]',
			'[:shy:]',
			'[:secret:]',
			'[:dance:]',
			'[:rock:]',
			'[:sos:]',
			'[:girl:]',
			'[:facepalm:]',
		);
		$smile_replace = array(
			'<img src="'.$this->smiles_url.'1.gif" alt=":)" />',
			'<img src="'.$this->smiles_url.'2.gif" alt=":(" />',
			'<img src="'.$this->smiles_url.'3.gif" alt=";)" />',
			'<img src="'.$this->smiles_url.'4.gif" alt=":beer:" />',
			'<img src="'.$this->smiles_url.'5.gif" alt=":good:" />',
			'<img src="'.$this->smiles_url.'6.gif" alt=":wall:" />',
			'<img src="'.$this->smiles_url.'7.gif" alt=":D" />',
			'<img src="'.$this->smiles_url.'8.gif" alt=":shy:" />',
			'<img src="'.$this->smiles_url.'9.gif" alt=":secret:" />',
			'<img src="'.$this->smiles_url.'10.gif" alt=":dance:" />',
			'<img src="'.$this->smiles_url.'11.gif" alt=":rock:" />',
			'<img src="'.$this->smiles_url.'12.gif" alt=":sos:" />',
			'<img src="'.$this->smiles_url.'13.gif" alt=":girl:" />',
			'<img src="'.$this->smiles_url.'14.gif" alt=":facepalm:" />',
		);
		return str_replace($smile_list, $smile_replace, $text);
	}
	// Обработчик единичных тегов
	private function parse_once($text){
		$replace = $pattern = array();
		foreach($this->codes_once as $key => $value){
			$pattern[] = $value['pattern'];
			$replace[] = $value['replace'];
		}
		return preg_replace($pattern, $replace, $text);
	}
	// Обработчик обычных тегов с открывающими и загрывающими тегами
	private function parse_simple_tags($text){
		$pattern = '/\[('.implode('|', array_keys($this->codes)).')\]((?:[^[]|\[(?!\/?(\\1)\])|(?R))+)\[\/\\1\]/Usi';
		if(is_array($text)){
			$left_tag = $this->codes[$text[1]]['left_tag'];
			$right_tag = $this->codes[$text[1]]['right_tag'];
			$content = $text[2];
			if($text[1]=='code'){
				$content = str_replace(array('[', ']'), array('&#91;', '&#93;'), $content);
			}
			$text = $left_tag.$content.$right_tag; // result
		}else{
			$text = nl2br(htmlspecialchars($text, ENT_NOQUOTES));
		}
		return preg_replace_callback($pattern, array($this, 'parse_simple_tags'), $text);
	}
	// Обработчик тегов с опциями
	private function parse_with_options($text){
		if(is_array($text)){
			$codes = $this->codes_options;
			if(isset($codes[$text[1]])){
				$escape = $codes[$text[1]]['escapes'];
				if($escape!==false){
					$text[$escape] = str_replace(array('[', ']'), array('&#91;', '&#93;'), $text[$escape]);
				}
				
				$replace = $codes[$text[1]]['replace'];
				unset($codes[$text[1]]['values'][0]);
				foreach($codes[$text[1]]['values'] as $key => $value){
					$replace = str_replace('{'.$value.'}', $text[$value], $replace);
				}
				$text = $replace;
			}
		}
		$patterns = array();
		foreach($this->codes_options as $key => $value){
			$patterns[] = $value['pattern'];
		}
		return preg_replace_callback($patterns, array($this, 'parse_with_options'), $text);
	}
	// Обработчик видео тегов
	private function parse_video($text){
		$pattern = $replace = array();
		foreach($this->codes_video as $name => $value){
			$pattern[] = '/\[video\=\"'.$name.'\"\]http(s)?\:\/\/(www\.)?'.$value['pattern'].'\[\/video\]/Usi';
			$replace[] = '<iframe width="854" class="qxbb-iframe" height="480" src="'.$value['replace'].'" frameborder="0"></iframe>';
		}
		return preg_replace($pattern, $replace, $text);
	}
	// Обработчик списковых тегов
	private function parse_list_line($text){
		if(is_array($text)){
			$text = '<li>'.$text[1].'</li>';
		}
		return preg_replace_callback('/\[\*\]((?:[^[]|(?R))*)/si', array($this, 'parse_list_line'), $text);
	}
	private function parse_list($text){
		if(is_array($text)){
			
			$text = ($text['1']=='numbers') ? '<ol class="qxbb-list-numbers">'.$text[2].'</ol>' : '<ul class="qxbb-list-markers">'.$text[2].'</ul>';
		}else{
			$text = $this->parse_list_line($text);
		}
		return preg_replace_callback('/\[list\=\"(markers|numbers)\"\]((?:[^[]|(?R))*)\[\/list\]/Usi', array($this, 'parse_list'), $text);
	}
	public function parse($text){
		$text = $this->parse_simple_tags($text);
		$text = $this->parse_smiles($text);
		$text = $this->parse_once($text);
		$text = $this->parse_video($text);
		$text = $this->parse_list($text);
		return $this->parse_with_options($text);
	}
	
	public static function parseText($text) {
		$o = new self();
		return $o->parse($text);
	}
}
?>
