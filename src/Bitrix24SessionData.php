<?php
/**
 * Created by PhpStorm.
 * User: Dennis Ziolkowski
 * Date: 15.06.2017
 * Time: 03:04
 */

namespace Bitrix24;


class Bitrix24SessionData {
	public $accessToken;
	public $refreshToken;
	public $memberId;
	
	/**
	 * Bitrix24SessionData constructor.
	 *
	 * @param $accessToken
	 * @param $refreshToken
	 * @param $memberId
	 */
	public function __construct($accessToken, $refreshToken, $memberId) {
		$this->accessToken = $accessToken;
		$this->refreshToken = $refreshToken;
		$this->memberId = $memberId;
	}
	
	
}