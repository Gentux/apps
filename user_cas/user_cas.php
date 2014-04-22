<?php

/**
 * ownCloud - user_cas
 *
 * @author Sixto Martin <sixto.martin.garcia@gmail.com>
 * @copyright Sixto Martin Garcia. 2012
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU AFFERO GENERAL PUBLIC LICENSE
 * License as published by the Free Software Foundation; either
 * version 3 of the License, or any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU AFFERO GENERAL PUBLIC LICENSE for more details.
 *
 * You should have received a copy of the GNU Affero General Public
 * License along with this library.  If not, see <http://www.gnu.org/licenses/>.
 *
 */


require_once('lib/ldap_backend_adapter.php');


class OC_USER_CAS extends OC_User_Backend {

	// cached settings
	public $autocreate;
	public $updateUserData;
	public $protectedGroups;
	public $defaultGroup;
	public $mailMapping;
	public $groupMapping;

	public function __construct() {

		$this->autocreate = OCP\Config::getAppValue('user_cas', 'cas_autocreate', false);
		$this->cas_link_to_ldap_backend = \OCP\Config::getAppValue('user_cas', 'cas_link_to_ldap_backend', false);
		$this->updateUserData = OCP\Config::getAppValue('user_cas', 'cas_update_user_data', false);
		$this->defaultGroup = OCP\Config::getAppValue('user_cas', 'cas_default_group', '');
		$this->protectedGroups = explode (',', str_replace(' ', '', OCP\Config::getAppValue('user_cas', 'cas_protected_groups', '')));
		$this->mailMapping = OCP\Config::getAppValue('user_cas', 'cas_email_mapping', '');
		$this->groupMapping = OCP\Config::getAppValue('user_cas', 'cas_group_mapping', '');

		$casVersion = OCP\Config::getAppValue('user_cas', 'cas_server_version', '1.0');
		$casHostname = OCP\Config::getAppValue('user_cas', 'cas_server_hostname', '');
		$casPort = OCP\Config::getAppValue('user_cas', 'cas_server_port', '443');
		$casPath = OCP\Config::getAppValue('user_cas', 'cas_server_path', '/cas');
		$casCertPath = OCP\Config::getAppValue('user_cas', 'cas_cert_path', '');

		if (!empty($casHostname)) {
			global $initialized_cas;

			if(!$initialized_cas) {

				# phpCAS::setDebug();

				phpCAS::client($casVersion,$casHostname,(int)$casPort,$casPath,false);

				if(!empty($casCertPath)) {
					phpCAS::setCasServerCACert($casCertPath);
				}
				else {
					phpCAS::setNoCasServerValidation();
				}
				$initialized_cas = true;
			}
		}
	}


	public function checkPassword($uid, $password) {

		if(!phpCAS::isAuthenticated()) {
			return false;
		}

		//distinguish between internal and external Shibboleth users
		//internal users log in with their LDAP (entry)uuid,
		$adapter = new LdapBackendAdapter();
		$uid = phpCAS::getUser();

		if ($this->cas_link_to_ldap_backend) {
			$ocname = $adapter->getUuid($uid);

			if (($uid !== false) && ($ocname !== false)) {
				return $ocname;
			}
		} else {
			//external users log in with their hashed persistentID
			return $uid;
		}
	}


	public function userExists($uid) {

		if(!phpCAS::isAuthenticated()) {
			return false;
		}

		if ($this->cas_link_to_ldap_backend) {
			$adapter = new LdapBackendAdapter();
			return (phpCAS::getUser() == $uid && $adapter->uuidExists($uid));
		} else {
			return (phpCAS::getUser() == $uid);
		}
	}
}
