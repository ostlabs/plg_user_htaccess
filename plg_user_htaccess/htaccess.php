<?php
/**
 * @copyright	Copyright (C) 2010 OSTLabs Inc. All rights reserved.
 * @license		GNU/GPL, see LICENSE.php
 * Joomla! is free software. This version may have been modified pursuant
 * to the GNU General Public License, and as distributed it includes or
 * is derivative of works licensed under the GNU General Public License or
 * other free or open source software licenses.
 * See COPYRIGHT.php for copyright notices and details.

 * Some functions (these are private and identifed starting with _ and marked with *** ) are user/modified from http://elonen.iki.fi/code/misc-notes/htpasswd-php/
 * .htpasswd file functions
 * Copyright (C) 2004,2005 Jarno Elonen <elonen@iki.fi>

 */

// Check to ensure this file is included in Joomla!
defined('_JEXEC') or die( 'Restricted access' );

jimport('joomla.plugin.plugin');

class plgUserHTAccess extends JPlugin {

	function plgUserHTAccess(& $subject, $config)
	{
		parent::__construct($subject, $config);
	}

	function onAfterStoreUser($user, $isnew, $success, $msg)
	{

		switch ($this->params->get('encryption')) {
		    case 1: // Crypt
			$password = $this->_rand_salt_crypt($user['password_clear']);
			break;

		    case 2: // SHA1
			$password = $this->_non_salted_sha1($user['password_clear']);
			break;

		    case 3: // Salted SHA1
			$password = $this->_rand_salt_sha1($user['password_clear']);
			break;
		}

		// Open the .htaccess file and  Read in the contents
		$htusers = $this->_open_htaccess_file();

		// Add the user
		if ($this->params->get('AutoAdd') || (!$this->params->get('AutoAdd') && isset ($htusers[$user['username']]))) {
			$htusers[$user['username']] = $password;
		}

		// Save the file
		$this->_save_htpasswd($htusers);
	}

	function onAfterDeleteUser($user, $succes, $msg)
	{
		// Open the .htaccess file and  Read in the contents
		$htusers = $this->_open_htaccess_file();

		// If the delete option is set, unset the user
		if ($this->params->get('AutoDelete')) {
		    unset ($htusers[$user['username']]);
		}

		// Save the file
		$this->_save_htpasswd($htusers);

	}

	// Function will open the htaccess file and return an array of users/passwords

	function _open_htaccess_file () // *** See Copyright above
	{

	  $file = $this->params->get('htaccess_path');

	  if ( !file_exists($file))
	      return Array();

	  $res = Array();
	  foreach(file($file) as $l)
	  {
	    $array = explode(':',$l);
	    $user = $array[0];
	    $pass = chop($array[1]);
	    $res[$user] = $pass;
	  }
	  return $res;
	}

	function _save_htpasswd( $pass_array )
	{
	  $file = $this->params->get('htaccess_path');
	  $result = true;

	  ignore_user_abort(true);
	  $fp = fopen($file, "w+");
	  if (flock($fp, LOCK_EX))
	  {
	    while( list($u,$p) = each($pass_array))
	      fputs($fp, "$u:$p\n");

	    flock($fp, LOCK_UN); // release the lock
	  }
	  else
	  {
	    trigger_error("Could not save (lock) .htpasswd", E_USER_WARNING);
	    $result = false;
	  }
	  fclose($fp);
	  ignore_user_abort(false);
	  return $result;
	}

	function _non_salted_sha1( $pass )  // *** See Copyright above
	{
	  return "{SHA}" . base64_encode(pack("H*", sha1($pass)));
	}

	function _rand_salt_sha1( $pass )   // *** See Copyright above
	{
	  mt_srand((double)microtime()*1000000);
	  $salt = pack("CCCC", mt_rand(), mt_rand(), mt_rand(), mt_rand());
	  return "{SSHA}" . base64_encode(pack("H*", sha1($pass . $salt)) . $salt);
	}

	function _rand_salt_crypt( $pass )  // *** See Copyright above
	{
	  $salt = "";
	  mt_srand((double)microtime()*1000000);
	  for ($i=0; $i<CRYPT_SALT_LENGTH; $i++)
	    $salt .= substr("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789./", mt_rand() & 63, 1);
	  return crypt($pass, $salt);
	}



}
