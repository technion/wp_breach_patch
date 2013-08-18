<?php
/*
Plugin Name: wp_breach_protect
Plugin URI: http://www.lolware.net
Description: Activates mitigation against the BREACH SSL attack
Version: 1.0
Author: Technion
Author URI: https://github.com/technion/wp_breach_patch
License: BSD
*/

define(PADLEN, '8');

if ( !function_exists('wp_verify_nonce') ) :
/**
 * Verify that correct nonce was used with time limit.
 *
 * The user is given an amount of time to use the token, so therefore, since the
 * UID and $action remain the same, the independent variable is the time.
 *
 * @since 2.0.3
 *
 * @param string $nonce Nonce that was used in the form to verify
 * @param string|int $action Should give context to what is taking place and be the same when nonce was created.
 * @return bool Whether the nonce check passed or failed.
 */
function wp_verify_nonce($nonce, $action = -1) {

	/* This segment of code reverses the functionality added 
	* to wp_create_nonce
	hex2bin no longer exists... WTF????? 
	*/

	$padstr = substr($nonce, 0, PADLEN);
	$nonce = substr($nonce, PADLEN);
	//error_log( "Read nonce was " . $nonce);
	$nonce = pack("H*", $nonce); 
	
	//error_log(" Decoded that nonce to " . $nonce); 

        for($i=0;$i<strlen($nonce);$i++)
        {
                $nonce{$i} = $nonce{$i} ^ $padstr{$i%PADLEN};
        }


	//error_log("Decrypted nonce was " . $nonce); 

	$user = wp_get_current_user();
	$uid = (int) $user->ID;
	if ( ! $uid )
		$uid = apply_filters( 'nonce_user_logged_out', $uid, $action );

	$i = wp_nonce_tick();

	// Nonce generated 0-12 hours ago
	if ( substr(wp_hash($i . $action . $uid, 'nonce'), -12, 10) === $nonce )
		return 1;
	// Nonce generated 12-24 hours ago
	if ( substr(wp_hash(($i - 1) . $action . $uid, 'nonce'), -12, 10) === $nonce )
		return 2;
	// Invalid nonce
	return false;
}
endif;

if ( !function_exists('wp_create_nonce') ) :
/**
 * Creates a random, one time use token.
 *
 * @since 2.0.3
 *
 * @param string|int $action Scalar value to add context to the nonce.
 * @return string The one use form token
 */
function wp_create_nonce($action = -1) {
	$user = wp_get_current_user();
	$uid = (int) $user->ID;
	if ( ! $uid )
		$uid = apply_filters( 'nonce_user_logged_out', $uid, $action );

	$i = wp_nonce_tick();

	$padstr = substr(wp_hash(time(), 'nonce'), 0, PADLEN);

	$thenonce = substr(wp_hash($i . $action . $uid, 'nonce'), -12, 10);
	//error_log("Created a nonce " . $thenonce);

	for($i=0;$i<strlen($thenonce);$i++)
	{
		$thenonce{$i} = $thenonce{$i} ^ $padstr{$i%PADLEN};
 	}
	
	//error_log("Encrypted that to nonce " . $thenonce);
	$retstr = $padstr . bin2hex($thenonce);
	//error_log("Encoded that to nonce " . $retstr);
	return $retstr;
}
endif;

