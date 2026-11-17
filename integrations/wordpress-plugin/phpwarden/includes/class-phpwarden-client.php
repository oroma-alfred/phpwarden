<?php
/**
 * HTTP client and sync routine.
 *
 * @package PHPWarden
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Talks to the phpwarden API (POST /v1/inventory, POST /v1/commands/<id>/result).
 */
class PHPWarden_Client {

	const LOCK = 'phpwarden_sync_lock';

	/**
	 * Send the inventory. Report only: anything else in the response is ignored.
	 *
	 * @param string $trigger cron|change|manual|cli (informational, stored in status).
	 * @return array Status as stored in the status option.
	 */
	public static function sync( $trigger = 'cron' ) {
		$token = PHPWarden_Settings::get_token();
		if ( '' === $token ) {
			return self::finish( $trigger, false, 0, __( 'No project token configured.', 'phpwarden' ) );
		}
		if ( get_transient( self::LOCK ) ) {
			return self::finish( $trigger, false, 0, __( 'A sync is already running.', 'phpwarden' ), false );
		}
		set_transient( self::LOCK, 1, 10 * MINUTE_IN_SECONDS );

		$body = PHPWarden_Inventory::encode( PHPWarden_Inventory::collect() );
		if ( false === $body ) {
			delete_transient( self::LOCK );
			return self::finish( $trigger, false, 0, __( 'Inventory is too large to send.', 'phpwarden' ) );
		}

		$response = self::post( '/v1/inventory', $body, $token );
		if ( ! $response['ok'] ) {
			delete_transient( self::LOCK );
			return self::finish( $trigger, false, $response['code'], $response['error'] );
		}
		$data   = $response['data'];
		$extra  = array(
			'stored'  => isset( $data['stored'] ) ? (int) $data['stored'] : 0,
			'exposed' => isset( $data['exposed'] ) ? (int) $data['exposed'] : 0,
			'kev'     => isset( $data['kev'] ) ? (int) $data['kev'] : 0,
		);
		$status = self::finish( $trigger, true, 200, '', true, $extra );

		delete_transient( self::LOCK );
		return $status;
	}

	/**
	 * POST JSON to the API.
	 *
	 * @param string $path  Path beginning with /v1/.
	 * @param string $json  Encoded body.
	 * @param string $token Project token.
	 * @return array { ok: bool, code: int, data: array, error: string }
	 */
	public static function post( $path, $json, $token ) {
		$response = wp_remote_post(
			PHPWarden_Settings::get_api_base() . $path,
			array(
				'timeout'     => 20,
				'redirection' => 0,
				'user-agent'  => 'phpwarden-wp/' . PHPWARDEN_VERSION,
				'headers'     => array(
					'Authorization' => 'Bearer ' . $token,
					'Content-Type'  => 'application/json',
					'Accept'        => 'application/json',
				),
				'body'        => $json,
				'data_format' => 'body',
			)
		);
		if ( is_wp_error( $response ) ) {
			return array(
				'ok'    => false,
				'code'  => 0,
				'data'  => array(),
				'error' => $response->get_error_message(),
			);
		}
		$code = (int) wp_remote_retrieve_response_code( $response );
		$data = json_decode( (string) wp_remote_retrieve_body( $response ), true );
		$data = is_array( $data ) ? $data : array();
		if ( 200 === $code && ! empty( $data['ok'] ) ) {
			return array(
				'ok'    => true,
				'code'  => $code,
				'data'  => $data,
				'error' => '',
			);
		}
		$error_code = isset( $data['error'] ) && is_string( $data['error'] ) ? sanitize_key( $data['error'] ) : '';
		return array(
			'ok'    => false,
			'code'  => $code,
			'data'  => $data,
			'error' => self::describe_error( $code, $error_code ),
		);
	}

	/**
	 * Human-readable error.
	 *
	 * @param int    $code  HTTP status.
	 * @param string $error Error code from the API.
	 * @return string
	 */
	private static function describe_error( $code, $error ) {
		switch ( $error ) {
			case 'invalid_token':
				return __( 'The project token was rejected. Check it in your phpwarden dashboard.', 'phpwarden' );
			case 'suspended':
				return __( 'This project is suspended.', 'phpwarden' );
			case 'too_large':
				return __( 'The report was too large for the server.', 'phpwarden' );
			case 'bad_json':
				return __( 'The server could not read the report.', 'phpwarden' );
		}
		/* translators: 1: HTTP status code, 2: error code. */
		return trim( sprintf( __( 'Unexpected response (HTTP %1$d) %2$s', 'phpwarden' ), $code, $error ) );
	}

	/**
	 * Build and (optionally) store the status.
	 *
	 * @param string $trigger Trigger.
	 * @param bool   $ok      Success.
	 * @param int    $code    HTTP status.
	 * @param string $message Message.
	 * @param bool   $store   Whether to persist.
	 * @param array  $extra   Extra fields (stored/exposed/kev).
	 * @return array
	 */
	private static function finish( $trigger, $ok, $code, $message, $store = true, array $extra = array() ) {
		$status = array_merge(
			array(
				'time'    => time(),
				'trigger' => sanitize_key( $trigger ),
				'ok'      => (bool) $ok,
				'code'    => (int) $code,
				'message' => sanitize_text_field( $message ),
			),
			$extra
		);
		if ( $store ) {
			if ( ! $ok ) {
				// Keep the counts from the last successful report visible.
				$previous = PHPWarden_Settings::get_status();
				foreach ( array( 'stored', 'exposed', 'kev', 'last_ok' ) as $key ) {
					if ( isset( $previous[ $key ] ) ) {
						$status[ $key ] = $previous[ $key ];
					}
				}
			} else {
				$status['last_ok'] = $status['time'];
			}
			PHPWarden_Settings::set_status( $status );
		}
		return $status;
	}
}
