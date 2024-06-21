
/**
 * [BoxLang]
 *
 * Copyright [2023] [Ortus Solutions, Corp]
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package ortus.boxlang.modules.encrypt.bifs;

import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.Set;

import com.lambdaworks.codec.Base64;
import com.lambdaworks.crypto.SCrypt;

import ortus.boxlang.modules.encrypt.types.EncryptKeys;
import ortus.boxlang.runtime.bifs.BIF;
import ortus.boxlang.runtime.bifs.BoxBIF;
import ortus.boxlang.runtime.context.IBoxContext;
import ortus.boxlang.runtime.scopes.ArgumentsScope;
import ortus.boxlang.runtime.scopes.Key;
import ortus.boxlang.runtime.types.Argument;
import ortus.boxlang.runtime.types.exceptions.BoxRuntimeException;
import ortus.boxlang.runtime.validation.Validator;

@BoxBIF
@BoxBIF( alias = "GenerateSCryptHash" )

public class SCryptHash extends BIF {

	/**
	 * Constructor
	 */
	public SCryptHash() {
		super();
		declaredArguments = new Argument[] {
		    new Argument( true, "string", Key.input ),
		    new Argument( false, "integer", EncryptKeys.saltLength, 8, Set.of( Validator.min( 8 ) ) ),
		    new Argument( false, "integer", EncryptKeys.parallelism, 1, Set.of( Validator.min( 1 ), Validator.max( 10 ) ) ),
		    new Argument( false, "integer", EncryptKeys.keySize, 32, Set.of( Validator.min( 32 ) ) ),
		    new Argument( false, "integer", EncryptKeys.memory, 8, Set.of( Validator.min( 2 ) ) ),
		    new Argument( false, "integer", EncryptKeys.cpuCost, 16384, Set.of( Validator.min( 2 ) ) ),
		};
	}

	/**
	 * Returns a secure input hash of the given string using the Argon2 hashing algorithm.
	 *
	 * @param context   The context in which the BIF is being invoked.
	 * @param arguments Argument scope for the BIF.
	 *
	 * @argument.input The string to perform secure hashing upon.
	 * 
	 * @argument.saltLength The length of the salt to use in the hashing algorithm. Must be greated than 8.
	 * 
	 * @argument.parallelism The number of threads to use in the hashing algorithm. Must be between 1 and 10.
	 * 
	 * @argument.keySize The size of the key to use in the hashing algorithm. Must be greater than 32.
	 * 
	 * @argument.memory The amount of memory to use in the hashing algorithm. Must be between 8 and 100000.
	 * 
	 * @argument.cpuCost The CPU cost to use in the hashing algorithm. Must be greater than 2 and be a power off 2
	 */
	public Object _invoke( IBoxContext context, ArgumentsScope arguments ) {

		try {
			byte[] salt = new byte[ arguments.getAsInteger( EncryptKeys.saltLength ) ];
			SecureRandom.getInstance( "SHA1PRNG" ).nextBytes( salt );

			byte[]			result		= SCrypt.scrypt(
			    arguments.getAsString( Key.input ).getBytes(),
			    salt,
			    arguments.getAsInteger( EncryptKeys.cpuCost ),
			    arguments.getAsInteger( EncryptKeys.memory ),
			    arguments.getAsInteger( EncryptKeys.parallelism ),
			    arguments.getAsInteger( EncryptKeys.keySize )
			);

			// The ScryptUtil class in the lambdaworks-crypto library does not allow for the key length argument so we have to manually build the response from
			// our raw byte array

			StringBuilder	response	= new StringBuilder( ( arguments.getAsInteger( EncryptKeys.saltLength ) + result.length ) * 2 );
			String			params		= Long.toString( log2( arguments.getAsInteger( EncryptKeys.cpuCost ) ) << 16L
			    | arguments.getAsInteger( EncryptKeys.memory ) << 8 | arguments.getAsInteger( EncryptKeys.parallelism ), 16 );
			response.append( "$s0$" ).append( params ).append( '$' );
			response.append( Base64.encode( salt ) ).append( '$' );
			response.append( Base64.encode( result ) );

			return response.toString();
		} catch ( GeneralSecurityException e ) {
			throw new BoxRuntimeException( "An exception occurred while performing the function SCryptHash: " + e.getMessage(), e );
		}
	}

	private static int log2( int n ) {
		int log = 0;
		if ( ( n & 0xffff0000 ) != 0 ) {
			n	>>>= 16;
			log	= 16;
		}
		if ( n >= 256 ) {
			n	>>>= 8;
			log	+= 8;
		}
		if ( n >= 16 ) {
			n	>>>= 4;
			log	+= 4;
		}
		if ( n >= 4 ) {
			n	>>>= 2;
			log	+= 2;
		}
		return log + ( n >>> 1 );
	}

}
