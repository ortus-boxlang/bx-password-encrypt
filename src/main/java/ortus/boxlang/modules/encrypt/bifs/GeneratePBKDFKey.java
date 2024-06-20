
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

import java.util.Base64;
import java.util.Set;

import de.mkammerer.argon2.Argon2Advanced;
import de.mkammerer.argon2.Argon2Factory;
import de.mkammerer.argon2.Argon2Factory.Argon2Types;
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

public class GeneratePBKDFKey extends BIF {

	/**
	 * Constructor
	 */
	public GeneratePBKDFKey() {
		super();
		declaredArguments = new Argument[] {
		    new Argument( true, "string", Key.password ),
		    new Argument( true, "string", EncryptKeys.salt ),
		    new Argument( false, "integer", EncryptKeys.iterations, 4096 ),
		    new Argument( false, "integer", EncryptKeys.keySize, 128 ),
		    new Argument( false, "integer", EncryptKeys.parallelism, 1, Set.of( Validator.min( 1 ), Validator.max( 10 ) ) ),
		    new Argument( false, "integer", EncryptKeys.memory, 8, Set.of( Validator.min( 8 ), Validator.max( 100000 ) ) ),
		    new Argument( false, "string", Key.variant, "ARGON2i" )
		};
	}

	/**
	 * Generates a PDFK key from the given password and salt.
	 *
	 * @param context   The context in which the BIF is being invoked.
	 * @param arguments Argument scope for the BIF.
	 *
	 * @argument.password The password to generate the key from.
	 * 
	 * @argument.salt The salt to use in the key generation.
	 * 
	 * @argument.iterations (Optional) The number of iterations to use in the hashing algorithm. The default is 4096
	 * 
	 * @argument.keySize (Optional) The size of the key to generate. The default is 128
	 * 
	 * @argument.parallelism (Optional) The number of threads to use in the hashing algorithm. The default is 1
	 * 
	 * @argument.memory (Optional) The amount of memory to use in the hashing algorithm. The default is 8
	 * 
	 * @argument.variant (Optional) The Argon2 variant to use. Defaults to "ARGON2i".
	 */
	public Object _invoke( IBoxContext context, ArgumentsScope arguments ) {
		// Handle Lucee's silly algorithm requirement
		if ( arguments.getAsString( Key.password ).equalsIgnoreCase( "PBKDF2WithHmacSHA1" ) ) {
			throw new BoxRuntimeException(
			    "The algorithm parameter to the function is no longer required, as the PBKDF2WithHmacSHA1 standard is implicit.  Please remove this argument." );
		}

		String variant = arguments.getAsString( Key.variant );
		if ( !ArgonHash.ACCEPTED_VARIANTS.contains( Key.of( variant ) ) ) {
			throw new BoxRuntimeException( "Invalid Argon2 variant: " + variant );
		}

		Argon2Advanced argon2 = Argon2Factory.createAdvanced( Argon2Types.valueOf( arguments.getAsString( Key.variant ) ) );

		return Base64.getEncoder().encodeToString(
		    argon2.pbkdf(
		        arguments.getAsInteger( EncryptKeys.iterations ),
		        arguments.getAsInteger( EncryptKeys.memory ),
		        arguments.getAsInteger( EncryptKeys.parallelism ),
		        arguments.getAsString( Key.password ).getBytes(),
		        arguments.getAsString( EncryptKeys.salt ).getBytes(),
		        arguments.getAsInteger( EncryptKeys.keySize )
		    )
		);
	}

}
