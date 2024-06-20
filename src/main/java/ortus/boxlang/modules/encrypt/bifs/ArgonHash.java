
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

import java.util.Set;
import java.util.stream.Stream;

import de.mkammerer.argon2.Argon2;
import de.mkammerer.argon2.Argon2Factory;
import de.mkammerer.argon2.Argon2Factory.Argon2Types;
import ortus.boxlang.modules.encrypt.types.EncryptKeys;
import ortus.boxlang.runtime.bifs.BIF;
import ortus.boxlang.runtime.bifs.BoxBIF;
import ortus.boxlang.runtime.context.IBoxContext;
import ortus.boxlang.runtime.scopes.ArgumentsScope;
import ortus.boxlang.runtime.scopes.Key;
import ortus.boxlang.runtime.types.Argument;
import ortus.boxlang.runtime.types.Array;
import ortus.boxlang.runtime.types.exceptions.BoxRuntimeException;
import ortus.boxlang.runtime.validation.Validator;

@BoxBIF
@BoxBIF( alias = "GenerateArgon2Hash" )

public class ArgonHash extends BIF {

	public static final Array ACCEPTED_VARIANTS = new Array();
	static {
		Stream.of( Argon2Types.values() ).map( type -> Key.of( type ) ).forEach( ACCEPTED_VARIANTS::add );
	}

	/**
	 * Constructor
	 */
	public ArgonHash() {
		super();
		declaredArguments = new Argument[] {
		    new Argument( true, "string", Key.input ),
		    new Argument( false, "string", Key.variant, "ARGON2i" ),
		    new Argument( false, "integer", EncryptKeys.parallelism, 1, Set.of( Validator.min( 1 ), Validator.max( 10 ) ) ),
		    new Argument( false, "integer", EncryptKeys.memory, 8, Set.of( Validator.min( 8 ), Validator.max( 100000 ) ) ),
		    new Argument( false, "integer", EncryptKeys.iterations, 8, Set.of( Validator.min( 1 ), Validator.max( 20 ) ) ),
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
	 * @argument.variant The Argon2 variant to use. Defaults to "ARGON2i".
	 * 
	 * @argument.parallelism The number of threads to use in the hashing algorithm. Must be between 1 and 10.
	 * 
	 * @argument.memory The amount of memory to use in the hashing algorithm. Must be between 8 and 100000.
	 * 
	 * @argument.iterations The number of iterations to use in the hashing algorithm. Must be between 1 and 20.
	 */
	public Object _invoke( IBoxContext context, ArgumentsScope arguments ) {
		String	input		= arguments.getAsString( Key.input );
		Key		variantKey	= Key.of( arguments.getAsString( Key.variant ) );
		System.out.println( ACCEPTED_VARIANTS.asString() );
		if ( !ACCEPTED_VARIANTS.contains( variantKey ) ) {
			throw new BoxRuntimeException( "Invalid Argon2 variant: " + arguments.getAsString( Key.variant ) );
		}
		Argon2Types	variant	= Argon2Types.valueOf( arguments.getAsString( Key.variant ) );
		Argon2		argon2	= Argon2Factory.create( variant );

		return argon2.hash(
		    arguments.getAsInteger( EncryptKeys.iterations ),
		    arguments.getAsInteger( EncryptKeys.memory ),
		    arguments.getAsInteger( EncryptKeys.parallelism ),
		    input.toCharArray()
		);
	}

}
