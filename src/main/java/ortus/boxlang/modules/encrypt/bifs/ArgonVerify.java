
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

import de.mkammerer.argon2.Argon2Factory;
import de.mkammerer.argon2.Argon2Factory.Argon2Types;
import ortus.boxlang.modules.encrypt.types.EncryptKeys;
import ortus.boxlang.runtime.bifs.BIF;
import ortus.boxlang.runtime.bifs.BoxBIF;
import ortus.boxlang.runtime.context.IBoxContext;
import ortus.boxlang.runtime.dynamic.casters.KeyCaster;
import ortus.boxlang.runtime.scopes.ArgumentsScope;
import ortus.boxlang.runtime.scopes.Key;
import ortus.boxlang.runtime.types.Argument;
import ortus.boxlang.runtime.types.exceptions.BoxRuntimeException;

@BoxBIF
@BoxBIF( alias = "Argon2CheckHash" )

public class ArgonVerify extends BIF {

	/**
	 * Constructor
	 */
	public ArgonVerify() {
		super();
		// Uncomment and define declare argument to this BIF
		declaredArguments = new Argument[] {
		    new Argument( true, "string", Key.input ),
		    new Argument( true, "string", EncryptKeys.hashed ),
		    new Argument( false, "string", Key.variant )
		};
	}

	/**
	 * Performs a Argon2 verification on the given string against the hashed value.
	 *
	 * @param context   The context in which the BIF is being invoked.
	 * @param arguments Argument scope for the BIF.
	 *
	 * @argument.input The string to verify against the hash.
	 * 
	 * @argument.hashed The hashed value to verify against.
	 * 
	 * @argument.variant The variant of Argon2 to use. If not provided the hashed value will be tested to determine the variant.
	 */
	public Object _invoke( IBoxContext context, ArgumentsScope arguments ) {
		String	input	= arguments.getAsString( Key.input );
		String	hashed	= arguments.getAsString( EncryptKeys.hashed );
		String	variant	= arguments.getAsString( Key.variant );
		if ( variant == null ) {
			StringBuilder variantBuilder = new StringBuilder();
			for ( int i = 0, n = hashed.length(); i < n; i++ ) {
				char c = hashed.charAt( i );
				if ( i == 0 && c != '$' ) {
					throw new BoxRuntimeException( "The format of passed Argon2 hash string is incorrect" );
				}
				if ( i > 0 && c == '$' ) {
					break;
				}
				if ( i > 0 ) {
					variantBuilder.append( c );
				}
			}
			String	foundVariant	= variantBuilder.toString();
			int		found			= ArgonHash.ACCEPTED_VARIANTS.indexOf( Key.of( foundVariant ) );

			if ( found != -1 ) {
				variant = KeyCaster.cast( ArgonHash.ACCEPTED_VARIANTS.get( found ) ).getName();
			} else {
				throw new BoxRuntimeException( "Invalid Argon2 variant: " + foundVariant );
			}

		}
		if ( variant != null && !ArgonHash.ACCEPTED_VARIANTS.contains( Key.of( variant ) ) ) {
			throw new BoxRuntimeException( "Invalid Argon2 variant: " + variant );
		}

		return Argon2Factory.create( Argon2Types.valueOf( variant ) ).verify( hashed, input.toCharArray() );
	}

}
