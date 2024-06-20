
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

import org.mindrot.jbcrypt.BCrypt;

import ortus.boxlang.modules.encrypt.types.EncryptKeys;
import ortus.boxlang.runtime.bifs.BIF;
import ortus.boxlang.runtime.bifs.BoxBIF;
import ortus.boxlang.runtime.context.IBoxContext;
import ortus.boxlang.runtime.scopes.ArgumentsScope;
import ortus.boxlang.runtime.scopes.Key;
import ortus.boxlang.runtime.types.Argument;
import ortus.boxlang.runtime.validation.Validator;

@BoxBIF
@BoxBIF( alias = "GenerateBCryptHash" )

public class BCryptHash extends BIF {

	/**
	 * Constructor
	 */
	public BCryptHash() {
		super();
		declaredArguments = new Argument[] {
		    new Argument( true, "string", Key.input ),
		    new Argument( false, "integer", EncryptKeys.iterations, Set.of( Validator.min( 5 ), Validator.max( 10 ) ) )
		};
	}

	/**
	 * Performs a BCrypt hash on the given string.
	 *
	 * @param context   The context in which the BIF is being invoked.
	 * @param arguments Argument scope for the BIF.
	 *
	 * @argument.input The string to perform secure hashing upon.
	 * 
	 * @argument.iterations The number of iterations to use in the hashing algorithm. Must be a multiple of 2 and between 2 and 30.
	 *                      Note that a high number of iterations can take _days_ to complete
	 */
	public Object _invoke( IBoxContext context, ArgumentsScope arguments ) {
		String	string	= arguments.getAsString( Key.input );
		String	salt;
		if ( arguments.get( EncryptKeys.iterations ) != null ) {
			salt = BCrypt.gensalt( arguments.getAsInteger( EncryptKeys.iterations ) );
		} else {
			salt = BCrypt.gensalt();
		}

		return BCrypt.hashpw( string, salt );
	}

}
