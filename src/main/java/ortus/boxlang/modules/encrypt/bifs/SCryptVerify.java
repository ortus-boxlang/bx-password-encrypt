
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

import com.lambdaworks.crypto.SCryptUtil;

import ortus.boxlang.modules.encrypt.types.EncryptKeys;
import ortus.boxlang.runtime.bifs.BIF;
import ortus.boxlang.runtime.bifs.BoxBIF;
import ortus.boxlang.runtime.context.IBoxContext;
import ortus.boxlang.runtime.scopes.ArgumentsScope;
import ortus.boxlang.runtime.scopes.Key;
import ortus.boxlang.runtime.types.Argument;

@BoxBIF

public class SCryptVerify extends BIF {

	/**
	 * Constructor
	 */
	public SCryptVerify() {
		super();
		declaredArguments = new Argument[] {
		    new Argument( true, "string", Key.string ),
		    new Argument( true, "string", EncryptKeys.hashed )
		};
	}

	/**
	 * Performs a verification of a supplied plaintext string against a hashed value.
	 *
	 * @param context   The context in which the BIF is being invoked.
	 * @param arguments Argument scope for the BIF.
	 *
	 * @argument.string The plaintext string to verify against the hashed value.
	 * 
	 * @argument.hashed The SCrypt hashed value to verify against.
	 */
	public Object _invoke( IBoxContext context, ArgumentsScope arguments ) {
		return SCryptUtil.check( arguments.getAsString( Key.string ), arguments.getAsString( EncryptKeys.hashed ) );
	}

}
