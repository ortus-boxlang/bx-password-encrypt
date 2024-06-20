package ortus.boxlang.modules.encrypt.types;

import ortus.boxlang.runtime.scopes.Key;

public class EncryptKeys {

	public static final Key	salt		= Key.of( "salt" );
	public static final Key	rounds		= Key.of( "rounds" );
	public static final Key	iterations	= Key.of( "iterations" );
	public static final Key	hashed		= Key.of( "hashed" );
	public static final Key	parallelism	= Key.of( "parallelism" );
	public static final Key	memory		= Key.of( "memory" );
	public static final Key	keySize		= Key.of( "keySize" );
}
