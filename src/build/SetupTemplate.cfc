/**
 * Setup the Module Template according to your needs
 */
component {

	/**
	 * Constructor
	 */
	function init(){
		// Setup Pathing
		variables.cwd = getCWD().reReplace( "\.$", "" );
		return this;
	}

	/**
	 * Setup the module template
	 */
	function run(){

		// remove old .git
		//directoryDelete( variables.cwd & ".git", true );

		// Create new git repo
		//command( "!git init" ).run();

		var moduleName = ask( "What is the human readable name of your module?" );
		if( !len( moduleName ) ){
			error( "Module Name is required" );
		}

		var moduleRegisteredName = ask( "What is the name this module should be registered as by the BoxLang runtime?" );
		if( !len( moduleRegisteredName ) ){
			error( "Module Registration name is required" );
		}

		var moduleSlug = ask( "What is the slug for your module?" );
		if( !len( moduleSlug ) ){
			error( "Module Slug is required" );
		}
		var moduleDescription = ask( "Short description of your module?" );
		if( !len( moduleDescription ) ){
			error( "Module Description is required" );
		}

		command( "tokenReplace" )
			.params(
				path        = "/#variables.cwd#/**",
				token       = "Encryption",
				replacement = moduleName
			)
			.run();

		command( "tokenReplace" )
			.params(
				path        = "/#variables.cwd#/**",
				token       = "encrypt",
				replacement = moduleRegisteredName
			)
			.run();

		command( "tokenReplace" )
			.params(
				path        = "/#variables.cwd#/**",
				token       = "bx-password-encrypt",
				replacement = moduleSlug
			)
			.run();

		command( "tokenReplace" )
			.params(
				path        = "/#variables.cwd#/**",
				token       = "Enables Encryption and Cryptography functionality for the BoxLang Runtime",
				replacement = moduleDescription
			)
			.run();

		// Finalize Message
		print
			.line()
			.boldMagentaLine( "Your module template is now ready for development! Just add the github origin, commit some code and Go rock it!" )
			.toConsole();
	}

}
