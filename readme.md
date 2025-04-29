# ⚡︎ BoxLang Module: Password Encryption

```
|:------------------------------------------------------:|
| ⚡︎ B o x L a n g ⚡︎
| Dynamic : Modular : Productive
|:------------------------------------------------------:|
```

<blockquote>
	Copyright Since 2023 by Ortus Solutions, Corp
	<br>
	<a href="https://www.boxlang.io">www.boxlang.io</a> |
	<a href="https://www.ortussolutions.com">www.ortussolutions.com</a>
</blockquote>

<p>&nbsp;</p>

This module provides password encryption and hashing functionality to Boxlang


It contributes the following Built-in-Functions to the language:

* `ArgonHash`: Returns a secure input hash of the given string using the Argon2 hashing algorithm. ( Alias: `GenerateArgon2Hash` )
* `ArgonVerify`: Performs a Argon2 verification on the given string against the hashed value. ( Alias: `Argon2CheckHash` )
* `BCryptHash`: Returns a secure input hash of the given string using the BCrypt hashing algorithm.( Alias: `GenerateBCryptHash` )
* `BCryptVerify`: Performs a BCrypt verification on the given string against the hashed value. ( Alias: `VerifyBCryptHash` )
* `SCryptHash`: Returns a secure input hash of the given string using the SCrypt hashing algorithm.( Alias: `GenerateSCryptHash` )
* `SCryptVerify`: Performs a SCrypt verification on the given string against the hashed value. ( Alias: `VerifySCryptHash` )
* `GeneratePBKDFKey`: Generates a PDFK key from the given password and salt.
