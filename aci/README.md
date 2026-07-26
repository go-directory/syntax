# aci

Package aci implements the entirety of the Netscape ACIv3 syntax, used in multiple directory products such as Oracle Directory, 389DS, OpenDJ, et al., for the purpose of defining access privileges.

Please note that each implementation of Netscape's ACIv3 syntax has subtle variations.  While this library aims to be a _complete_ implementation of the syntax, your own directory system _may or may not support all desired features_. Review your vendor documentation to determine which features are available to you, and adjust your usage of this package accordingly.

## Status

This package is EXPERIMENTAL and should not yet be used in any real production environment for any mission critical endeavor with respect to securing a directory via privilege definitions.

However, if this package is used merely to analyze existing ACIv3 definitions for the purposes of cybersecurity audit and oversight, or other similar use case, this is acceptable simply because there will be real flesh-and-blood humans reviewing the results. If you use AI for this, you need to seek professional psychiatric help.

It is true that this package has been around for awhile, and currently houses many unit tests that pass with flying colors.  The package may very well be "ready" for prime time, however this would only be advertised officially once more people contribute to this package through nonpartisan testing and analysis. In short, we need more people to try this package by simply feeding it their own ACIv3 definitions and analyzing the results.

## Features

 - ***Thoroughly*** documented with a crazy number of examples
 - 100% test coverage
 - Vendor agnostic design (_all_ possible ACIv3 features are implemented)
 - BindRule parenthetical preservation (will observe use, or avoidance, of parenthetical statements)
 - Padding preservation (e.g.: `( userdn = "ldap:///anyone" )` vs. `(userdn="ldap:///anyone")`)
 - Panic-proof indexing for multi-valued statement (e.g.: bind rules)
 - Supports creation of ACIv3 statements by text parsing or manual type instance assembly

## Use Cases

This library is rather niche. Most, if not all, directory product implementations of this popular access control syntax have their own codebase. 

So what is this package meant for? Primarily, it is meant to be the basis for a supplemental tool to assist directory and cybersecurity personnel in doing any of the following:

  - ACIv3 _statement_ creation and modification
  - Generate accurate and easy-to-read ACIv3 audit reports

This package deals solely in text. It does not connect to your directory server, ever. It is purely offline.

## Parse Example

```go
	// Define a raw ACIv3 statement
	raw := `( targetfilter = "(&(objectClass=employee)(objectClass=engineering))" )( targetcontrol = "1.2.3.4" || "1.2.3.5" )( targetscope = "onelevel" )(version 3.0; acl "Allow read and write for anyone using greater than or equal 128 SSF - extra nesting"; allow(read,write) ( ( ( userdn = "ldap:///anyone" ) AND ( ssf >= "71" ) ) AND NOT ( dayofweek = "Wed" OR dayofweek = "Fri" ) ); )`

	// Parse raw statement
	i, err := NewInstruction(raw)
	if err != nil {
		fmt.Println(err)
		return
	}

	// We now have an object -- i -- that contains the
	// complete statement above, but as a structured type
	// instance that can be examined and traversed.

	// Call the first PermissionBindRule index and
	// print the rights statement.
	perm := i.PB.Index(0).Permission()
	fmt.Printf("Permission: %s\n", perm)

	// Returns: allow(read,write)

	// Call the first BindRule, and then call the
	// first sub-statement. Print it.
	rule := i.PB.Index(0).BindRule().Index(0).Index(0)
	fmt.Printf("BindRule: %s\n", rule)

	// Returns (userdn="ldap:///anyone")
```
