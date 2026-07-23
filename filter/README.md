# go-ldapfilter

Package filter implements [RFC4515](https://www.rfc-editor.org/info/rfc4515/) search filters.

## Features

 - Interface-based `Filter` type, qualified through instances of `FilterAnd`, `FilterExtensibleMatch`, et al
 - 100% test coverage
 - Panic-proof indexing
 - Supports creation of search filters by text parsing or manual type instance assembly

