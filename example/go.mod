module github.com/chmike/csrftoken/example

go 1.22

require (
	github.com/chmike/csrftoken v0.0.0
	github.com/chmike/securecookie/v2 v2.0.1
)

// Use the csrftoken package of the parent directory. Remove this line to
// use a published version.
replace github.com/chmike/csrftoken => ../
