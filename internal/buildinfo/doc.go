// Package buildinfo exists to hold the test that keeps the project's version
// number from drifting between the places that carry it.
//
// There is no production code here on purpose: the check needs to import both
// internal/client and internal/server to read their constants, and neither of
// them should import the other.
package buildinfo
