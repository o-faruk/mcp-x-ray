package rules

// Default returns the production rule set. See docs/owasp-mapping.md for
// what each rule detects and why it's mapped to its OWASP ASI category.
func Default() *Registry {
	return NewRegistry(
		ConcealmentRule{},
		CredentialHarvestingRule{},
		ExfiltrationEndpointRule{},
		ShadowingRule{},
		ExcessiveCapabilityRule{},
		TyposquatRule{},
		HiddenContentRule{},
	)
}
