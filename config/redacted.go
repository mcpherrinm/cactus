package config

// RedactedConfig is a public-safe view of Config, suitable for serving on the
// log's HTML index page. It is built by an *allowlist*: only fields that are
// neither secrets nor filesystem paths are copied across. A newly added field
// is therefore excluded by default — it has to be added here explicitly to be
// exposed — so a future secret can't leak by accident. Everything path-like is
// intentionally absent: data_dir, ca_cosigner.seed_path, acme.tls_cert /
// tls_key, every *.public_key_path / ca_cosigner_key_path, mirror.seed_path.
//
// Internal bind addresses (acme.listen, monitoring.listen, metrics.listen,
// mirror.sign_subtree_listen) are also dropped; only the public external_url
// values are exposed. sign_subtree_path is an HTTP route, not a bind address
// or filesystem path, so it is kept. The metrics section has nothing left to
// expose once its listen address is dropped, so it is omitted entirely.
type RedactedConfig struct {
	Log              LogConfig        `json:"log"`
	CACosigner       RedactedCosigner `json:"ca_cosigner"`
	CACosignerQuorum RedactedQuorum   `json:"ca_cosigner_quorum"`
	ACME             RedactedACME     `json:"acme"`
	Monitoring       RedactedListener `json:"monitoring"`
	Landmarks        LandmarkConfig   `json:"landmarks"`
	Mirror           RedactedMirror   `json:"mirror"`
	LogLevel         string           `json:"log_level"`
}

// RedactedCosigner drops CosignerConfig.SeedPath.
type RedactedCosigner struct {
	ID        string `json:"id"`
	Algorithm string `json:"algorithm"`
}

// RedactedACME drops ACMEConfig.TLSCert, TLSKey, and the internal Listen
// address.
type RedactedACME struct {
	ExternalURL   string `json:"external_url"`
	ChallengeMode string `json:"challenge_mode"`
}

// RedactedListener drops ListenerConfig.Listen (the internal bind address).
type RedactedListener struct {
	ExternalURL string `json:"external_url"`
}

// RedactedQuorum mirrors CACosignerQuorum but with redacted endpoints.
type RedactedQuorum struct {
	Mirrors                []RedactedMirrorEndpoint `json:"mirrors"`
	MinSignatures          int                      `json:"min_signatures"`
	RequestTimeoutMS       int                      `json:"request_timeout_ms"`
	BestEffortAfterMinimum bool                     `json:"best_effort_after_minimum"`
	MirrorRetryDeadlineMS  int                      `json:"mirror_retry_deadline_ms"`
}

// RedactedMirrorEndpoint drops MirrorEndpointConfig.PublicKeyPath.
type RedactedMirrorEndpoint struct {
	ID        string `json:"id"`
	URL       string `json:"url"`
	Algorithm string `json:"algorithm"`
}

// RedactedMirror drops MirrorConfig.SeedPath and the internal
// SignSubtreeListen bind address.
type RedactedMirror struct {
	Enabled                     bool             `json:"enabled"`
	CosignerID                  string           `json:"cosigner_id"`
	Algorithm                   string           `json:"algorithm"`
	Upstream                    RedactedUpstream `json:"upstream"`
	SignSubtreePath             string           `json:"sign_subtree_path"`
	RequireCASignatureOnSubtree bool             `json:"require_ca_signature_on_subtree"`
}

// RedactedUpstream drops UpstreamConfig.CACosignerKeyPath.
type RedactedUpstream struct {
	TileURL        string `json:"tile_url"`
	LogID          string `json:"log_id"`
	CACosignerID   string `json:"ca_cosigner_id"`
	PollIntervalMS int    `json:"poll_interval_ms"`
}

// Redacted returns the public-safe view of c. See RedactedConfig.
func (c Config) Redacted() RedactedConfig {
	rc := RedactedConfig{
		Log:        c.Log,
		CACosigner: RedactedCosigner{ID: c.CACosigner.ID, Algorithm: c.CACosigner.Algorithm},
		CACosignerQuorum: RedactedQuorum{
			MinSignatures:          c.CACosignerQuorum.MinSignatures,
			RequestTimeoutMS:       c.CACosignerQuorum.RequestTimeoutMS,
			BestEffortAfterMinimum: c.CACosignerQuorum.BestEffortAfterMinimum,
			MirrorRetryDeadlineMS:  c.CACosignerQuorum.MirrorRetryDeadlineMS,
		},
		ACME: RedactedACME{
			ExternalURL:   c.ACME.ExternalURL,
			ChallengeMode: c.ACME.ChallengeMode,
		},
		Monitoring: RedactedListener{ExternalURL: c.Monitoring.ExternalURL},
		Landmarks:  c.Landmarks,
		Mirror: RedactedMirror{
			Enabled:                     c.Mirror.Enabled,
			CosignerID:                  c.Mirror.CosignerID,
			Algorithm:                   c.Mirror.Algorithm,
			SignSubtreePath:             c.Mirror.SignSubtreePath,
			RequireCASignatureOnSubtree: c.Mirror.RequireCASignatureOnSubtree,
			Upstream: RedactedUpstream{
				TileURL:        c.Mirror.Upstream.TileURL,
				LogID:          c.Mirror.Upstream.LogID,
				CACosignerID:   c.Mirror.Upstream.CACosignerID,
				PollIntervalMS: c.Mirror.Upstream.PollIntervalMS,
			},
		},
		LogLevel: c.LogLevel,
	}
	for _, m := range c.CACosignerQuorum.Mirrors {
		rc.CACosignerQuorum.Mirrors = append(rc.CACosignerQuorum.Mirrors, RedactedMirrorEndpoint{
			ID:        m.ID,
			URL:       m.URL,
			Algorithm: m.Algorithm,
		})
	}
	return rc
}
