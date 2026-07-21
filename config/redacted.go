package config

// RedactedConfig is a public-safe view of Config, suitable for serving on the
// log's HTML index page. It is built by an *allowlist*: only fields that are
// neither secrets nor filesystem paths are copied across. A newly added field
// is therefore excluded by default — it has to be added here explicitly to be
// exposed — so a future secret can't leak by accident. Everything path-like is
// intentionally absent: data_dir, ca_cosigner.seed_path, acme.tls_cert /
// tls_key, every *.public_key_path.
//
// Internal bind addresses (acme.listen, monitoring.listen, metrics.listen) are
// also dropped; only the public external_url values are exposed. The metrics
// section has nothing left to expose once its listen address is dropped, so it
// is omitted entirely.
type RedactedConfig struct {
	Log              LogConfig        `json:"log"`
	CACosigner       RedactedCosigner `json:"ca_cosigner"`
	CACosignerQuorum RedactedQuorum   `json:"ca_cosigner_quorum"`
	MirrorPush       RedactedPush     `json:"mirror_push"`
	ACME             RedactedACME     `json:"acme"`
	Monitoring       RedactedListener `json:"monitoring"`
	Landmarks        LandmarkConfig   `json:"landmarks"`
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

// RedactedPush mirrors MirrorPushConfig with per-target public key
// paths dropped.
type RedactedPush struct {
	Targets          []RedactedPushTarget `json:"targets"`
	RequestTimeoutMS int                  `json:"request_timeout_ms"`
	PushTimeoutMS    int                  `json:"push_timeout_ms"`
	DisableGzip      bool                 `json:"disable_gzip"`
}

// RedactedPushTarget drops MirrorPushTarget.PublicKeyPath. The two URL
// prefixes are kept: they are public endpoints, and publishing which
// mirrors a log replicates to is the point of the exercise.
type RedactedPushTarget struct {
	ID               string `json:"id"`
	SubmissionPrefix string `json:"submission_prefix"`
	MonitoringPrefix string `json:"monitoring_prefix"`
	Algorithm        string `json:"algorithm"`
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
		MirrorPush: RedactedPush{
			RequestTimeoutMS: c.MirrorPush.RequestTimeoutMS,
			PushTimeoutMS:    c.MirrorPush.PushTimeoutMS,
			DisableGzip:      c.MirrorPush.DisableGzip,
		},
		Monitoring: RedactedListener{ExternalURL: c.Monitoring.ExternalURL},
		Landmarks:  c.Landmarks,
		LogLevel:   c.LogLevel,
	}
	for _, m := range c.CACosignerQuorum.Mirrors {
		rc.CACosignerQuorum.Mirrors = append(rc.CACosignerQuorum.Mirrors, RedactedMirrorEndpoint{
			ID:        m.ID,
			URL:       m.URL,
			Algorithm: m.Algorithm,
		})
	}
	for _, t := range c.MirrorPush.Targets {
		rc.MirrorPush.Targets = append(rc.MirrorPush.Targets, RedactedPushTarget{
			ID:               t.ID,
			SubmissionPrefix: t.SubmissionPrefix,
			MonitoringPrefix: t.MonitoringPrefix,
			Algorithm:        t.Algorithm,
		})
	}
	return rc
}
