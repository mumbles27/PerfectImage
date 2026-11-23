// Package siem will forward logs and audit events to external SIEMs
// (syslog/CEF, HTTP, Splunk HEC, ...).
//
// Owner: ops agent. Not implemented in the foundation.
//
// Expected seams: implement logging.Sink (non-blocking!) and/or
// audit.Recorder per config.SIEMOutput, installed from an app.Plugin via
// Deps.Logging.AddSink and Deps.Audit.Set.
package siem
