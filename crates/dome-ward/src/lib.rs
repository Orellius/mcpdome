//! `dome-ward` -- Injection detection, schema integrity, and heuristic analysis.
//!
//! Three detection strategies layered together:
//! 1. **Pattern matching** -- known injection signatures in tool descriptions and arguments
//! 2. **Schema pinning** -- cryptographic hashing of tool schemas to detect rug pulls
//! 3. **Heuristic analysis** -- entropy scoring, encoding detection, length anomalies

pub mod heuristics;
pub mod patterns;
pub mod schema_pin;

pub use heuristics::{entropy_score, is_base64_encoded, is_suspiciously_long};
pub use patterns::{InjectionMatch, InjectionScanner, Severity};
pub use schema_pin::{SchemaDrift, SchemaDriftType, SchemaPin, SchemaPinStore};
