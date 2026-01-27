pub mod cra;

use thiserror::Error;

#[derive(Debug, Error)]
pub enum ClassifierError {
    #[error("failed to read rules file: {0}")]
    Io(#[from] std::io::Error),
    #[error("failed to parse rules TOML: {0}")]
    Toml(#[from] toml::de::Error),
}
