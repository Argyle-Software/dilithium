#[derive(Debug, PartialEq)]
pub enum DilithiumError {
  Input,
  Verify,
  RandomBytesGeneration,
}

#[cfg(feature = "std")]
impl std::error::Error for DilithiumError {}
