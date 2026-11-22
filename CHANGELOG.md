# Changelog

All notable changes to this project are documented in this file. The format is
based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

## [1.0.1] - 2026-11-22

### Added

- **First public release.** A static scanner for ML model artifacts and the code
  around them: pickle, joblib, torch, safetensors, numpy, GGUF, ONNX, TensorFlow,
  Keras, TFLite, CoreML, ExecuTorch and TensorRT formats, plus Python source,
  notebooks, chat templates and model cards. Content-based dispatch, no
  execution, report-only.
- Text, JSON, SARIF and CycloneDX reports with stable rule IDs, a generated rule
  catalogue and documented exit codes.
