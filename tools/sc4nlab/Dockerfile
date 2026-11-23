# The oracle for the graphs profile: onnx.checker validates the model document
# and onnxruntime builds the session a loader would.
#
# Pinned versions, because an oracle that changes shape between runs turns a
# matrix row into a coin flip. This image is never part of the scanner: sc4n
# links no third-party code and shells out to nothing, and the graphs profile is
# the only thing that uses Python at all.
FROM python:3.12-slim

RUN pip install --no-cache-dir onnx==1.20.0 onnxruntime==1.22.0
COPY py/check.py py/mutate.py /opt/sc4nlab/

WORKDIR /w
USER 65532:65532
