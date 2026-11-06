# The sandbox a confirmation run happens in.
#
# This image is never part of the scanner: sc4n links no third-party code and
# shells out to nothing, and TestScanPathDoesNotExec fails the build if that
# changes. The image exists because "did the artifact execute, and what did it
# touch?" can only be answered by loading it, and loading it must happen
# somewhere disposable.
#
# Versions are pinned, because an image that changes shape between runs turns
# "demonstrated" into a coin flip: a loader upgrade that changes an import path
# changes the verdict for the same bytes.
#
# What is deliberately absent: tensorflow and keras. A Keras Lambda layer's grade
# is already decided statically (SC4N-KERAS-LAMBDA says the class name is the
# load path that runs config.code), so shipping ~600 MB to demonstrate a claim we
# already make is cost without information.
FROM python:3.12-slim

# strace is the effect source: it is the only one a payload cannot blind from
# native code, which is why the container is started with SYS_PTRACE.
RUN apt-get update \
 && apt-get install -y --no-install-recommends strace \
 && rm -rf /var/lib/apt/lists/*

# torch from the CPU index: the CUDA wheels are ~3x larger and this image never
# sees a GPU.
RUN pip install --no-cache-dir --index-url https://download.pytorch.org/whl/cpu \
      torch==2.15.0

RUN pip install --no-cache-dir \
      transformers==5.22.1 \
      joblib==1.6.0 \
      jinja2==3.1.6

COPY load.py /opt/sc4nconfirm/load.py
COPY entrypoint.sh /opt/sc4nconfirm/entrypoint.sh
RUN chmod 0755 /opt/sc4nconfirm/entrypoint.sh

# The worker home holds the canaries the entrypoint plants. It is a tmpfs in the
# run, so whatever the payload writes there dies with the container.
ENV HOME=/home/worker
ENV PYTHONDONTWRITEBYTECODE=1
ENV HF_HUB_OFFLINE=1
ENV TRANSFORMERS_OFFLINE=1

WORKDIR /w
ENTRYPOINT ["/opt/sc4nconfirm/entrypoint.sh"]
