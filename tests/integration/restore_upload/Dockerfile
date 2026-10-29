FROM ubuntu:24.04@sha256:534baea6a22c03a63003dbc8dbe78fe34bc0d7e595d9a9dc9834884ff530eb55

RUN apt-get update -o APT::Update::Error-Mode=any \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
       python3 python3-pytest rsync procps \
    && rm -rf /var/lib/apt/lists/*
COPY src/ops_deploy /source/ops_deploy
COPY tests/test_restore_upload.py /owned/test_restore_upload.py
ENV PYTHONPATH=/source
WORKDIR /owned
CMD ["python3", "-m", "pytest", "-v", "test_restore_upload.py"]
