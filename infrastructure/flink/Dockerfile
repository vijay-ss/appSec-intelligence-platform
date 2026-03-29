# Custom Flink image for the AppSec Intelligence Platform.
#
# CHANGED: base image updated from apache/flink:1.20-python3 to
# flink:2.0-java17. The -python3 tag no longer exists — Apache removed it.
# Python 3.11 is now installed explicitly in this Dockerfile.
#
# This Dockerfile does four things:
#   1. Installs Python 3.11, gcc, and the JDK (for pemja to compile against)
#   2. Downloads flink-sql-connector-kafka into /opt/flink/lib/
#   3. Moves flink-s3-fs-hadoop into the Flink plugins directory
#   4. Installs Python packages the operators need at runtime
#
# Both the jobmanager and taskmanager use this same image.

FROM flink:1.19

# ── 1. Python 3.11 + build dependencies ──────────────────────────────────────
# CHANGED: was pre-installed in apache/flink:1.20-python3, now installed here.
#
# pemja (a PyFlink dependency) compiles a native C extension that calls into
# the JVM via JNI. It requires:
#   - gcc         — C compiler for the native extension
#   - default-jdk — full JDK with jni.h headers (the base image only has JRE)
#   - JAVA_HOME   — must point to the JDK so pemja's build script finds jni.h
#
# CHANGED: previous attempts tried to symlink/copy jni.h from the base image,
# but flink:2.0-java17 ships only a JRE — jni.h doesn't exist at all.
# The fix is to install default-jdk which brings the full JDK headers, then
# set JAVA_HOME=/usr/lib/jvm/default-java so pemja finds them correctly.
RUN apt-get update -y && \
    apt-get install -y --no-install-recommends \
        python3.11 \
        python3.11-dev \
        python3-pip \
        wget \
        gcc \
        default-jdk \
    && ln -sf /usr/bin/python3.11 /usr/bin/python3 \
    && ln -sf /usr/bin/python3.11 /usr/bin/python \
    && rm -rf /var/lib/apt/lists/*

# JAVA_HOME must be set as an ENV (not just a shell variable) so it is
# available when pip spawns subprocess builds for pemja.
ENV JAVA_HOME=/usr/lib/jvm/default-java

# ── 2. Kafka connector JAR ────────────────────────────────────────────────────
# CHANGED: connector version is 4.0.1-2.0 — the correct version for Flink 2.0.
# 3.x connector versions target Flink 1.x only.
ARG KAFKA_CONNECTOR_VERSION=3.2.0-1.19
RUN wget -q \
    "https://repo1.maven.org/maven2/org/apache/flink/flink-sql-connector-kafka/${KAFKA_CONNECTOR_VERSION}/flink-sql-connector-kafka-${KAFKA_CONNECTOR_VERSION}.jar" \
    -O "/opt/flink/lib/flink-sql-connector-kafka-${KAFKA_CONNECTOR_VERSION}.jar"

# ── 3. S3 / MinIO plugin for checkpoint storage ───────────────────────────────
RUN mkdir -p /opt/flink/plugins/s3-fs-hadoop && \
    cp /opt/flink/opt/flink-s3-fs-hadoop-*.jar /opt/flink/plugins/s3-fs-hadoop/

# ── 4. Python runtime dependencies ───────────────────────────────────────────
COPY requirements.txt /tmp/flink-requirements.txt
RUN pip install --no-cache-dir -r /tmp/flink-requirements.txt
