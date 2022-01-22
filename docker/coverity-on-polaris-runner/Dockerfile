FROM openjdk:slim
COPY --from=python:3.6-slim / /

# Set up GitHub Runner
ARG TARGETPLATFORM=amd64
ARG RUNNER_VERSION="2.284.0"

# Update base packages, install necessary tools and set up non-sudo user
RUN apt-get update \
  && apt-get install -y curl unzip git jq

RUN useradd -m runner \
    && usermod -aG sudo runner \
    && echo "%sudo   ALL=(ALL:ALL) NOPASSWD:ALL" > /etc/sudoers

# Ensure all Python dependencies are installed
RUN python3 -m ensurepip
RUN pip3 install --upgrade pip && pip3 install requests==2.26.0 urllib3==1.26.7 jsonapi-requests==0.6.2 tenacity==6.2.0

# Build args
WORKDIR /runner

# Runner download supports amd64 as x64
RUN export ARCH=$(echo ${TARGETPLATFORM} | cut -d / -f2) \
    && if [ "$ARCH" = "amd64" ]; then export ARCH=x64 ; fi \
    && curl -Ls -o runner.tar.gz https://github.com/actions/runner/releases/download/v${RUNNER_VERSION}/actions-runner-linux-${ARCH}-${RUNNER_VERSION}.tar.gz \
    && tar xzf ./runner.tar.gz \
    && rm runner.tar.gz \
    && ./bin/installdependencies.sh \
    && rm -rf /var/lib/apt/lists/*

# Dumb Init
RUN export ARCH=$(echo ${TARGETPLATFORM} | cut -d / -f2) \
    && curl -Ls  -o /usr/local/bin/dumb-init https://github.com/Yelp/dumb-init/releases/download/v1.2.2/dumb-init_1.2.2_${ARCH} \
    && chmod +x /usr/local/bin/dumb-init

# copy over the start.sh script
COPY start.sh /usr/local/bin/start.sh

# make the script executable
RUN chmod +x /usr/local/bin/start.sh

# since the config and run script for actions are not allowed to be run by root,
# set the user to "docker" so all subsequent commands are run as the docker user
USER runner

# set the entrypoint to the start.sh script
ENTRYPOINT ["/usr/local/bin/dumb-init", "--"]
CMD ["start.sh"]

