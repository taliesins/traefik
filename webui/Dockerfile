FROM node:6.9.1

ARG npm_config_registry
ARG yarn_config_registry
ENV WEBUI_DIR /src/webui

WORKDIR $WEBUI_DIR

COPY . $WEBUI_DIR/
COPY package.json $WEBUI_DIR/
COPY yarn.lock $WEBUI_DIR/

RUN apt-get -yq update \
&& apt-get -yq --no-install-suggests --no-install-recommends --force-yes install apt-transport-https \
&& curl -sS https://dl.yarnpkg.com/debian/pubkey.gpg | apt-key add - \
&& echo "deb https://dl.yarnpkg.com/debian/ stable main" |  tee /etc/apt/sources.list.d/yarn.list \
&& apt-get -yq update \ 
&& apt-get -yq --no-install-suggests --no-install-recommends --force-yes install yarn \
&& rm -fr /var/lib/apt/lists/ \
&& if [ -n "${npm_config_registry+1}" ]; then npm config set registry $npm_config_registry --global ; fi \
&& if [ -n "${yarn_config_registry+1}" ]; then yarn config set registry $yarn_config_registry --global ; find . -type f -name 'yarn.lock' -exec sed -i "s|https:\/\/registry\.yarnpkg\.com\/|$yarn_config_registry|g" {} + ; fi \
&& npm set progress=false \
&& yarn install

EXPOSE 8080
