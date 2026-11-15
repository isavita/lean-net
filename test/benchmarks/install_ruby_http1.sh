#!/usr/bin/env bash
set -euo pipefail

destination="${1:?usage: install_ruby_http1.sh GEM_DIRECTORY}"
gem install --install-dir "$destination" --no-document nio4r -v 2.7.5
gem install --install-dir "$destination" --no-document rack -v 3.2.8
gem install --install-dir "$destination" --no-document --ignore-dependencies puma -v 8.0.3
