 #!/usr/bin/env bash

 # Execute this file to install the rito cli tools into your path on OS X

 CURRENT_LOC="$( cd "$(dirname "$0")" ; pwd -P )"
 LOCATION=${CURRENT_LOC%Rito-Qt.app*}

 # Ensure that the directory to symlink to exists
 sudo mkdir -p /usr/local/bin

 # Create symlinks to the cli tools
 sudo ln -s ${LOCATION}/Rito-Qt.app/Contents/MacOS/ritod /usr/local/bin/ritod
 sudo ln -s ${LOCATION}/Rito-Qt.app/Contents/MacOS/rito-cli /usr/local/bin/rito-cli
