#!/bin/bash

# install pv
sudo apt install pv

# mkdir of data saving
mkdir /home/ubuntu

# read every single line in urls.txt
while IFS= read -r url; do
    # switch to /home/ubuntu directory
    cd /home/ubuntu

    # using wget to download files
    wget "$url" -O temp.tar

    # check if download files is a tar and unzip
    if file temp.tar | grep -q 'tar archive'; then
        pv temp.tar | tar -xf - -C /home/ubuntu
    fi

    # delete tar file
    rm temp.tar

    # check back to original directory
    cd -

done < urls.txt
