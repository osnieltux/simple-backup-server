#!/bin/bash

apt update && apt -y install python3-virtualenv

INSTALL_PATH='/var/sbs/'

mkdir -p "$INSTALL_PATH"/{backups,server}
cp -r server/* "$INSTALL_PATH"/server/


virtualenv "$INSTALL_PATH/venv/"
source "$INSTALL_PATH/venv/bin/activate"

pip install -r requirements.txt

useradd -m -s /bin/bash -G mssql sbs
chown sbs:mssql -R /var/sbs
chmod 770 -R /var/sbs


cat <<EOF > /etc/systemd/system/sbs.service
[Unit]
Description=SBS
After=network.target

[Service]
Type=simple
User=sbs
Group=mssql
WorkingDirectory=$INSTALL_PATH
ExecStart=$INSTALL_PATH/venv/bin/python $INSTALL_PATH/server/sbs.py
Environment="PATH=$INSTALL_PATH/venv/bin"

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload 
systemctl enable --now sbs
