# simple-backup-server for microsoft sql server on linux (ubuntu)
web server for backup and restore SQL


### License
**[GPL v3](https://www.gnu.org/licenses/gpl-3.0.html)**

### install
```bash
# download
wget https://github.com/osnieltux/simple-backup-server/archive/refs/heads/main.zip

unzip simple-backup-server.zip 
cd simple-backup-server-main
./deploy.sh

# set your config
su sbs
INSTALL_PATH='/var/sbs/'
nano $INSTALL_PATH/config.conf

# create an user
cd $INSTALL_PATH
$INSTALL_PATH/venv/bin/python $INSTALL_PATH/server/sbs.py -c <username>
exit

# restart service
systemctl restart sbs

# check
systemctl status sbs

# user certificate (optional, automatically detected)
INSTALL_PATH='/var/sbs'
cd $INSTALL_PATH
openssl req -x509 -newkey rsa:2048 -nodes -keyout $INSTALL_PATH/key.pem -out $INSTALL_PATH/cert.pem -days 365
chown sbs $INSTALL_PATH/key.pem
systemctl restart sbs

```

### default web access (hardcoded port)
- http://0.0.0.0:5000
- https://0.0.0.0:5000
