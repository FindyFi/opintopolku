# Opintopolku-todisteet

Vahvistettavia todisteita oman opintopolun tiedoista.

Tutustu demoon osoitteessa [opintopolku.findy.fi](https://opintopolku.findy.fi/).

## Käyttöönotto

```sh
cd ~/github
git clone https://github.com/FindyFi/opintopolku.git
cd opintopolku
mkdir db
sudo NODE_OPTIONS=--max-old-space-size=3072 sudo npm i @veramo/cli -g
veramo config create
export CREDENTIALS_DB_FILE="./db/credentials.db"
HOST='opintopolku.findy.fi'
PORT=4343
DBFILE='.db/veramo.db'
KEY=`veramo config gen-key -q`
sed -i'.default' \                                                                                                                                                                                                                                                                                                                                       [17:03:57]
 -e "s/\(baseUrl: \).*/\1'https:\/\/$HOST'/" \
 -e "s/\(port: \).*/\1$PORT/" \
 -e "s/\(dbEncryptionKey: \).*/\1$KEY/" \
 -e "s|\(databaseFile: \).*|\1$DBFILE|" ./agent.yml
npm install
npm run start
```
