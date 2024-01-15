# Opintopolku-todisteet
Vahvistettavia todisteita oman opintopolun tiedoista

# Käyttöönotto

```sh
git clone https://github.com/FindyFi/opintopolku.git
cd opintopolku
npm i @veramo/cli -g
veramo config create
HOST='opintopolku.findy.fi'
PORT=4343
DBFILE='veramo.db'
KEY=`veramo config gen-key -q`
sed -i'.default' \
 -e "s/\(baseUrl: \).*/\1'https:\/\/$HOST'/" \
 -e "s/\(port: \).*/\1$PORT/" \
 -e "s/\(dbEncryptionKey: \).*/\1$KEY/" \
 -e "s/\(databaseFile: \).*/\1$DBFILE/" ./agent.yml
npm install
npm run start
```
