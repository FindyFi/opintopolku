# Opintopolku-todisteet
Vahvistettavia todisteita oman opintopolun tiedoista

# Käyttöönotto

```sh
git clone https://github.com/FindyFi/opintopolku.git
cd opintopolku
npm i @veramo/cli -g
veramo config create
export HOST='opintopolku.findy.fi'
sed -i -re "s/(baseUrl: ).+/\1'https:\/\/$HOST'/" ./agent.yml
export PORT=4343
sed -i -re "s/(port: ).+/\1$PORT/" ./agent.yml
export KEY=`veramo config gen-key -q`
sed -i -re "s/(dbEncryptionKey: )\w+/\1'$KEY'/" ./agent.yml
npm install
npm run start
```
