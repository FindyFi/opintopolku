# Opintopolku-todisteet
Vahvistettavia todisteita oman opintopolun tiedoista

# Käyttöönotto

```sh
git clone https://github.com/FindyFi/opintopolku.git
cd opintopolku
npm i @veramo/cli -g
veramo config create
export HOST='opintopolku.findy.fi'
sed -i -e "s/\(baseUrl: \).*/\1'https:\/\/$HOST'/" ./agent.yml
export PORT=4343
sed -i -e "s/\(port: \).*/\1$PORT/" ./agent.yml
KEY=`veramo config gen-key -q`
sed -i -e "s/\(dbEncryptionKey: \).*/\1$KEY/" ./agent.yml
npm install
npm run start
```
