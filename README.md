# TestCall

- Clone the project and get the dependencies:
```
git clone https://github.com/DanielaIvanova/test_call
cd test_call
mix deps.get
```
- Start the project
```
iex -S mix
```
- Deploy already predefined contract:
```
TestCall.deploy
```
- Search the contract in the blockchain by passing **contract ID**:
```
TestCall.search_contract("ct_gUtbZbfKyP74PggKfsXafs37yUB1sTnF7iXBNty1zAvuKxKJj")
```
- Get transaction info by hash
```
TestCall.get_tx_info_by_hash("th_RzjdqZ38T6pF8EdkbaZpFUqabpN2x3z2Cuj64kYm18inZm537")
```

