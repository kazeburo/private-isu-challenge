# private-isu-try

## 環境

さくらのクラウド 東京第二ゾーン 2core/1GBサーバ

## 初期スコア

```
{"pass":true,"score":1857,"success":1994,"fail":11,"messages":["リクエストがタイムアウトしました (GET /)","リクエストがタイムアウトしました (GET /logout)","リクエストがタイムアウトしました (GET /posts)","リクエストがタイムアウトしました (POST /login)"]}
{"pass":true,"score":1914,"success":1992,"fail":8,"messages":["リクエストがタイムアウトしました (GET /)","リクエストがタイムアウトしました (GET /logout)","リク エストがタイムアウトしました (GET /posts)","リクエストがタイムアウトしました (POST /login)"]}
{"pass":true,"score":2053,"success":2113,"fail":7,"messages":["リクエストがタイムアウトしました (GET /)","リクエストがタイムアウトしました (GET /logout)","リク エストがタイムアウトしました (GET /posts)","リクエストがタイムアウトしました (POST /login)"]}
```

## post_id_idx 追加

```
mysql> ALTER TABLE `comments` ADD INDEX `post_id_idx` (`post_id`);
Query OK, 0 rows affected (0.63 sec)
Records: 0  Duplicates: 0  Warnings: 0
```

score

```
{"pass":true,"score":11531,"success":9791,"fail":0,"messages":[]}
{"pass":true,"score":11715,"success":9938,"fail":0,"messages":[]}
{"pass":true,"score":11207,"success":9529,"fail":0,"messages":[]}
```
